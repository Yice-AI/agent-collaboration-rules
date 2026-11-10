"""Validate private runtime resource mappings locally without exposing their values."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

if __package__:
    from scripts.confirmed_ledger import LedgerError, decode_json
else:
    from confirmed_ledger import LedgerError, decode_json

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / 'schemas' / 'runtime-manifest.schema.json'
MAX_BYTES = 2_000_000
SUPPORTED_KEYWORDS = {'$schema', '$id', 'title', 'description', 'type', 'const', 'enum',
                      'required', 'properties', 'additionalProperties', 'pattern',
                      'minLength', 'maxLength'}


class ManifestError(ValueError):
    pass


def _validate(value, schema: dict) -> None:
    """Apply only the checked-in schema vocabulary; unknown rules fail closed."""
    if not isinstance(schema, dict) or set(schema) - SUPPORTED_KEYWORDS:
        raise ManifestError('Unsupported schema rule')
    kind = schema.get('type')
    types = {'object': dict, 'string': str, 'integer': int, 'boolean': bool}
    if kind is not None and (kind not in types or type(value) is not types[kind]):
        raise ManifestError('Invalid field type')
    if 'const' in schema and (type(value) is not type(schema['const']) or value != schema['const']):
        raise ManifestError('Unexpected fixed value')
    if 'enum' in schema and not any(type(value) is type(x) and value == x for x in schema['enum']):
        raise ManifestError('Unexpected enumerated value')
    if isinstance(value, dict):
        if any(key not in value for key in schema.get('required', [])):
            raise ManifestError('Missing required field')
        properties = schema.get('properties', {})
        if schema.get('additionalProperties') is False and set(value) - set(properties):
            raise ManifestError('Unknown field')
        for key, rule in properties.items():
            if key in value:
                _validate(value[key], rule)
    if isinstance(value, str):
        if len(value) < schema.get('minLength', 0) or len(value) > schema.get('maxLength', MAX_BYTES):
            raise ManifestError('Invalid text length')
        if 'pattern' in schema and not re.fullmatch(schema['pattern'], value):
            raise ManifestError('Invalid text format')


def validate_runtime(value: dict, *, schema_path: Path = SCHEMA_PATH) -> dict:
    """Accept an index containing agent_runtime, or the standalone runtime object."""
    if not isinstance(value, dict):
        raise ManifestError('Expected an object')
    manifest = value['agent_runtime'] if 'agent_runtime' in value else value
    schema = decode_json(schema_path.read_bytes())
    _validate(manifest, schema)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='本地校验私有运行manifest；不连接云盘、不回显私有资源值')
    commands = parser.add_subparsers(dest='command', required=True)
    validate = commands.add_parser('validate')
    validate.add_argument('--input', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        raw = args.input.read_bytes()
        if len(raw) > MAX_BYTES:
            raise ManifestError('Input exceeds size limit')
        manifest = validate_runtime(decode_json(raw))
        print(json.dumps({'status': 'local_manifest_validation_only',
                          'schema_version': manifest['schema_version'],
                          'version': manifest['release']['version'],
                          'resource_count': len(manifest['resources']),
                          'cloud_verified': False}, ensure_ascii=False))
        return 0
    except (ManifestError, LedgerError, OSError, UnicodeError, ValueError, KeyError, TypeError):
        print('运行manifest本地校验失败；请检查固定版本、必需资源、类型和预期父目录。未连接或修改云端。')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
