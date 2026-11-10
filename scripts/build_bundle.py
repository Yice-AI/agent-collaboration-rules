"""Build and verify a deterministic public rules bundle; never execute its files.

The SHA-256 covers the canonical UTF-8 JSON bytes, without a trailing newline.
When transporting this text through a native document, its structural final LF
is not part of the bundle; callers must inspect the document structure first.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile

if __package__:
    from scripts.privacy_check import PATTERNS, PUBLIC_PATTERNS, unique_json_object, walk_json, walk_public_json
else:
    from privacy_check import PATTERNS, PUBLIC_PATTERNS, unique_json_object, walk_json, walk_public_json

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_DIRECTORIES = {'docs', 'scripts', 'templates', 'schema', 'schemas'}
ALLOWED_SUFFIXES = {'.md', '.py', '.json', '.txt'}
FORBIDDEN_PARTS = {'private', '_private', 'secrets', 'archive', 'data', 'reports', 'tests', '__pycache__'}
MAX_BYTES = 2_000_000
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')


class BundleError(ValueError):
    pass


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(bundle: dict) -> bytes:
    return json.dumps(bundle, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def validate_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise BundleError('Invalid bundle path')
    path = PurePosixPath(value)
    if (path.is_absolute() or value != path.as_posix() or any(
            part in {'.', '..'} or part.startswith('.') or part.lower() in FORBIDDEN_PARTS
            for part in path.parts) or path.name.lower() == 'release.json'):
        raise BundleError('Private, noncanonical or reserved bundle path')
    if len(path.parts) == 1:
        if path.suffix != '.md':
            raise BundleError('Only explicitly listed root Markdown entries are allowed')
    elif path.parts[0] not in ALLOWED_DIRECTORIES or path.suffix not in ALLOWED_SUFFIXES:
        raise BundleError('Path is outside the public bundle allowlist categories')
    return path


def reject_constant(_: str):
    raise BundleError('Non-finite JSON values are forbidden')


def check_content(path: str, content: str) -> None:
    if not isinstance(content, str) or '\x00' in content:
        raise BundleError('Bundle entries must be text')
    try:
        content.encode('utf-8')
    except UnicodeError as exc:
        raise BundleError('Invalid UTF-8 text') from exc
    if any(pattern.search(content) for pattern in (*PATTERNS.values(), *PUBLIC_PATTERNS.values())):
        raise BundleError('Public-content privacy check failed')
    if path.endswith('.json'):
        try:
            data = json.loads(content, object_pairs_hook=unique_json_object,
                              parse_constant=reject_constant)
        except (ValueError, TypeError) as exc:
            raise BundleError('Invalid JSON bundle entry') from exc
        if any(walk_json(data)) or any(walk_public_json(data)):
            raise BundleError('Public JSON contains a forbidden identity or credential field')


def parse_allowlist(raw: str) -> list[str]:
    paths = [line.strip() for line in raw.splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    if not paths or len(paths) != len(set(paths)):
        raise BundleError('Allowlist is empty or contains duplicate paths')
    for path in paths:
        validate_path(path)
    return sorted(paths)


def build(root: Path, allowlist: Path, version: str) -> bytes:
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise BundleError('Invalid release version')
    root = root.resolve(strict=True)
    if not root.is_dir() or allowlist.is_symlink():
        raise BundleError('Invalid source root or symlink allowlist')
    paths = parse_allowlist(allowlist.read_text(encoding='utf-8'))
    entries = []
    for name in paths:
        path = root / name
        cursor = path
        while cursor != root:
            if cursor.is_symlink():
                raise BundleError('Source symlinks are forbidden')
            cursor = cursor.parent
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise BundleError('Missing or out-of-root source file')
        raw = path.read_bytes()
        if len(raw) > MAX_BYTES:
            raise BundleError('Source file exceeds bundle limit')
        try:
            content = raw.decode('utf-8')
        except UnicodeError as exc:
            raise BundleError('Non-UTF-8 source file') from exc
        check_content(name, content)
        entries.append({'path': name, 'content': content, 'sha256': digest(raw)})
    payload = canonical({'schema_version': 1, 'version': version, 'files': entries})
    if len(payload) > MAX_BYTES:
        raise BundleError('Bundle exceeds size limit')
    return payload


def verify(raw: bytes, expected_sha256: str) -> dict:
    if (not isinstance(raw, bytes) or len(raw) > MAX_BYTES
            or not isinstance(expected_sha256, str) or not SHA256.fullmatch(expected_sha256)
            or digest(raw) != expected_sha256):
        raise BundleError('Bundle byte hash or size mismatch')
    try:
        bundle = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_json_object,
                            parse_constant=reject_constant)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise BundleError('Invalid bundle JSON') from exc
    if (not isinstance(bundle, dict) or set(bundle) != {'schema_version', 'version', 'files'}
            or type(bundle['schema_version']) is not int or bundle['schema_version'] != 1
            or not isinstance(bundle['version'], str) or not VERSION.fullmatch(bundle['version'])
            or not isinstance(bundle['files'], list) or not bundle['files']):
        raise BundleError('Unsupported bundle schema')
    names = []
    for entry in bundle['files']:
        if not isinstance(entry, dict) or set(entry) != {'path', 'content', 'sha256'}:
            raise BundleError('Invalid bundle file entry')
        validate_path(entry['path'])
        check_content(entry['path'], entry['content'])
        if (not isinstance(entry['sha256'], str) or not SHA256.fullmatch(entry['sha256'])
                or digest(entry['content'].encode('utf-8')) != entry['sha256']):
            raise BundleError('Bundled file hash mismatch')
        names.append(entry['path'])
    if names != sorted(set(names)) or canonical(bundle) != raw:
        raise BundleError('Bundle ordering, duplicate paths or serialization is not canonical')
    return bundle


def write_bundle(raw: bytes, output: Path, *, root: Path, protected: tuple[Path, ...] = ()) -> None:
    root = root.resolve(strict=True)
    output = output.absolute()
    private = root / '_private'
    temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
    if (output.suffix != '.json' or '..' in output.parts
            or any(p.is_symlink() for p in (output, *output.parents))
            or any(output.resolve() == p.resolve() for p in protected)):
        raise BundleError('Unsafe bundle output path')
    if output.is_relative_to(private):
        if (root / '.git').exists():
            result = subprocess.run(['git', '-C', str(root), 'check-ignore', '--quiet', '--no-index',
                                     str(output.relative_to(root))], check=False,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode != 0:
                raise BundleError('Private output must be ignored by Git')
        directories = [private, *reversed([p for p in (output.parent, *output.parent.parents)
                                          if p != private and private in p.parents])]
    elif output.is_relative_to(root) or not output.is_relative_to(temp_root):
        raise BundleError('Output must be ignored private storage or an external temporary path')
    else:
        missing = []
        parent = output.parent
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        directories = [parent, *reversed(missing)]
    for directory in directories:
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.stat()
        if (directory.is_symlink() or not directory.is_dir()
                or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid()):
            raise BundleError('Output directories must be owned by this user with mode 700')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, output)
        except FileExistsError:
            info = output.stat()
            if (not output.is_file() or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid()):
                raise BundleError('Existing output must be a private regular file') from None
            if output.read_bytes() != raw:
                raise BundleError('Refusing to overwrite a different bundle') from None
        if output.read_bytes() != raw:
            raise BundleError('Written bundle differs from expected bytes')
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='构建/核验通用规则包；不读取私有资料、不执行包内容')
    commands = parser.add_subparsers(dest='command', required=True)
    make = commands.add_parser('build')
    make.add_argument('--root', type=Path, default=ROOT)
    make.add_argument('--allowlist', type=Path, required=True)
    make.add_argument('--version', required=True)
    make.add_argument('--out', type=Path, required=True)
    check = commands.add_parser('verify')
    check.add_argument('--input', type=Path, required=True)
    check.add_argument('--expected-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'build':
            raw = build(args.root, args.allowlist, args.version)
            verified = verify(raw, digest(raw))
            write_bundle(raw, args.out, root=args.root, protected=(args.allowlist,))
        else:
            raw = args.input.read_bytes()
            verified = verify(raw, args.expected_sha256)
        print(json.dumps({'status': 'local_bundle_verified', 'version': verified['version'],
                          'file_count': len(verified['files']), 'sha256': digest(raw),
                          'bytes': len(raw), 'published': False}))
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print('规则包构建或校验失败；未发布。核对白名单、隐私、路径及哈希；不自动覆盖。')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
