"""Replay immutable, user-confirmed changes without overwriting the historical base.

This is an offline validator, not a cloud daemon or proof of who authored a fact.
Cloud upload and full folder listing must be independently verified by the caller.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import stat
import tempfile
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

if __package__:
    from scripts.privacy_check import CREDENTIAL_KEYS, PATTERNS
else:
    from privacy_check import CREDENTIAL_KEYS, PATTERNS

ROOT = Path(__file__).resolve().parents[1]

TARGETS = {
    'accounts': ('id', {'当前状态', '当前用途', '主要入金', '主要出金', '下一步动作', '备注', 'balance'}),
    'account_cards': ('平台/账户', {'当前状态', '申请/开户日期', 'Apple Pay/卡状态', '待确认/下一步',
                                  '注册姓名', '注册邮箱', '注册手机号', '注册地址/地区'}),
    'routes': ('编号', {'建议状态', '费用/速度', '触发条件'}),
    'checks': ('id', {'value'}),
    'tasks': ('id', {'due'}),
    'opportunities': ('id', {'status'}),
}
EVENT_KEYS = {'schema_version', 'event_id', 'parent', 'baseline_sha256', 'observed_at',
              'recorded_at', 'source', 'changes'}
SECRET_PATTERNS = {k: v for k, v in PATTERNS.items()
                   if k in {'private_key', 'provider_token', 'sensitive_assignment'}}
SECRET_LABEL = re.compile(r'(?:^|[\s\"\'，;])(?:' + '|'.join(re.escape(k) for k in CREDENTIAL_KEYS)
                          + r')[\"\']?\s*[:=：]\s*\S+', re.IGNORECASE)


class LedgerError(ValueError):
    """Invalid or incomplete event input; no candidate state should be published."""


class ConflictError(LedgerError):
    """Two confirmed changes share a parent; both remain intact for reconciliation."""


def decode_json(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise LedgerError('Duplicate JSON key')
            result[key] = value
        return result

    def constant(_):
        raise LedgerError('Non-finite JSON number')

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def validate_event(event: dict, baseline_sha256: str, *, now: datetime | None = None) -> None:
    if not isinstance(event, dict) or set(event) != EVENT_KEYS:
        raise LedgerError('Unexpected event schema')
    if type(event['schema_version']) is not int or event['schema_version'] != 1:
        raise LedgerError('Unsupported event version')
    try:
        if str(uuid.UUID(event['event_id'])) != event['event_id']:
            raise ValueError()
        observed = date.fromisoformat(event['observed_at'])
        recorded = datetime.fromisoformat(event['recorded_at'])
    except (ValueError, TypeError, AttributeError):
        raise LedgerError('Invalid event id or date') from None
    if (observed.isoformat() != event['observed_at'] or recorded.tzinfo is None
            or observed > recorded.astimezone(timezone(timedelta(hours=8))).date()):
        raise LedgerError('Future observation or missing timezone')
    reference = datetime.now(timezone.utc) if now is None else now
    if reference.tzinfo is None:
        raise LedgerError('Reference time must include a timezone')
    if recorded > reference + timedelta(minutes=5):
        raise LedgerError('Record time is in the future')
    if event['baseline_sha256'] != baseline_sha256:
        raise LedgerError('Historical base does not match')
    if not isinstance(event['parent'], str) or not event['parent']:
        raise LedgerError('Missing parent')
    if event['parent'] != 'baseline:' + baseline_sha256:
        try:
            if str(uuid.UUID(event['parent'])) != event['parent']:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise LedgerError('Invalid parent id') from None
    source = event['source']
    if not isinstance(source, dict) or set(source) != {'kind', 'statement', 'thread_id', 'message_id'}:
        raise LedgerError('Missing source reference')
    if (source['kind'] != 'user_confirmed' or not isinstance(source['statement'], str)
            or not 1 <= len(source['statement'].strip()) <= 2048):
        raise LedgerError('Only user-confirmed facts are accepted')
    if (SECRET_LABEL.search(source['statement']) or PATTERNS['identity_number'].search(source['statement'])
            or any(p.search(source['statement']) for p in SECRET_PATTERNS.values())):
        raise LedgerError('Recognized secret or complete identity number is forbidden')
    try:
        for key in ('thread_id', 'message_id'):
            if source[key] is not None and str(uuid.UUID(source[key])) != source[key]:
                raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise LedgerError('Invalid source reference id') from None
    changes = event['changes']
    if not isinstance(changes, list) or not 1 <= len(changes) <= 100:
        raise LedgerError('Missing or excessive changes')
    touched = set()
    for change in changes:
        if not isinstance(change, dict) or set(change) != {'collection', 'record_id', 'field', 'before', 'after'}:
            raise LedgerError('Invalid change schema')
        collection, record_id, field = (change[k] for k in ('collection', 'record_id', 'field'))
        if not all(isinstance(x, str) and x.strip() for x in (collection, record_id, field)):
            raise LedgerError('Invalid target')
        if collection not in TARGETS or field not in TARGETS[collection][1]:
            raise LedgerError('Target field is not supported')
        target = (collection, record_id, field)
        if target in touched:
            raise LedgerError('Repeated target in one event')
        touched.add(target)
        for key in ('before', 'after'):
            value = change[key]
            if value is not None and type(value) not in (str, bool, int, float):
                raise LedgerError('Only scalar field changes are supported')
            if isinstance(value, float) and not math.isfinite(value):
                raise LedgerError('Non-finite field value')
            if isinstance(value, str) and (SECRET_LABEL.search(value) or PATTERNS['identity_number'].search(value)
                                         or any(p.search(value) for p in SECRET_PATTERNS.values())):
                raise LedgerError('Recognized credential content is forbidden')
        if change['before'] == change['after'] and type(change['before']) is type(change['after']):
            raise LedgerError('Change has no effect')
        if collection == 'checks' and change['after'] is not None and type(change['after']) is not bool:
            raise LedgerError('Check value must be true, false or null')
        if field == 'balance' and change['after'] is not None and type(change['after']) not in (int, float):
            raise LedgerError('Balance must be numeric or unknown')
        if field not in {'value', 'balance'} and change['after'] is not None and type(change['after']) is not str:
            raise LedgerError('Text field must be text or unknown')
        if collection == 'tasks' and field == 'due' and change['after'] is not None:
            try:
                if date.fromisoformat(change['after']).isoformat() != change['after']:
                    raise ValueError()
            except ValueError:
                raise LedgerError('Task date must use YYYY-MM-DD') from None


def materialize(base_raw: bytes, events: list[dict]) -> dict:
    """Return a full candidate only when the entire input forms one verified chain."""
    baseline_sha256 = hashlib.sha256(base_raw).hexdigest()
    state = decode_json(base_raw)
    if not isinstance(state, dict):
        raise LedgerError('Historical base must be an object')
    state = copy.deepcopy(state)
    by_id = {}
    for event in events:
        validate_event(event, baseline_sha256)
        previous = by_id.get(event['event_id'])
        if previous is not None and json.dumps(previous, sort_keys=True) != json.dumps(event, sort_keys=True):
            raise ConflictError('Event id has inconsistent content')
        by_id[event['event_id']] = event
    children = {}
    for event in by_id.values():
        if event['parent'] in children:
            raise ConflictError('Concurrent changes require reconciliation')
        children[event['parent']] = event
    head = 'baseline:' + baseline_sha256
    applied = []
    while head in children:
        event = children[head]
        for change in event['changes']:
            collection, field = change['collection'], change['field']
            rows = state.get(collection)
            if not isinstance(rows, list):
                raise LedgerError('Missing target collection')
            identity = TARGETS[collection][0]
            matches = [r for r in rows if isinstance(r, dict) and r.get(identity) == change['record_id']]
            if len(matches) != 1 or field not in matches[0]:
                raise LedgerError('Missing or ambiguous target')
            row = matches[0]
            before, after = change['before'], change['after']
            if type(row[field]) is not type(before) or row[field] != before:
                raise ConflictError('Previous field value has changed')
            if after is not None and before is not None and type(after) is not type(before):
                raise LedgerError('Field type must not change')
            row[field] = after
            row.setdefault('_confirmed_updates', []).append({
                'event_id': event['event_id'], 'field': field,
                'observed_at': event['observed_at'], 'recorded_at': event['recorded_at'],
                'source': event['source'],
            })
        applied.append(event['event_id'])
        head = event['event_id']
    if len(applied) != len(by_id):
        raise LedgerError('Missing parent or cyclic event chain')
    return {'baseline_sha256': baseline_sha256, 'head': head, 'applied_event_ids': applied, 'state': state}


def save_candidate(result: dict, output: Path, *, private_root: Path | None = None) -> None:
    """Private output only; do not touch the original baseline or Git business data."""
    output = output.absolute()
    private_root = (private_root or ROOT / '_private').absolute()
    if (not output.is_relative_to(private_root) or output == private_root
            or '..' in output.parts or '..' in private_root.parts or output.suffix.lower() != '.json'
            or any(p.is_symlink() for p in (output, *output.parents, private_root))):
        raise LedgerError('Output must be JSON inside the controlled private root without symlinks')
    payload = (json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2) + '\n').encode()
    private_root.mkdir(mode=0o700, exist_ok=True)
    missing = [p for p in (output.parent, *output.parent.parents) if p != private_root and private_root in p.parents]
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
    for directory in (private_root, *reversed(missing)):
        info = directory.stat()
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise LedgerError('Private directory must be owned by this user with mode 700')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as f:
            temporary = Path(f.name)
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        if temporary.read_bytes() != payload:
            raise LedgerError('Candidate readback failed')
        try:
            os.link(temporary, output)
        except FileExistsError:
            info = output.stat()
            if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
                raise LedgerError('Existing candidate must be owned by this user with mode 600') from None
            if output.read_bytes() != payload:
                raise ConflictError('Existing candidate must not be overwritten') from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description='离线核验确认记录；不连接云盘、不修改历史台账')
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--events', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.events.is_dir() or args.events.is_symlink():
        raise LedgerError('Missing events directory or symlink')
    output = args.output.resolve()
    if output.is_relative_to(args.events.resolve()):
        raise LedgerError('Output must be outside the events directory')
    records = sorted(args.events.iterdir())
    if any(p.is_symlink() or not p.is_file() or p.suffix.lower() != '.json' for p in records):
        raise LedgerError('Events directory contains an unexpected entry')
    inputs = [args.base, *records]
    if any(p.resolve() == output for p in inputs):
        raise LedgerError('Output must not overwrite an input')
    result = materialize(args.base.read_bytes(), [decode_json(p.read_bytes()) for p in inputs[1:]])
    save_candidate(result, args.output)
    print(json.dumps({'head': result['head'], 'applied_count': len(result['applied_event_ids'])}))


def cli() -> int:
    """Keep known local failures from disclosing paths or private input values."""
    try:
        main()
        return 0
    except (LedgerError, OSError, UnicodeError, ValueError, KeyError, TypeError):
        print('确认记录本地校验失败；请检查输入、确认链及私有输出目录。未连接或修改云端。')
        return 1


if __name__ == '__main__':
    raise SystemExit(cli())
