"""Validate and plan append-only working notes; never writes cloud or account data.

The caller verifies owner-only Drive metadata, a single JSON paragraph/tab,
conditional-write response and readback. Notes are context, not account truth.
"""
from __future__ import annotations

import copy
import argparse
import json
import re
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

if __package__:
    from scripts.confirmed_ledger import ConflictError, LedgerError, SECRET_LABEL, decode_json, save_candidate
    from scripts.privacy_check import walk_json
else:
    from confirmed_ledger import ConflictError, LedgerError, SECRET_LABEL, decode_json, save_candidate
    from privacy_check import walk_json

KINDS = {'need', 'decision', 'research', 'runtime', 'result'}
STATUSES = {'open', 'waiting', 'resolved'}
SOURCE_KINDS = {'user_statement', 'assistant_report', 'tool_readback', 'official_source'}
ENTRY_KEYS = {'id', 'topic', 'kind', 'status', 'summary', 'next_step', 'source',
              'recorded_at', 'supersedes', 'recheck_before_action'}
DRAFT_KEYS = ENTRY_KEYS - {'id', 'recorded_at', 'supersedes'}
MAX_BYTES = 200_000


def encode_log(log: dict) -> str:
    return json.dumps(log, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def validate_log(log: dict, *, now: datetime | None = None) -> None:
    if not isinstance(log, dict) or set(log) != {'schema_version', 'version', 'entries'}:
        raise LedgerError('Unexpected work-context schema')
    if type(log['schema_version']) is not int or log['schema_version'] != 1:
        raise LedgerError('Unsupported work-context schema')
    entries = log['entries']
    if (not isinstance(entries, list) or type(log['version']) is not int
            or log['version'] != len(entries)):
        raise LedgerError('Version must equal the append-only entry count')
    if len(encode_log(log).encode('utf-8')) > MAX_BYTES:
        raise LedgerError('Work context needs reviewed archival; never truncate history')
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        raise LedgerError('Reference time needs timezone')
    ids, latest = set(), {}
    previous_recorded = None
    for number, entry in enumerate(entries, 1):
        prefix = f'Entry {number}: '
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise LedgerError(prefix + 'Unexpected working entry fields')
        try:
            if str(uuid.UUID(entry['id'])) != entry['id'] or entry['id'] in ids:
                raise ValueError()
            recorded = datetime.fromisoformat(entry['recorded_at'])
        except (ValueError, TypeError, AttributeError):
            raise LedgerError(prefix + 'Invalid or duplicate working entry id/time') from None
        if (recorded.tzinfo is None or recorded > reference + timedelta(minutes=5)
                or (previous_recorded is not None and recorded < previous_recorded)):
            raise LedgerError(prefix + 'Invalid recorded_at chronology')
        topic = entry['topic']
        if not isinstance(topic, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,79}', topic):
            raise LedgerError(prefix + 'Invalid working topic')
        if (not isinstance(entry['kind'], str) or entry['kind'] not in KINDS
                or not isinstance(entry['status'], str) or entry['status'] not in STATUSES):
            raise LedgerError(prefix + 'Unsupported working kind/status')
        if type(entry['recheck_before_action']) is not bool:
            raise LedgerError(prefix + 'Invalid recheck_before_action')
        if entry['kind'] in {'research', 'runtime'} and not entry['recheck_before_action']:
            raise LedgerError(prefix + 'Research and runtime reports require action-time recheck')
        for field in ('summary', 'next_step'):
            if not isinstance(entry[field], str) or not 1 <= len(entry[field].strip()) <= 2000:
                raise LedgerError(prefix + f'Missing or excessive {field}')
            if SECRET_LABEL.search(entry[field]):
                raise LedgerError(prefix + f'Recognized secret label in {field} is forbidden')
        source = entry['source']
        if not isinstance(source, dict) or set(source) != {'kind', 'reference', 'observed_at'}:
            raise LedgerError(prefix + 'Working notes need source and observation date')
        if (not isinstance(source['kind'], str) or source['kind'] not in SOURCE_KINDS
                or not isinstance(source['reference'], str)
                or not 1 <= len(source['reference'].strip()) <= 1000):
            raise LedgerError(prefix + 'Invalid source.kind/reference')
        if entry['kind'] in {'need', 'decision'} and source['kind'] != 'user_statement':
            raise LedgerError(prefix + 'Needs and decisions require an explicit user source')
        if SECRET_LABEL.search(source['reference']):
            raise LedgerError(prefix + 'Recognized secret source reference is forbidden')
        try:
            observed = date.fromisoformat(source['observed_at'])
        except (ValueError, TypeError):
            raise LedgerError(prefix + 'Invalid source.observed_at') from None
        if (observed.isoformat() != source['observed_at']
                or observed > recorded.astimezone(timezone(timedelta(hours=8))).date()):
            raise LedgerError(prefix + 'Invalid or future source.observed_at')
        if entry['supersedes'] != latest.get(topic):
            raise ConflictError(prefix + 'supersedes must extend the exact latest topic entry')
        if any(walk_json(entry)):
            raise LedgerError(prefix + 'Recognized private identity or credential content')
        ids.add(entry['id'])
        latest[topic] = entry['id']
        previous_recorded = recorded


def parse_log(text: str) -> dict:
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_BYTES:
        raise LedgerError('Invalid or excessive work-context text')
    # Native Docs may leave empty terminal paragraphs after a text replacement.
    # Only LF terminators are tolerated; never strip or merge body content.
    raw = text.rstrip('\n')
    if '\n' in raw or '\r' in raw:
        raise LedgerError('Expected a single JSON paragraph')
    log = decode_json(raw.encode('utf-8'))
    validate_log(log)
    return log


def latest_entries(log: dict) -> list[dict]:
    validate_log(log)
    latest = {}
    for entry in log['entries']:
        latest[entry['topic']] = copy.deepcopy(entry)
    return sorted(latest.values(), key=lambda item: datetime.fromisoformat(item['recorded_at']),
                  reverse=True)


def prepare_append(text: str, entry: dict, *, revision_id: str, tab_id: str,
                   paragraph_end_index: int | None = None) -> dict:
    """Prepare exact replacement at the read revision; never auto-rebase conflicts."""
    if (not isinstance(revision_id, str) or not revision_id.strip()
            or not isinstance(tab_id, str) or not tab_id.strip()):
        raise LedgerError('Missing conditional revision or tab')
    current = parse_log(text)
    if not isinstance(entry, dict):
        raise LedgerError('Invalid working entry')
    for old in current['entries']:
        if old['id'] == entry.get('id'):
            if old != entry:
                raise ConflictError('Same entry id has different content')
            return {'status': 'already_present', 'expected': current, 'requests': [],
                    'write_control': None}
    updated = copy.deepcopy(current)
    updated['entries'].append(copy.deepcopy(entry))
    updated['version'] += 1
    validate_log(updated)
    replacement = encode_log(updated)
    # Replace only the JSON paragraph; native Docs retains its final newline.
    # Preserve existing empty terminal paragraphs and budget for them up front.
    terminal_lines = max(1, len(text) - len(text.rstrip('\n')))
    if len(replacement.encode('utf-8')) + terminal_lines > MAX_BYTES:
        raise LedgerError('Work context needs reviewed archival; native text exceeds limit')
    if paragraph_end_index is not None:
        # Native Docs indexes are UTF-16 units. Caller must verify a plain JSON
        # paragraph starting at 1, its actual endIndex, and no protected controls.
        old_units = len(text.rstrip('\n').encode('utf-16-le')) // 2
        if type(paragraph_end_index) is not int or paragraph_end_index != old_units + 2:
            raise LedgerError('Native JSON paragraph range does not match the source text')
        requests = [
            {'deleteContentRange': {'range': {
                'startIndex': 1, 'endIndex': paragraph_end_index - 1, 'tabId': tab_id}}},
            {'insertText': {'location': {'index': 1, 'tabId': tab_id}, 'text': replacement}},
        ]
    else:
        requests = [{'replaceAllText': {
            'containsText': {'text': text.rstrip('\n'), 'matchCase': True},
            'replaceText': replacement, 'tabsCriteria': {'tabIds': [tab_id]},
        }}]
    return {
        'status': 'ready', 'expected': updated, 'requests': requests,
        'write_control': {'requiredRevisionId': revision_id},
    }


def confirm_append(plan: dict, readback: str) -> bool:
    """Allow later valid appends, but require the complete expected history prefix."""
    expected = plan['expected']
    validate_log(expected)
    actual = parse_log(readback)
    return (actual['version'] >= expected['version']
            and actual['entries'][:expected['version']] == expected['entries'])


def prepare_draft(text: str, draft: dict, *, revision_id: str, tab_id: str,
                  paragraph_end_index: int | None = None) -> dict:
    """Generate system fields once; invalid history and aliases remain errors."""
    current = parse_log(text)
    if not isinstance(draft, dict) or set(draft) != DRAFT_KEYS:
        raise LedgerError('Draft must contain exactly the seven content fields')
    parent = next((old['id'] for old in reversed(current['entries'])
                   if old['topic'] == draft['topic']), None)
    entry = copy.deepcopy(draft)
    entry.update(id=str(uuid.uuid4()), recorded_at=datetime.now(timezone.utc).isoformat(),
                 supersedes=parent)
    plan = prepare_append(text, entry, revision_id=revision_id, tab_id=tab_id,
                          paragraph_end_index=paragraph_end_index)
    plan['entry'] = entry
    return plan


def main(argv: list[str] | None = None) -> int:
    """Local preparation only. The caller still verifies and submits via Drive."""
    parser = argparse.ArgumentParser(description='近期工作记录：本地校验和生成，不写云盘')
    commands = parser.add_subparsers(dest='command', required=True)
    validate = commands.add_parser('validate')
    validate.add_argument('--input', type=Path, required=True)
    prepare = commands.add_parser('prepare')
    for flag in ('input', 'draft', 'out'):
        prepare.add_argument('--' + flag, type=Path, required=True)
    for flag in ('revision', 'tab', 'document-id'):
        prepare.add_argument('--' + flag, required=True)
    prepare.add_argument('--paragraph-end-index', type=int, required=True,
                         help='本轮原生读取的正文 JSON 段落 endIndex；须确认起点为 1 且无控件')
    verify = commands.add_parser('verify')
    verify.add_argument('--input', type=Path, required=True)
    verify.add_argument('--plan', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        # Preserve LF/CR exactly: native paragraph validation must see raw bytes.
        text = args.input.read_bytes().decode('utf-8')
        if args.command == 'prepare':
            if not args.document_id.strip():
                raise LedgerError('Missing document ID')
            draft = decode_json(args.draft.read_bytes())
            plan = prepare_draft(text, draft, revision_id=args.revision, tab_id=args.tab,
                                 paragraph_end_index=args.paragraph_end_index)
            plan['document_id'] = args.document_id
            save_candidate(plan, args.out)
            print(json.dumps({'status': 'local_plan_only', 'cloud_saved': False,
                              'version': plan['expected']['version'], 'id': plan['entry']['id']}))
        elif args.command == 'verify':
            plan = decode_json(args.plan.read_bytes())
            if not confirm_append(plan, text):
                raise LedgerError('Readback does not match the expected history prefix')
            print(json.dumps({'status': 'local_content_match_only', 'cloud_saved': False}))
        else:
            log = parse_log(text)
            print(json.dumps({'status': 'local_validation_only', 'version': log['version']}))
        return 0
    except LedgerError as error:
        print(f'本地校验失败：{error}；未写云盘。核对输入，必要时交付待手动保存摘要。')
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        # Never print input content, credentials, private paths or an unsafe traceback.
        print('本地校验失败或候选文件已存在；未写云盘。核对输入，必要时交付待手动保存摘要。')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
