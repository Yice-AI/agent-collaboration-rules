"""Verify a Drive commit manifest against immutable confirmed-event documents.

The caller must independently read every referenced document and its owner-only
permissions. This module never writes to Drive or the historical baseline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import uuid
from pathlib import Path

if __package__:
    from scripts.confirmed_ledger import ConflictError, LedgerError, decode_json, materialize, save_candidate, validate_event
else:
    from confirmed_ledger import ConflictError, LedgerError, decode_json, materialize, save_candidate, validate_event

_SHA256 = re.compile(r'[0-9a-f]{64}\Z')
_DOCUMENT_ID = re.compile(r'[A-Za-z0-9_-]{10,200}\Z')


def validate_owner_only_metadata(metadata: dict, folder_id: str) -> None:
    """Reject files whose Drive metadata cannot prove owner-only containment."""
    if not isinstance(metadata, dict) or not isinstance(folder_id, str):
        raise LedgerError('Missing Drive permission metadata')
    permissions = metadata.get('permissions')
    if (metadata.get('shared') is not False or metadata.get('parent_ids') != [folder_id]
            or not isinstance(permissions, list) or len(permissions) != 1
            or not isinstance(permissions[0], dict)
            or permissions[0].get('type') != 'user'
            or permissions[0].get('role') != 'owner'):
        raise LedgerError('Drive document is not verified owner-only in the ledger folder')


def validate_manifest(manifest: dict, baseline_sha256: str) -> None:
    if (not isinstance(manifest, dict) or set(manifest) !=
            {'schema_version', 'baseline_sha256', 'head', 'events'}):
        raise LedgerError('Unexpected manifest schema')
    if type(manifest['schema_version']) is not int or manifest['schema_version'] != 1:
        raise LedgerError('Unsupported manifest version')
    if manifest['baseline_sha256'] != baseline_sha256:
        raise LedgerError('Historical base does not match manifest')
    records = manifest['events']
    if not isinstance(records, list):
        raise LedgerError('Manifest events must be a list')
    ids, documents = set(), set()
    for item in records:
        if not isinstance(item, dict) or set(item) != {'event_id', 'document_id', 'sha256'}:
            raise LedgerError('Invalid manifest entry')
        event_id, document_id, digest = (item[k] for k in ('event_id', 'document_id', 'sha256'))
        try:
            if str(uuid.UUID(event_id)) != event_id:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise LedgerError('Invalid manifest event id') from None
        if (not isinstance(document_id, str) or not _DOCUMENT_ID.fullmatch(document_id)
                or not isinstance(digest, str) or not _SHA256.fullmatch(digest)):
            raise LedgerError('Invalid manifest document reference')
        if event_id in ids or document_id in documents:
            raise ConflictError('Repeated event or document in manifest')
        ids.add(event_id)
        documents.add(document_id)
    expected_head = records[-1]['event_id'] if records else 'baseline:' + baseline_sha256
    if manifest['head'] != expected_head:
        raise LedgerError('Manifest head does not match its final entry')


def materialize_manifest(base_raw: bytes, manifest: dict, documents: dict[str, str],
                         *, listed_document_ids: set[str] | None = None,
                         head_document_id: str | None = None) -> dict:
    """Replay committed records; report uncommitted docs when a full listing exists.

    `documents` contains the exact single-line text read from each referenced Doc.
    The caller must separately verify ownership, folder and listing pagination.
    A full listing must include the explicitly identified HEAD document.
    """
    baseline_sha256 = hashlib.sha256(base_raw).hexdigest()
    validate_manifest(manifest, baseline_sha256)
    if not isinstance(documents, dict):
        raise LedgerError('Missing document text mapping')
    required = {item['document_id'] for item in manifest['events']}
    if set(documents) != required:
        raise LedgerError('Required document text is missing or unexpected')
    if listed_document_ids is not None:
        if (not isinstance(head_document_id, str) or not _DOCUMENT_ID.fullmatch(head_document_id)
                or head_document_id in required or not isinstance(listed_document_ids, set)
                or head_document_id not in listed_document_ids
                or not required <= listed_document_ids):
            raise LedgerError('Folder listing omits a committed document')
    events = []
    previous = 'baseline:' + baseline_sha256
    for item in manifest['events']:
        raw_text = documents[item['document_id']]
        if not isinstance(raw_text, str) or not raw_text or '\n' in raw_text or '\r' in raw_text:
            raise LedgerError('Event document must contain exactly one line of JSON')
        raw = raw_text.encode('utf-8')
        if hashlib.sha256(raw).hexdigest() != item['sha256']:
            raise LedgerError('Event document hash mismatch')
        try:
            event = decode_json(raw)
        except (UnicodeError, ValueError) as exc:
            raise LedgerError('Invalid event document JSON') from exc
        validate_event(event, baseline_sha256)
        if event['event_id'] != item['event_id'] or event['parent'] != previous:
            raise ConflictError('Event does not extend the committed head')
        events.append(event)
        previous = event['event_id']
    result = materialize(base_raw, events)
    if result['head'] != manifest['head']:
        raise LedgerError('Replayed head differs from manifest')
    uncommitted = (sorted(listed_document_ids - required - {head_document_id})
                   if listed_document_ids is not None else None)
    result['folder_audit'] = ('not_performed' if uncommitted is None else
                              'uncommitted_found' if uncommitted else 'complete')
    result['uncommitted_document_ids'] = uncommitted
    return result


def append_manifest(manifest: dict, event: dict, document_id: str, document_text: str) -> dict:
    """Prepare the next manifest for a revision-guarded Drive write."""
    baseline_sha256 = manifest.get('baseline_sha256') if isinstance(manifest, dict) else None
    if not isinstance(baseline_sha256, str) or not _SHA256.fullmatch(baseline_sha256):
        raise LedgerError('Invalid baseline hash')
    validate_manifest(manifest, baseline_sha256)
    validate_event(event, baseline_sha256)
    if event['parent'] != manifest['head']:
        raise ConflictError('Event was prepared against an older head')
    if (not isinstance(document_id, str) or not _DOCUMENT_ID.fullmatch(document_id)
            or not isinstance(document_text, str) or '\n' in document_text or '\r' in document_text):
        raise LedgerError('Invalid event document')
    parsed = decode_json(document_text.encode('utf-8'))
    canonical = lambda value: json.dumps(value, ensure_ascii=False, sort_keys=True,
                                         separators=(',', ':'), allow_nan=False)
    if canonical(parsed) != canonical(event):
        raise LedgerError('Event document differs from validated event')
    item = {'event_id': event['event_id'], 'document_id': document_id,
            'sha256': hashlib.sha256(document_text.encode('utf-8')).hexdigest()}
    if any(existing['event_id'] == item['event_id'] or existing['document_id'] == document_id
           for existing in manifest['events']):
        raise ConflictError('Event or document already appears in manifest')
    return {**manifest, 'head': event['event_id'], 'events': [*manifest['events'], item]}


def receipt_status(manifest: dict, event_id: str, document_id: str, sha256: str) -> str:
    """Check manifest membership after a lost response; document proof is separate."""
    baseline_sha256 = manifest.get('baseline_sha256') if isinstance(manifest, dict) else None
    if not isinstance(baseline_sha256, str) or not _SHA256.fullmatch(baseline_sha256):
        raise LedgerError('Invalid baseline hash')
    validate_manifest(manifest, baseline_sha256)
    matches = [item for item in manifest['events'] if item['event_id'] == event_id]
    if not matches:
        return 'pending'
    if matches[0]['document_id'] != document_id or matches[0]['sha256'] != sha256:
        raise ConflictError('Event id is committed with different content')
    return 'listed_unverified'


def prepare_head(manifest_text: str, event: dict, document_id: str, document_text: str,
                 *, head_document_id: str, revision_id: str, tab_id: str,
                 paragraph_end_index: int) -> dict:
    """Build a local, revision-guarded HEAD plan; never upload or claim ownership."""
    if (not isinstance(manifest_text, str) or not manifest_text
            or '\r' in manifest_text or '\n' in manifest_text.rstrip('\n')):
        raise LedgerError('HEAD must be one JSON paragraph with optional terminal LF')
    if (not isinstance(head_document_id, str) or not _DOCUMENT_ID.fullmatch(head_document_id)
            or head_document_id == document_id or not isinstance(revision_id, str)
            or not revision_id.strip() or not isinstance(tab_id, str) or not tab_id.strip()):
        raise LedgerError('Missing HEAD identity, conditional revision or tab')
    old_units = len(manifest_text.rstrip('\n').encode('utf-16-le')) // 2
    if type(paragraph_end_index) is not int or paragraph_end_index != old_units + 2:
        raise LedgerError('Native HEAD paragraph range does not match the source text')
    manifest = decode_json(manifest_text.encode('utf-8'))
    baseline_sha256 = manifest.get('baseline_sha256') if isinstance(manifest, dict) else None
    if not isinstance(baseline_sha256, str) or not _SHA256.fullmatch(baseline_sha256):
        raise LedgerError('Invalid baseline hash')
    validate_manifest(manifest, baseline_sha256)
    validate_event(event, baseline_sha256)
    # append_manifest validates original event bytes, duplicate documents and
    # exact parent. Membership alone is deliberately not a success receipt.
    expected = append_manifest(manifest, event, document_id, document_text)
    replacement = json.dumps(expected, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    return {
        'status': 'local_plan_only', 'cloud_saved': False,
        'document_id': head_document_id, 'expected': expected,
        'requests': [
            {'deleteContentRange': {'range': {
                'startIndex': 1, 'endIndex': paragraph_end_index - 1, 'tabId': tab_id}}},
            {'insertText': {'location': {'index': 1, 'tabId': tab_id}, 'text': replacement}},
        ],
        'write_control': {'requiredRevisionId': revision_id},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='离线核验云盘确认链或生成HEAD条件写入计划；不上传、不核验云端权限')
    commands = parser.add_subparsers(dest='command', required=True)
    verify = commands.add_parser('verify')
    for flag in ('base', 'manifest', 'documents', 'listed-ids', 'output'):
        verify.add_argument('--' + flag, type=Path, required=True)
    verify.add_argument('--head-document-id', required=True)
    prepare = commands.add_parser('prepare-head')
    for flag in ('manifest', 'event', 'document-text', 'out'):
        prepare.add_argument('--' + flag, type=Path, required=True)
    for flag in ('document-id', 'head-document-id', 'revision', 'tab'):
        prepare.add_argument('--' + flag, required=True)
    prepare.add_argument('--paragraph-end-index', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'verify':
            listed = decode_json(args.listed_ids.read_bytes())
            if (not isinstance(listed, list) or any(not isinstance(x, str) for x in listed)
                    or len(listed) != len(set(listed))):
                raise LedgerError('Listing must be an array of unique document IDs')
            result = materialize_manifest(
                args.base.read_bytes(), decode_json(args.manifest.read_bytes()),
                decode_json(args.documents.read_bytes()), listed_document_ids=set(listed),
                head_document_id=args.head_document_id)
            if result['folder_audit'] != 'complete':
                raise ConflictError('Folder contains uncommitted or unknown documents')
            save_candidate(result, args.output)
            print(json.dumps({'status': 'local_chain_match_only', 'cloud_saved': False,
                              'permissions_verified': False, 'head': result['head'],
                              'applied_count': len(result['applied_event_ids'])}))
        else:
            plan = prepare_head(
                args.manifest.read_bytes().decode('utf-8'), decode_json(args.event.read_bytes()),
                args.document_id, args.document_text.read_bytes().decode('utf-8'),
                head_document_id=args.head_document_id, revision_id=args.revision,
                tab_id=args.tab, paragraph_end_index=args.paragraph_end_index)
            save_candidate(plan, args.out)
            print(json.dumps({'status': 'local_plan_only', 'cloud_saved': False,
                              'head': plan['expected']['head']}))
        return 0
    except (LedgerError, OSError, UnicodeError, ValueError, KeyError, TypeError):
        print('本地核验失败；未上传。请核对正文、范围、目录清单和私有输出路径，不盲重试。')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
