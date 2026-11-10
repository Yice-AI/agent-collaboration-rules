import copy
import contextlib
from datetime import datetime
import hashlib
import io
import json
import stat
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from scripts.confirmed_ledger import (
    ConflictError, LedgerError, decode_json, main, materialize, save_candidate, validate_event,
)


class ConfirmedLedgerTests(unittest.TestCase):
    def setUp(self):
        self.base = {'snapshot_as_of': '2026-09-27', 'accounts': [
            {'id': 'virtual', '当前状态': '申请中', '备注': '虚拟资料', 'balance': None},
        ], 'checks': [{'id': 'virtual-check', 'value': None}],
            'tasks': [{'id': 'virtual-task', 'complete': '虚拟完成标准', 'due': None}]}
        self.raw = json.dumps(self.base, ensure_ascii=False).encode()
        self.sha = hashlib.sha256(self.raw).hexdigest()

    def event(self, **overrides):
        result = {'schema_version': 1, 'event_id': str(uuid.uuid4()),
                  'parent': 'baseline:' + self.sha, 'baseline_sha256': self.sha,
                  'observed_at': '2026-09-28', 'recorded_at': '2026-09-28T10:00:00+08:00',
                  'source': {'kind': 'user_confirmed', 'statement': '虚拟账户已经获批。', 'thread_id': str(uuid.uuid4()),
                             'message_id': str(uuid.uuid4())},
                  'changes': [{'collection': 'accounts', 'record_id': 'virtual',
                               'field': '当前状态', 'before': '申请中', 'after': '获批'}]}
        result.update(overrides)
        return result

    def test_chain_replays_in_parent_order_and_keeps_sources_and_baseline(self):
        first = self.event()
        second = self.event(parent=first['event_id'], changes=[{
            'collection': 'accounts', 'record_id': 'virtual', 'field': '当前状态',
            'before': '获批', 'after': '激活',
        }])
        result = materialize(self.raw, [second, first])
        self.assertEqual(result['applied_event_ids'], [first['event_id'], second['event_id']])
        self.assertEqual(result['state']['accounts'][0]['当前状态'], '激活')
        self.assertEqual(result['state']['accounts'][0]['_confirmed_updates'][0]['source'], first['source'])
        self.assertEqual(decode_json(self.raw), self.base)
        self.assertEqual(result['state']['snapshot_as_of'], '2026-09-27')

    def test_same_id_same_content_is_deduplicated(self):
        event = self.event()
        self.assertEqual(len(materialize(self.raw, [event, copy.deepcopy(event)])['applied_event_ids']), 1)

    def test_same_id_different_content_is_rejected(self):
        event = self.event()
        changed = copy.deepcopy(event)
        changed['changes'][0]['after'] = '关闭'
        with self.assertRaises(ConflictError):
            materialize(self.raw, [event, changed])

    def test_concurrent_siblings_do_not_pick_a_winner(self):
        with self.assertRaises(ConflictError):
            materialize(self.raw, [self.event(), self.event()])

    def test_missing_parent_or_cycle_is_rejected(self):
        event = self.event(parent=str(uuid.uuid4()))
        with self.assertRaises(LedgerError):
            materialize(self.raw, [event])
        event['parent'] = event['event_id']
        with self.assertRaises(LedgerError):
            materialize(self.raw, [event])

    def test_before_value_must_match_exactly(self):
        event = self.event()
        event['changes'][0]['before'] = '关闭'
        with self.assertRaises(ConflictError):
            materialize(self.raw, [event])

    def test_boolean_and_integer_are_not_interchangeable(self):
        base = copy.deepcopy(self.base)
        base['checks'][0]['value'] = False
        raw = json.dumps(base, ensure_ascii=False).encode()
        digest = hashlib.sha256(raw).hexdigest()
        event = self.event(baseline_sha256=digest, parent='baseline:' + digest, changes=[{
            'collection': 'checks', 'record_id': 'virtual-check', 'field': 'value', 'before': 0, 'after': True}])
        with self.assertRaises(ConflictError):
            materialize(raw, [event])

    def test_check_rejects_text_true(self):
        event = self.event(changes=[{'collection': 'checks', 'record_id': 'virtual-check',
                                    'field': 'value', 'before': None, 'after': 'true'}])
        with self.assertRaises(LedgerError):
            materialize(self.raw, [event])

    def test_source_must_reference_user_message(self):
        event = self.event()
        event['source']['kind'] = 'assistant_guess'
        with self.assertRaises(LedgerError):
            materialize(self.raw, [event])

    def test_future_observation_and_missing_timezone_are_rejected(self):
        for overrides in ({'observed_at': '2026-09-29'}, {'recorded_at': '2026-09-28T10:00:00'}):
            with self.assertRaises(LedgerError):
                materialize(self.raw, [self.event(**overrides)])

    def test_future_record_time_is_rejected_against_reference_clock(self):
        event = self.event(observed_at='2099-01-01', recorded_at='2099-01-01T10:00:00+08:00')
        with self.assertRaises(LedgerError):
            validate_event(event, self.sha, now=datetime.fromisoformat('2026-09-28T10:00:00+08:00'))

    def test_observation_date_uses_the_projects_shanghai_timezone(self):
        event = self.event(recorded_at='2026-09-27T18:00:00+00:00')
        self.assertEqual(len(materialize(self.raw, [event])['applied_event_ids']), 1)

    def test_wrong_baseline_or_unknown_field_is_rejected(self):
        with self.assertRaises(LedgerError):
            materialize(self.raw, [self.event(baseline_sha256='0' * 64)])
        event = self.event()
        event['changes'][0]['field'] = '密码'
        with self.assertRaises(LedgerError):
            materialize(self.raw, [event])

    def test_credential_text_in_business_note_is_rejected(self):
        event = self.event()
        event['changes'][0].update(field='备注', before='虚拟资料', after='P' + 'IN' + ':' + ' 1234')
        with self.assertRaises(LedgerError):
            materialize(self.raw, [event])

    def test_missing_or_ambiguous_target_is_rejected(self):
        event = self.event()
        event['changes'][0]['record_id'] = 'absent'
        with self.assertRaises(LedgerError):
            materialize(self.raw, [event])
        base = copy.deepcopy(self.base)
        base['accounts'].append(copy.deepcopy(base['accounts'][0]))
        raw = json.dumps(base, ensure_ascii=False).encode()
        digest = hashlib.sha256(raw).hexdigest()
        event = self.event(baseline_sha256=digest, parent='baseline:' + digest)
        with self.assertRaises(LedgerError):
            materialize(raw, [event])

    def test_duplicate_json_keys_and_nonfinite_values_are_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(LedgerError):
                decode_json(raw)

    def test_output_is_private_atomic_and_cannot_overwrite_other_candidate(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder).resolve() / '_private' / 'current' / 'candidate.json'
            result = materialize(self.raw, [self.event()])
            save_candidate(result, path, private_root=Path(folder).resolve() / '_private')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            before = path.read_bytes()
            save_candidate(result, path, private_root=Path(folder).resolve() / '_private')
            with self.assertRaises(ConflictError):
                save_candidate(materialize(self.raw, []), path, private_root=Path(folder).resolve() / '_private')
            self.assertEqual(path.read_bytes(), before)

    def test_nonprivate_path_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            result = materialize(self.raw, [])
            with self.assertRaises(LedgerError):
                save_candidate(result, root / 'public.json', private_root=root / '_private')
            private = root / '_private'
            private.mkdir()
            (private / 'link').symlink_to(root, target_is_directory=True)
            with self.assertRaises(LedgerError):
                save_candidate(result, private / 'link' / 'candidate.json', private_root=private)

    def test_nested_private_directory_and_nonjson_output_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            result = materialize(self.raw, [])
            for path in (root / 'docs' / '_private' / 'candidate.md', root / '_private' / 'candidate.md'):
                with self.assertRaises(LedgerError):
                    save_candidate(result, path, private_root=root / '_private')

    def test_existing_candidate_with_wide_permissions_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            private = Path(folder).resolve() / '_private'
            path = private / 'candidate.json'
            result = materialize(self.raw, [])
            save_candidate(result, path, private_root=private)
            path.chmod(0o644)
            with self.assertRaises(LedgerError):
                save_candidate(result, path, private_root=private)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    def test_missing_message_ids_are_honestly_recorded_with_user_statement(self):
        event = self.event()
        event['source'].update(thread_id=None, message_id=None)
        self.assertEqual(len(materialize(self.raw, [event])['applied_event_ids']), 1)

    def test_task_completion_standard_is_not_a_boolean_status(self):
        event = self.event(changes=[{'collection': 'tasks', 'record_id': 'virtual-task',
                                    'field': 'complete', 'before': '虚拟完成标准', 'after': True}])
        with self.assertRaises(LedgerError):
            materialize(self.raw, [event])

    def test_cli_reads_uppercase_json_and_rejects_unexpected_entries(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            base = root / 'base.json'
            base.write_bytes(self.raw)
            events = root / 'events'
            events.mkdir()
            (events / 'confirmed.JSON').write_text(json.dumps(self.event(), ensure_ascii=False))
            output = root / '_private' / 'candidate.json'
            argv = ['confirmed_ledger', '--base', str(base), '--events', str(events), '--output', str(output)]
            with patch('sys.argv', argv), patch('scripts.confirmed_ledger.ROOT', root), contextlib.redirect_stdout(io.StringIO()):
                main()
            self.assertEqual(len(json.loads(output.read_text())['applied_event_ids']), 1)
            (events / 'unexpected.txt').write_text('unexpected')
            before = output.read_bytes()
            with patch('sys.argv', argv), patch('scripts.confirmed_ledger.ROOT', root), self.assertRaises(LedgerError):
                main()
            self.assertEqual(output.read_bytes(), before)
            (events / 'unexpected.txt').unlink()
            argv[-1] = str(events / 'candidate.json')
            with patch('sys.argv', argv), patch('scripts.confirmed_ledger.ROOT', root), self.assertRaises(LedgerError):
                main()
