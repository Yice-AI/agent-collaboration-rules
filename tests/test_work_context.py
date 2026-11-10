import copy
import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.confirmed_ledger import ConflictError, LedgerError, save_candidate
from scripts.work_context import confirm_append, encode_log, latest_entries, parse_log, prepare_append
from scripts.work_context import main, prepare_draft


class WorkContextTests(unittest.TestCase):
    def setUp(self):
        self.empty = {'schema_version': 1, 'version': 0, 'entries': []}
        self.entry = {
            'id': '352e0631-d470-4f1b-96c4-9c2343676486', 'topic': 'sample-need',
            'kind': 'need', 'status': 'open', 'summary': '需要理解完整费用。',
            'next_step': '用通俗语言整理已有证据与待核验项。',
            'source': {'kind': 'user_statement', 'reference': 'test-fixture',
                       'observed_at': '2026-09-27'},
            'recorded_at': datetime.now(timezone.utc).isoformat(),
            'supersedes': None, 'recheck_before_action': False,
        }

    def plan(self, text=None, entry=None):
        return prepare_append(text or encode_log(self.empty), entry or self.entry,
                              revision_id='provider-revision', tab_id='t.0')

    def test_conditional_append_preserves_history_and_input(self):
        first = self.plan()
        self.assertEqual(first['write_control'], {'requiredRevisionId': 'provider-revision'})
        self.assertEqual(self.empty['entries'], [])
        newer = dict(self.entry, id='96d26e68-6700-46cc-b13f-a643ef222dba',
                     supersedes=self.entry['id'], status='waiting')
        second = self.plan(encode_log(first['expected']), newer)
        self.assertEqual(second['expected']['entries'][0], self.entry)
        self.assertTrue(confirm_append(first, encode_log(second['expected'])))
        self.assertEqual(latest_entries(second['expected']), [newer])

    def test_duplicate_is_noop_and_changed_id_is_conflict(self):
        first = self.plan()
        text = encode_log(first['expected'])
        self.assertEqual(self.plan(text)['status'], 'already_present')
        with self.assertRaises(ConflictError):
            self.plan(text, dict(self.entry, summary='另一个内容'))

    def test_stale_topic_parent_cannot_overwrite_newer_work(self):
        current = self.plan()['expected']
        with self.assertRaises(ConflictError):
            self.plan(encode_log(current), dict(self.entry,
                      id='96d26e68-6700-46cc-b13f-a643ef222dba', supersedes=None))

    def test_readback_cannot_drop_or_change_history(self):
        first = self.plan()
        self.assertFalse(confirm_append(first, encode_log(self.empty)))
        altered = copy.deepcopy(first['expected'])
        altered['entries'][0]['summary'] = '内容变了'
        self.assertFalse(confirm_append(first, encode_log(altered)))

    def test_missing_revision_duplicate_keys_and_multi_paragraph_fail(self):
        with self.assertRaises(LedgerError):
            prepare_append(encode_log(self.empty), self.entry, revision_id='', tab_id='t.0')
        with self.assertRaises(LedgerError):
            parse_log('{"schema_version":1,"schema_version":1,"version":0,"entries":[]}')
        with self.assertRaises(LedgerError):
            parse_log(encode_log(self.empty) + '\n{}')

    def test_native_terminal_empty_paragraph_preserves_history_and_cas(self):
        text = encode_log(self.empty) + '\n\n'
        plan = self.plan(text)
        self.assertEqual(plan['write_control'], {'requiredRevisionId': 'provider-revision'})
        replacement = plan['requests'][0]['replaceAllText']
        self.assertEqual(replacement['containsText']['text'], text.rstrip('\n'))
        readback = text.replace(replacement['containsText']['text'], replacement['replaceText'])
        self.assertTrue(confirm_append(plan, readback))
        self.assertEqual(parse_log(readback)['entries'], [self.entry])

    def test_append_reserves_native_terminal_paragraph_bytes(self):
        from unittest.mock import patch
        expected = self.plan()['expected']
        encoded_size = len(encode_log(expected).encode('utf-8'))
        for tail in ('', '\n', '\n\n'):
            retained = max(1, len(tail))
            with self.subTest(tail=repr(tail)):
                with patch('scripts.work_context.MAX_BYTES', encoded_size + retained - 1):
                    with self.assertRaises(LedgerError):
                        self.plan(encode_log(self.empty) + tail)
                with patch('scripts.work_context.MAX_BYTES', encoded_size + retained):
                    plan = self.plan(encode_log(self.empty) + tail)
                    self.assertTrue(confirm_append(plan, encode_log(plan['expected']) + '\n' * retained))

    def test_terminal_newlines_do_not_hide_content_or_bypass_size_limit(self):
        from scripts.work_context import MAX_BYTES
        text = encode_log(self.empty)
        for invalid in ('\n' + text, text + '\n{}\n', text + '\nextra\n',
                        text + '\r\n', text + '\n' * MAX_BYTES):
            with self.subTest(tail=invalid[-12:]), self.assertRaises(LedgerError):
                parse_log(invalid)

    def test_research_and_runtime_cannot_claim_permanent_freshness(self):
        for kind in ('research', 'runtime'):
            with self.subTest(kind=kind), self.assertRaises(LedgerError):
                self.plan(entry=dict(self.entry, kind=kind))
        valid = dict(self.entry, kind='research', recheck_before_action=True)
        self.assertEqual(self.plan(entry=valid)['status'], 'ready')

    def test_rejects_secret_identity_future_dates_and_unknown_fields(self):
        bad_cases = [dict(self.entry, summary='联系 ' + 'person' + '@' + 'example.com'),
                     dict(self.entry, summary='pass' + 'word: ' + 'example-only-value'),
                     dict(self.entry, recorded_at='2999-01-01T00:00:00+00:00'),
                     dict(self.entry, balance=0),
                     dict(self.entry, source={'kind': 'assistant_report', 'reference': 'x',
                                              'observed_at': '2999-01-01'})]
        for entry in bad_cases:
            with self.subTest(fields=list(entry)), self.assertRaises(LedgerError):
                self.plan(entry=entry)

    def test_result_note_does_not_mutate_business_state(self):
        plan = self.plan(entry=dict(self.entry, kind='result', status='resolved'))
        self.assertEqual(set(plan['expected']), {'schema_version', 'version', 'entries'})
        self.assertNotIn('balance', plan['expected']['entries'][0])

    def test_needs_and_decisions_cannot_be_assistant_inferences(self):
        for kind in ('need', 'decision'):
            entry = copy.deepcopy(self.entry)
            entry['kind'] = kind
            entry['source']['kind'] = 'assistant_report'
            with self.assertRaises(LedgerError):
                self.plan(entry=entry)

    def test_latest_topics_use_actual_time_across_timezones(self):
        first = dict(self.entry, recorded_at='2026-09-27T22:00:00+08:00')
        plan = self.plan(entry=first)
        newer = dict(self.entry, id='96d26e68-6700-46cc-b13f-a643ef222dba',
                     topic='another-topic', recorded_at='2026-09-27T15:00:00+00:00')
        log = self.plan(encode_log(plan['expected']), newer)['expected']
        self.assertEqual(latest_entries(log)[0]['id'], newer['id'])

    def draft(self):
        return {key: copy.deepcopy(value) for key, value in self.entry.items()
                if key not in {'id', 'recorded_at', 'supersedes'}}

    def test_draft_fills_identity_time_and_latest_topic_parent(self):
        before = self.plan()['expected']
        draft = self.draft()
        plan = prepare_draft(encode_log(before), draft, revision_id='current-revision', tab_id='t.0')
        new = plan['expected']['entries'][-1]
        self.assertNotEqual(new['id'], self.entry['id'])
        self.assertEqual(new['supersedes'], self.entry['id'])
        self.assertEqual(new['summary'], draft['summary'])
        self.assertEqual(before['entries'][0], plan['expected']['entries'][0])
        self.assertEqual(plan['entry'], new)
        self.assertEqual(plan['write_control'], {'requiredRevisionId': 'current-revision'})
        self.assertTrue(confirm_append(plan, encode_log(plan['expected'])))

    def test_draft_rejects_observed_legacy_spellings_and_missing_sources(self):
        invalid = [dict(self.draft(), kind='process'), dict(self.draft(), kind='summary'),
                   dict(self.draft(), status='closed'),
                   dict(self.draft(), source={'kind': 'user_report', 'reference': 'fixture',
                                             'observed_at': '2026-09-27'}),
                   dict(self.draft(), source={'kind': 'user_statement', 'reference': None,
                                             'observed_at': '2026-09-27'})]
        for draft in invalid:
            with self.subTest(draft=draft), self.assertRaises(LedgerError):
                prepare_draft(encode_log(self.empty), draft, revision_id='r', tab_id='t.0')

    def test_draft_does_not_guess_or_repair_invalid_history(self):
        bad = copy.deepcopy(self.plan()['expected'])
        bad['entries'][0]['source']['reference'] = None
        with self.assertRaisesRegex(LedgerError, 'Entry 1.*source'):
            prepare_draft(encode_log(bad), self.draft(), revision_id='r', tab_id='t.0')
        self.assertIsNone(bad['entries'][0]['source']['reference'])

    def test_draft_rejects_caller_supplied_system_fields(self):
        for key, value in [('id', self.entry['id']), ('recorded_at', self.entry['recorded_at']),
                           ('supersedes', None)]:
            with self.subTest(key=key), self.assertRaises(LedgerError):
                prepare_draft(encode_log(self.empty), dict(self.draft(), **{key: value}),
                              revision_id='r', tab_id='t.0')

    def test_draft_rejects_invalid_revision_or_tab(self):
        for revision, tab in [(' ', 't.0'), ('r', ' '), ('r', 1), (None, 't.0')]:
            with self.subTest(revision=revision, tab=tab), self.assertRaises(LedgerError):
                prepare_draft(encode_log(self.empty), self.draft(), revision_id=revision, tab_id=tab)

    def test_prepared_draft_has_stable_retry_id_and_no_automatic_rebase(self):
        plan = prepare_draft(encode_log(self.empty), self.draft(), revision_id='r', tab_id='t.0')
        self.assertEqual(prepare_append(encode_log(plan['expected']), plan['entry'],
                                       revision_id='r2', tab_id='t.0')['status'], 'already_present')
        different = dict(plan['entry'], summary='同一个记录编号的不同内容。')
        with self.assertRaises(ConflictError):
            prepare_append(encode_log(plan['expected']), different, revision_id='r2', tab_id='t.0')

    def test_cli_prepares_private_candidate_without_cloud_claim_or_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            current, draft, output = root / 'body.txt', root / 'draft.json', root / 'plan.json'
            current.write_text(encode_log(self.empty), encoding='utf-8')
            draft.write_text(json.dumps(self.draft()), encoding='utf-8')
            args = ['prepare', '--input', str(current), '--draft', str(draft),
                    '--out', str(output), '--revision', 'rev', '--tab', 't.0',
                    '--document-id', 'fixture-document', '--paragraph-end-index',
                    str(len(encode_log(self.empty)) + 2)]
            save = lambda plan, path: save_candidate(plan, path, private_root=root)
            with patch('scripts.work_context.save_candidate', side_effect=save), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(main(args), 0)
                first = output.read_bytes()
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertFalse(json.loads(stdout.getvalue())['cloud_saved'])
                self.assertEqual(main(args), 1)
                self.assertEqual(output.read_bytes(), first)
            plan = json.loads(first)
            self.assertEqual(plan['document_id'], 'fixture-document')
            current.write_text(encode_log(plan['expected']), encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(main(['verify', '--plan', str(output), '--input', str(current)]), 0)
                self.assertFalse(json.loads(stdout.getvalue())['cloud_saved'])
            plan['expected']['entries'][0]['summary'] = '不同的读回内容'
            current.write_text(encode_log(plan['expected']), encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['verify', '--plan', str(output), '--input', str(current)]), 1)

    def test_cli_preserves_raw_paragraph_boundaries_and_hides_private_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'body.txt'
            for data in (encode_log(self.empty) + '\r\n', 'UNIQUE_PRIVATE_CONTENT'):
                path.write_bytes(data.encode())
                with contextlib.redirect_stdout(io.StringIO()) as stdout:
                    self.assertEqual(main(['validate', '--input', str(path)]), 1)
                    self.assertNotIn('UNIQUE_PRIVATE_CONTENT', stdout.getvalue())

    def test_cli_rejects_output_outside_private_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current, draft, output = root / 'body.txt', root / 'draft.json', root / 'plan.json'
            current.write_text(encode_log(self.empty), encoding='utf-8')
            draft.write_text(json.dumps(self.draft()), encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['prepare', '--input', str(current), '--draft', str(draft),
                    '--out', str(output), '--revision', 'rev', '--tab', 't.0',
                    '--document-id', 'fixture-document', '--paragraph-end-index',
                    str(len(encode_log(self.empty)) + 2)]), 1)
            self.assertFalse(output.exists())

    def test_native_range_write_preserves_json_and_uses_utf16_indices(self):
        old = self.plan(entry=dict(self.entry, summary='中文与表情 🧭'))['expected']
        text = encode_log(old) + '\n\n'
        end = len(text.rstrip('\n').encode('utf-16-le')) // 2 + 2
        plan = prepare_draft(text, self.draft(), revision_id='native-revision', tab_id='t.0',
                             paragraph_end_index=end)
        delete, insert = plan['requests']
        self.assertEqual(delete['deleteContentRange']['range'],
                         {'startIndex': 1, 'endIndex': end - 1, 'tabId': 't.0'})
        self.assertEqual(insert['insertText']['location'], {'index': 1, 'tabId': 't.0'})
        self.assertEqual(plan['write_control'], {'requiredRevisionId': 'native-revision'})
        self.assertTrue(confirm_append(plan, insert['insertText']['text'] + '\n\n'))
        self.assertEqual(plan['expected']['entries'][0], old['entries'][0])

    def test_native_range_write_rejects_stale_or_invalid_bounds(self):
        text = encode_log(self.empty)
        for end in (True, 1, len(text) + 1, len(text) + 3, str(len(text) + 2)):
            with self.subTest(end=end), self.assertRaises(LedgerError):
                prepare_draft(text, self.draft(), revision_id='r', tab_id='t.0',
                              paragraph_end_index=end)

    def test_noop_cloud_response_cannot_be_mistaken_for_saved_content(self):
        text = encode_log(self.empty)
        plan = prepare_draft(text, self.draft(), revision_id='r', tab_id='t.0',
                             paragraph_end_index=len(text) + 2)
        self.assertFalse(confirm_append(plan, text))


if __name__ == '__main__':
    unittest.main()
