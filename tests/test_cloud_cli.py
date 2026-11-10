import contextlib
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from scripts.cloud_ledger import append_manifest, main, prepare_head
from scripts.confirmed_ledger import LedgerError


class CloudCliTests(unittest.TestCase):
    def setUp(self):
        self.base = b'{"accounts":[{"id":"virtual","balance":100}]}'
        sha = hashlib.sha256(self.base).hexdigest()
        self.manifest = {'schema_version': 1, 'baseline_sha256': sha,
                         'head': 'baseline:' + sha, 'events': []}
        self.event = {'schema_version': 1, 'event_id': str(uuid.uuid4()),
                      'parent': 'baseline:' + sha, 'baseline_sha256': sha,
                      'observed_at': '2026-01-01', 'recorded_at': '2026-01-01T10:00:00+08:00',
                      'source': {'kind': 'user_confirmed', 'statement': '虚拟余额已确认。',
                                 'thread_id': None, 'message_id': None},
                      'changes': [{'collection': 'accounts', 'record_id': 'virtual',
                                   'field': 'balance', 'before': 100, 'after': 80}]}
        self.text = json.dumps(self.event, ensure_ascii=False, separators=(',', ':'))
        self.head_text = json.dumps(self.manifest, ensure_ascii=False, separators=(',', ':'))

    def plan(self, **changes):
        args = dict(head_document_id='virtualHead001', revision_id='revision-a',
                    tab_id='t.0', paragraph_end_index=len(self.head_text) + 2)
        args.update(changes)
        return prepare_head(self.head_text + '\n', self.event, 'virtualEvent001', self.text, **args)

    def test_plan_guards_same_revision_and_preserves_original_head(self):
        before = json.dumps(self.manifest, sort_keys=True)
        plan = self.plan()
        self.assertFalse(plan['cloud_saved'])
        self.assertEqual(plan['write_control'], {'requiredRevisionId': 'revision-a'})
        self.assertEqual(plan['document_id'], 'virtualHead001')
        inserted = plan['requests'][1]['insertText']['text']
        self.assertEqual(json.loads(inserted), plan['expected'])
        self.assertEqual(plan['expected']['events'][0]['sha256'], hashlib.sha256(self.text.encode()).hexdigest())
        self.assertEqual(json.dumps(self.manifest, sort_keys=True), before)

    def test_bad_native_bounds_and_missing_revision_are_rejected(self):
        for changes in ({'revision_id': ''}, {'tab_id': ''}, {'paragraph_end_index': 1},
                        {'head_document_id': 'virtualEvent001'}, {'paragraph_end_index': True}):
            with self.subTest(changes=changes), self.assertRaises(LedgerError):
                self.plan(**changes)
        with self.assertRaises(LedgerError):
            prepare_head(self.head_text.replace(',', ',\n', 1), self.event, 'virtualEvent001', self.text,
                         head_document_id='virtualHead001', revision_id='r', tab_id='t.0',
                         paragraph_end_index=len(self.head_text) + 3)

    def write_inputs(self, root):
        manifest = append_manifest(self.manifest, self.event, 'virtualEvent001', self.text)
        (root / 'base.json').write_bytes(self.base)
        for name, value in [('head.json', manifest), ('documents.json', {'virtualEvent001': self.text}),
                            ('listing.json', ['virtualHead001', 'virtualEvent001'])]:
            (root / name).write_text(json.dumps(value, ensure_ascii=False))
        return ['verify', '--base', str(root / 'base.json'), '--manifest', str(root / 'head.json'),
                '--documents', str(root / 'documents.json'), '--listed-ids', str(root / 'listing.json'),
                '--head-document-id', 'virtualHead001', '--output', str(root / '_private' / 'result.json')]

    def test_verify_cli_outputs_candidate_without_cloud_or_permission_claim(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            args = self.write_inputs(root)
            out = io.StringIO()
            with patch('scripts.confirmed_ledger.ROOT', root), contextlib.redirect_stdout(out):
                self.assertEqual(main(args), 0)
            receipt = json.loads(out.getvalue())
            self.assertFalse(receipt['cloud_saved'])
            self.assertFalse(receipt['permissions_verified'])
            result = json.loads((root / '_private' / 'result.json').read_text())
            self.assertEqual(result['state']['accounts'][0]['balance'], 80)
            self.assertEqual((root / 'base.json').read_bytes(), self.base)

    def test_unknown_missing_or_duplicate_listing_never_emits_candidate(self):
        for listing in (['virtualHead001'], ['virtualHead001', 'virtualEvent001', 'unknownEvent001'],
                        ['virtualHead001', 'virtualEvent001', 'virtualEvent001']):
            with self.subTest(listing=listing), tempfile.TemporaryDirectory() as folder:
                root = Path(folder).resolve()
                args = self.write_inputs(root)
                (root / 'listing.json').write_text(json.dumps(listing))
                with patch('scripts.confirmed_ledger.ROOT', root), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(args), 1)
                self.assertFalse((root / '_private' / 'result.json').exists())

    def test_scripts_can_be_called_directly(self):
        root = Path(__file__).resolve().parents[1]
        for script in ('work_context.py', 'cloud_ledger.py', 'confirmed_ledger.py'):
            result = subprocess.run([sys.executable, '-B', str(root / 'scripts' / script), '--help'],
                                    cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_confirmed_ledger_cli_redacts_known_private_input_failures(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            events = directory / 'events'
            events.mkdir()
            private = directory / 'private-baseline-marker.json'
            command = [sys.executable, '-B', str(root / 'scripts/confirmed_ledger.py'),
                       '--base', str(private), '--events', str(events),
                       '--output', str(directory / 'candidate.json')]
            for raw in (None, b'{"sensitive-input-marker":', b'{"accounts":null}'):
                if raw is not None:
                    private.write_bytes(raw)
                result = subprocess.run(command, cwd=root, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                output = result.stdout + result.stderr
                self.assertNotIn('Traceback', output)
                self.assertNotIn(str(private), output)
                self.assertNotIn('sensitive-input-marker', output)


if __name__ == '__main__':
    unittest.main()
