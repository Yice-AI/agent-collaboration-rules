import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.runtime_manifest import ManifestError, validate_runtime


ROOT = Path(__file__).resolve().parents[1]


def runtime_fixture():
    return {
        'schema_version': 1,
        'release': {
            'repository_url': 'https://github.com/example/rules',
            'commit': 'a' * 40,
            'version': '1.0.0',
            'bundle_sha256': 'b' * 64,
            'fallback_document_id': 'virtualFallback001',
        },
        'resources': {
            'baseline': {'type': 'file', 'file_id': 'virtualBaseline001', 'sha256': 'c' * 64},
            'ledger_head': {'type': 'document', 'file_id': 'virtualHead001'},
            'ledger_folder': {'type': 'folder', 'file_id': 'virtualLedger001'},
            'ledger_pending_folder': {'type': 'folder', 'file_id': 'virtualPending001'},
            'work_log': {'type': 'document', 'file_id': 'virtualWorklog001',
                         'parent_folder_id': 'virtualParent001'},
            'preferences': {'type': 'document', 'file_id': 'virtualPreferences001'},
            'project_context': {'type': 'document', 'file_id': 'virtualContext001'},
            'holdings_sheet': {'type': 'spreadsheet', 'spreadsheet_id': 'virtualSheet001'},
        },
    }


class RuntimeManifestTests(unittest.TestCase):
    def test_accepts_standalone_and_index_and_preserves_test_mode(self):
        value = runtime_fixture()
        value['test_mode'] = True
        self.assertEqual(validate_runtime(value), value)
        self.assertEqual(validate_runtime({'unrelated_index_section': {}, 'agent_runtime': value}), value)

    def test_requires_all_release_fields_and_resources(self):
        for section in ('release', 'resources'):
            for field in runtime_fixture()[section]:
                with self.subTest(section=section, field=field):
                    value = runtime_fixture()
                    del value[section][field]
                    with self.assertRaises(ManifestError):
                        validate_runtime(value)

    def test_requires_baseline_hash_worklog_parent_and_correct_resource_ids(self):
        for resource, field in [('baseline', 'sha256'), ('work_log', 'parent_folder_id'),
                                ('holdings_sheet', 'spreadsheet_id'), ('ledger_head', 'file_id')]:
            with self.subTest(resource=resource, field=field):
                value = runtime_fixture()
                del value['resources'][resource][field]
                with self.assertRaises(ManifestError):
                    validate_runtime(value)

    def test_rejects_resource_type_confusion(self):
        for name in runtime_fixture()['resources']:
            with self.subTest(resource=name):
                value = runtime_fixture()
                value['resources'][name]['type'] = 'unknown'
                with self.assertRaises(ManifestError):
                    validate_runtime(value)

    def test_rejects_wrong_types_and_unknown_release_or_resource_names(self):
        values = []
        for version in (True, 1.0, '1', 2):
            value = runtime_fixture()
            value['schema_version'] = version
            values.append(value)
        value = runtime_fixture()
        value['release']['extra'] = 'unexpected'
        values.append(value)
        value = runtime_fixture()
        value['resources']['unknown_resource'] = {}
        values.append(value)
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(ManifestError):
                    validate_runtime(value)

    def test_rejects_malformed_pins_ids_and_trailing_newlines(self):
        for field, wrong in [('commit', 'a' * 39), ('commit', 'a' * 40 + '\n'),
                             ('bundle_sha256', 'b' * 63), ('bundle_sha256', 'b' * 64 + '\n'),
                             ('repository_url', 'https://github.com.evil.invalid/example/rules'),
                             ('repository_url', 'https://github.com/example/rules?extra=1'),
                             ('version', '1.0.0\n'), ('fallback_document_id', 'too-short'),
                             ('fallback_document_id', 'virtualFallback001\n')]:
            value = runtime_fixture()
            value['release'][field] = wrong
            with self.subTest(field=field, wrong=wrong):
                with self.assertRaises(ManifestError):
                    validate_runtime(value)

    def test_cli_is_local_and_redacts_private_values_on_success_and_error(self):
        with tempfile.TemporaryDirectory() as name:
            private = Path(name) / 'private-input-marker.json'
            command = [sys.executable, '-B', str(ROOT / 'scripts/runtime_manifest.py'),
                       'validate', '--input', str(private)]
            for payload in (None, '{"private-marker":"sensitive-input",}',
                            '{"agent_runtime":null}',
                            '{"schema_version":1,"schema_version":2}'):
                if payload is not None:
                    private.write_text(payload, encoding='utf-8')
                result = subprocess.run(command, text=True, capture_output=True)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn('Traceback', result.stdout + result.stderr)
                self.assertNotIn(str(private), result.stdout + result.stderr)
                self.assertNotIn('sensitive-input', result.stdout + result.stderr)
            private.write_text(json.dumps(runtime_fixture()), encoding='utf-8')
            result = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['cloud_verified'])
            self.assertNotIn('virtual', result.stdout)
            self.assertNotIn('github.com', result.stdout)

    def test_unknown_schema_vocabulary_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            schema = Path(name) / 'schema.json'
            schema.write_text(json.dumps({'type': 'object', 'unknownRule': True}), encoding='utf-8')
            with self.assertRaises(ManifestError):
                validate_runtime(runtime_fixture(), schema_path=schema)


if __name__ == '__main__':
    unittest.main()
