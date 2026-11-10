import json
from pathlib import Path
import tempfile
import unittest

from scripts.build_bundle import BundleError, build, canonical, digest, verify, write_bundle
from scripts.confirmed_ledger import save_candidate


class BundleTests(unittest.TestCase):
    def test_schema_plural_is_included_by_explicit_allowlist(self):
        (self.root / 'schemas').mkdir()
        (self.root / 'schemas' / 'runtime.json').write_text('{"type":"object"}', encoding='utf-8')
        self.allowlist.write_text('schemas/runtime.json\n', encoding='utf-8')
        raw = self.bundle()
        self.assertEqual(verify(raw, digest(raw))['files'][0]['path'], 'schemas/runtime.json')

    def test_nested_private_directories_remain_usable_by_ledger_writer(self):
        private = self.root / '_private'
        output = private / 'release' / 'bundle.json'
        write_bundle(self.bundle(), output, root=self.root)
        self.assertEqual(private.stat().st_mode & 0o777, 0o700)
        self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)
        candidate = private / 'worklog' / 'candidate.json'
        save_candidate({'virtual': True}, candidate, private_root=private)
        self.assertEqual(json.loads(candidate.read_text()), {'virtual': True})

    def test_existing_publicly_readable_private_directory_is_rejected_unchanged(self):
        private = self.root / '_private'
        private.mkdir(mode=0o755)
        private.chmod(0o755)
        with self.assertRaises(BundleError):
            write_bundle(self.bundle(), private / 'release' / 'bundle.json', root=self.root)
        self.assertEqual(private.stat().st_mode & 0o777, 0o755)
        self.assertFalse((private / 'release').exists())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name).resolve()
        self.root = self.parent / 'source'
        self.root.mkdir()
        (self.root / 'docs').mkdir()
        (self.root / 'README.md').write_text('# 通用入口\n', encoding='utf-8')
        (self.root / 'docs' / 'rules.md').write_text('虚拟规则。\n', encoding='utf-8')
        self.allowlist = self.root / 'bundle-paths.txt'
        self.allowlist.write_text('docs/rules.md\nREADME.md\n', encoding='utf-8')
        self.output = self.parent / 'bundle.json'

    def bundle(self):
        return build(self.root, self.allowlist, '1.0.0')

    def test_reproducible_bytes_independent_of_allowlist_order_and_metadata(self):
        first = self.bundle()
        self.allowlist.write_text('# ordered\nREADME.md\ndocs/rules.md\n', encoding='utf-8')
        self.assertEqual(first, self.bundle())
        result = verify(first, digest(first))
        self.assertEqual(result['version'], '1.0.0')
        self.assertEqual([x['path'] for x in result['files']], ['README.md', 'docs/rules.md'])
        self.assertFalse(first.endswith(b'\n'))

    def test_global_hash_and_individual_hash_are_both_required(self):
        raw = self.bundle()
        with self.assertRaises(BundleError):
            verify(raw, '0' * 64)
        bundle = json.loads(raw)
        bundle['files'][0]['content'] += 'changed'
        bad = canonical(bundle)
        with self.assertRaises(BundleError):
            verify(bad, digest(bad))

    def test_rejects_duplicate_paths_schema_and_noncanonical_transport(self):
        raw = self.bundle()
        bundle = json.loads(raw)
        bundle['files'].append(bundle['files'][0])
        bad = canonical(bundle)
        with self.assertRaises(BundleError):
            verify(bad, digest(bad))
        for bad in (raw + b'\n', raw.replace(b'"schema_version":1', b'"schema_version":true'),
                    raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')):
            with self.assertRaises(BundleError):
                verify(bad, digest(bad))

    def test_rejects_private_reserved_and_traversal_paths(self):
        for path in ('release.json', 'docs/release.json', '_private/note.md', 'docs/private/note.md',
                     'data/state.json', 'tests/test.py', '.git/config', '../README.md',
                     'docs/../README.md', 'docs//rules.md', 'docs/./rules.md', '/README.md',
                     'docs\\rules.md'):
            with self.subTest(path=path):
                self.allowlist.write_text(path)
                with self.assertRaises(BundleError):
                    self.bundle()

    def test_symlink_file_and_directory_are_rejected(self):
        target = self.root / 'docs' / 'rules.md'
        target.unlink()
        target.symlink_to(self.root / 'README.md')
        with self.assertRaises(BundleError):
            self.bundle()
        target.unlink()
        (self.root / 'docs').rmdir()
        (self.root / 'docs').symlink_to(self.parent, target_is_directory=True)
        with self.assertRaises(BundleError):
            self.bundle()

    def test_public_privacy_screen_runs_on_build_and_verify(self):
        secret_link = 'https://' + 'docs.google.com/document/d/' + ('x' * 32)
        path = self.root / 'docs' / 'rules.md'
        for unsafe in (secret_link, '/' + 'Users' + '/fixture/example.txt'):
            with self.subTest(kind=unsafe.split(':')[0]):
                path.write_text(unsafe)
                with self.assertRaises(BundleError):
                    self.bundle()
                raw = canonical({'schema_version': 1, 'version': '1.0.0', 'files': [
                    {'path': 'docs/rules.md', 'content': unsafe, 'sha256': digest(unsafe.encode())}]})
                with self.assertRaises(BundleError):
                    verify(raw, digest(raw))

    def test_writes_are_idempotent_and_cannot_overwrite_different_content(self):
        first = self.bundle()
        write_bundle(first, self.output, root=self.root)
        write_bundle(first, self.output, root=self.root)
        with self.assertRaises(BundleError):
            write_bundle(first + b'changed', self.output, root=self.root)
        self.assertEqual(self.output.read_bytes(), first)

    def test_output_cannot_overwrite_public_inputs_or_follow_symlinks(self):
        raw = self.bundle()
        with self.assertRaises(BundleError):
            write_bundle(raw, self.root / 'docs' / 'bundle.json', root=self.root)
        self.output.symlink_to(self.root / 'README.md')
        with self.assertRaises(BundleError):
            write_bundle(raw, self.output, root=self.root)
        self.assertEqual((self.root / 'README.md').read_text(), '# 通用入口\n')

    def test_json_fixture_rejects_credential_fields_and_duplicate_keys(self):
        (self.root / 'templates').mkdir()
        self.allowlist.write_text('templates/example.json')
        file = self.root / 'templates' / 'example.json'
        for content in ('{"key":1,"key":2}', '{"password":"' + 'fake' + '"}', '{"value":NaN}'):
            file.write_text(content)
            with self.assertRaises(BundleError):
                self.bundle()

    def test_json_private_pointers_are_blocked_but_placeholders_are_allowed(self):
        (self.root / 'templates').mkdir()
        self.allowlist.write_text('templates/example.json')
        file = self.root / 'templates' / 'example.json'
        file.write_text(json.dumps({'document_id': 'v' * 32}))
        with self.assertRaises(BundleError):
            self.bundle()
        file.write_text(json.dumps({'document_id': 'REPLACE_PRIVATE_DOCUMENT_ID'}))
        self.assertEqual(verify(self.bundle(), digest(self.bundle()))['version'], '1.0.0')


if __name__ == '__main__':
    unittest.main()
