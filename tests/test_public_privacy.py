import json
import tempfile
import unittest
from pathlib import Path

from scripts.privacy_check import PUBLIC_PATTERNS, scan, walk_json, walk_public_json


class PublicPrivacyTests(unittest.TestCase):
    def test_private_resource_links_and_decoded_ids_are_not_public(self):
        sample_id = 'sample' + 'x' * 30
        link = 'https://' + 'docs.google.com/spreadsheets/d/' + sample_id
        self.assertIn('private_resource_url', set(walk_public_json(link)))
        self.assertIn('private_resource_id', set(walk_public_json({'spreadsheet_id': sample_id})))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'sample.json').write_text(json.dumps({'document_id': sample_id}))
            self.assertIn('private_resource_id', {x['type'] for x in scan(root)})

    def test_private_log_sources_remain_legal(self):
        sample_id = 'sample' + 'x' * 30
        link = 'https://' + 'docs.google.com/document/d/' + sample_id
        self.assertEqual(list(walk_json({'source': link})), [])

    def test_examples_and_empty_resource_placeholders_are_allowed(self):
        for value in ('', 'REPLACE_DOCUMENT_ID_HERE', 'EXAMPLE_DOCUMENT_ID_00001', '<private-id>'):
            self.assertEqual(list(walk_public_json({'document_id': value})), [])

    def test_user_directory_paths_are_rejected_without_names_in_source(self):
        paths = ['/' + 'Users' + '/sample/private.json', '/' + 'home' + '/sample/private.json',
                 'C:' + '\\' + 'Users' + '\\sample\\private.json']
        for value in paths:
            with self.subTest(value=value):
                self.assertTrue(PUBLIC_PATTERNS['absolute_user_path'].search(value))


if __name__ == '__main__':
    unittest.main()
