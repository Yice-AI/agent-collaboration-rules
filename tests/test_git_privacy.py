import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from privacy_check import scan


class GitPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        (self.root / '.gitignore').write_text('/_private/\n/.serena/\n')

    def git(self, *args):
        subprocess.run(['git', '-C', str(self.root), *args], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_ignored_original_does_not_enter_scan(self):
        p = self.root / '_private' / 'original.xlsx'
        p.parent.mkdir()
        p.write_bytes(b'local-original')
        self.assertEqual(scan(self.root), [])

    def test_force_staged_original_is_rejected(self):
        p = self.root / '_private' / 'original.xlsx'
        p.parent.mkdir()
        p.write_bytes(b'local-original')
        self.git('add', '-f', str(p))
        self.assertEqual(scan(self.root, staged=True)[0]['type'], 'raw_or_sensitive_file')

    def test_index_is_checked_even_when_working_file_is_clean(self):
        p = self.root / 'record.json'
        key = 'pass' + 'word'
        p.write_text(json.dumps({key: 'synthetic-only'}))
        self.git('add', str(p))
        p.write_text('{}')
        self.assertEqual(scan(self.root), [])
        self.assertTrue(any(f['type'] == 'sensitive_assignment'
                            for f in scan(self.root, staged=True)))

    def test_symlink_is_rejected_without_reading_target(self):
        p = self.root / 'reference.md'
        p.symlink_to('missing-target')
        self.git('add', str(p))
        self.assertEqual(scan(self.root, staged=True)[0]['type'], 'symlink_not_allowed')

    def test_force_staged_developer_cache_is_rejected(self):
        p = self.root / '.serena' / 'cache.pkl'
        p.parent.mkdir()
        p.write_bytes(b'cache')
        self.git('add', '-f', str(p))
        self.assertEqual(scan(self.root, staged=True)[0]['type'], 'development_cache_not_allowed')

    def test_staged_scan_requires_repository(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                scan(Path(td), staged=True)

    def test_invalid_staged_json_is_rejected(self):
        p = self.root / 'invalid.json'
        p.write_text('{')
        self.git('add', str(p))
        self.assertEqual(scan(self.root, staged=True)[0]['type'], 'invalid_json')

    def test_duplicate_json_key_cannot_hide_identity_value(self):
        p = self.root / 'duplicate.json'
        p.write_text('{"姓名":"示例名字","姓名":"[高敏字段不入库]"}')
        self.git('add', str(p))
        self.assertIn('invalid_json', {f['type'] for f in scan(self.root, staged=True)})

    def test_binary_staged_as_text_is_rejected(self):
        p = self.root / 'hidden.md'
        p.write_bytes(b'\xff\xfe')
        self.git('add', str(p))
        self.assertEqual(scan(self.root, staged=True)[0]['type'], 'unexpected_binary')

    def test_decoded_json_credentials_are_rejected(self):
        for key, value in [('pin', 123456), ('密'+'码', 'SYNTHETIC_ONLY'),
                           ('pass'+'word', 'SYNTHETIC_ONLY')]:
            with self.subTest(key=key):
                p = self.root / 'record.json'
                encoded_key = ''.join('\\u%04x' % ord(c) for c in key)
                text = json.dumps({key: value}, ensure_ascii=False).replace(key, encoded_key)
                p.write_text(text)
                self.git('add', str(p))
                kinds = {f['type'] for f in scan(self.root, staged=True)}
                self.assertIn('unminimized_credential_field', kinds)

    def test_uppercase_json_and_decoded_string_values_are_checked(self):
        p = self.root / 'note.JSON'
        key = '注册姓名'
        p.write_text(json.dumps({key: 'SYNTHETIC_ONLY'}, ensure_ascii=True))
        self.git('add', str(p))
        self.assertIn('unminimized_identity_field', {f['type'] for f in scan(self.root, staged=True)})
        value = 'synthetic'+'@'+'example.invalid'
        encoded = ''.join('\\u%04x' % ord(c) for c in value)
        p.write_text(json.dumps({'note': value}).replace(value, encoded))
        self.git('add', str(p))
        self.assertIn('unredacted_email', {f['type'] for f in scan(self.root, staged=True)})

    def test_empty_credential_values_and_identity_placeholder_are_allowed(self):
        p = self.root / 'record.json'
        p.write_text(json.dumps({'pin': None, 'pass'+'word': '',
                                 '注册姓名': '[高敏字段不入库]'}, ensure_ascii=True))
        self.git('add', str(p))
        self.assertEqual(scan(self.root, staged=True), [])

    def test_chinese_identity_fields_are_blocked_in_json_and_csv(self):
        for suffix, content in [('.json', json.dumps({'姓名': '示例名字',
                                                     '出生日期': '1990年1月1日',
                                                     '详细住址': '示例街1号'}, ensure_ascii=False)),
                                ('.csv', '姓名,出生日期,详细住址\n示例名字,1990年1月1日,示例街1号\n')]:
            with self.subTest(suffix=suffix):
                p = self.root / ('record' + suffix)
                p.write_text(content)
                self.git('add', str(p))
                self.assertIn('unminimized_identity_field',
                              {f['type'] for f in scan(self.root, staged=True)})
                self.git('reset', '-q', '--', str(p))
                p.unlink()

    def test_csv_identity_placeholder_is_allowed_and_malformed_row_rejected(self):
        p = self.root / 'record.csv'
        p.write_text('姓名,登录名\n[高敏字段不入库],[高敏字段不入库]\n')
        self.git('add', str(p))
        self.assertEqual(scan(self.root, staged=True), [])
        p.write_text('姓名,登录名\nexample\n')
        self.git('add', str(p))
        self.assertIn('invalid_csv_row', {f['type'] for f in scan(self.root, staged=True)})


if __name__ == '__main__':
    unittest.main()
