import copy
import hashlib
import json
import unittest
import uuid

from scripts.cloud_ledger import (append_manifest, materialize_manifest, receipt_status,
                                  validate_owner_only_metadata)
from scripts.confirmed_ledger import ConflictError, LedgerError


class CloudLedgerTests(unittest.TestCase):
    def setUp(self):
        self.base = {'accounts': [{'id': 'virtual', '当前状态': '申请中'}]}
        self.raw = json.dumps(self.base, ensure_ascii=False).encode()
        self.sha = hashlib.sha256(self.raw).hexdigest()
        self.manifest = {'schema_version': 1, 'baseline_sha256': self.sha,
                         'head': 'baseline:' + self.sha, 'events': []}

    def event(self, *, parent=None, before='申请中', after='获批'):
        return {'schema_version': 1, 'event_id': str(uuid.uuid4()),
                'parent': parent or 'baseline:' + self.sha, 'baseline_sha256': self.sha,
                'observed_at': '2026-09-28', 'recorded_at': '2026-09-28T10:00:00+08:00',
                'source': {'kind': 'user_confirmed', 'statement': '虚拟账户已经获批。',
                           'thread_id': None, 'message_id': None},
                'changes': [{'collection': 'accounts', 'record_id': 'virtual',
                             'field': '当前状态', 'before': before, 'after': after}]}

    @staticmethod
    def text(event):
        return json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

    def test_committed_chain_and_folder_orphan_are_distinct(self):
        first = self.event()
        first_text = self.text(first)
        one = append_manifest(self.manifest, first, 'virtualDoc0001', first_text)
        second = self.event(parent=first['event_id'], before='获批', after='激活')
        second_text = self.text(second)
        two = append_manifest(one, second, 'virtualDoc0002', second_text)
        result = materialize_manifest(self.raw, two,
                                      {'virtualDoc0001': first_text, 'virtualDoc0002': second_text},
                                      listed_document_ids={'virtualHead0001', 'virtualDoc0001',
                                                           'virtualDoc0002', 'orphanDoc0003'},
                                      head_document_id='virtualHead0001')
        self.assertEqual(result['state']['accounts'][0]['当前状态'], '激活')
        self.assertEqual(result['head'], second['event_id'])
        self.assertEqual(result['folder_audit'], 'uncommitted_found')
        self.assertEqual(result['uncommitted_document_ids'], ['orphanDoc0003'])
        self.assertEqual(receipt_status(two, second['event_id'], 'virtualDoc0002',
                                        two['events'][-1]['sha256']), 'listed_unverified')

    def test_lost_receipt_is_pending_until_manifest_contains_exact_event(self):
        event = self.event()
        self.assertEqual(receipt_status(self.manifest, event['event_id'],
                                        'virtualDoc0001', 'a' * 64), 'pending')
        one = append_manifest(self.manifest, event, 'virtualDoc0001', self.text(event))
        self.assertEqual(receipt_status(one, event['event_id'], 'virtualDoc0001',
                                        one['events'][0]['sha256']), 'listed_unverified')
        with self.assertRaises(ConflictError):
            receipt_status(one, event['event_id'], 'virtualDoc0001', 'b' * 64)

    def test_stale_parent_and_same_id_conflict_never_append(self):
        event = self.event()
        one = append_manifest(self.manifest, event, 'virtualDoc0001', self.text(event))
        other = self.event()
        with self.assertRaises(ConflictError):
            append_manifest(one, other, 'virtualDoc0002', self.text(other))
        changed = copy.deepcopy(event)
        changed['parent'] = event['event_id']
        with self.assertRaises(ConflictError):
            append_manifest(one, changed, 'virtualDoc0002', self.text(changed))

    def test_missing_or_altered_event_fails_closed(self):
        event = self.event()
        one = append_manifest(self.manifest, event, 'virtualDoc0001', self.text(event))
        with self.assertRaises(LedgerError):
            materialize_manifest(self.raw, one, {})
        with self.assertRaises(LedgerError):
            materialize_manifest(self.raw, one, {'virtualDoc0001': self.text(event) + ' '})
        with self.assertRaises(LedgerError):
            materialize_manifest(self.raw, one, {'virtualDoc0001': self.text(event)},
                                 listed_document_ids={'virtualHead0001', 'otherDoc00001'},
                                 head_document_id='virtualHead0001')

    def test_full_empty_folder_contains_only_head(self):
        result = materialize_manifest(self.raw, self.manifest, {},
                                      listed_document_ids={'virtualHead0001'},
                                      head_document_id='virtualHead0001')
        self.assertEqual(result['folder_audit'], 'complete')
        self.assertEqual(result['uncommitted_document_ids'], [])
        for listing, head in [({'virtualHead0001'}, None), (set(), 'virtualHead0001'),
                              ({'virtualHead0001'}, 'short')]:
            with self.assertRaises(LedgerError):
                materialize_manifest(self.raw, self.manifest, {},
                                     listed_document_ids=listing, head_document_id=head)

    def test_document_boolean_and_integer_are_not_equivalent(self):
        event = self.event()
        event['changes'] = [{'collection': 'accounts', 'record_id': 'virtual',
                             'field': 'balance', 'before': 1, 'after': 2}]
        altered = copy.deepcopy(event)
        altered['changes'][0]['before'] = True
        with self.assertRaises(LedgerError):
            append_manifest(self.manifest, event, 'virtualDoc0001', self.text(altered))

    def test_manifest_rollback_or_malformed_references_fail(self):
        event = self.event()
        one = append_manifest(self.manifest, event, 'virtualDoc0001', self.text(event))
        tampered = copy.deepcopy(one)
        tampered['head'] = self.manifest['head']
        with self.assertRaises(LedgerError):
            materialize_manifest(self.raw, tampered, {'virtualDoc0001': self.text(event)})
        tampered = copy.deepcopy(one)
        tampered['events'].append(copy.deepcopy(tampered['events'][0]))
        tampered['head'] = event['event_id']
        with self.assertRaises(ConflictError):
            materialize_manifest(self.raw, tampered, {'virtualDoc0001': self.text(event)})

    def test_unlisted_folder_cannot_claim_full_audit(self):
        result = materialize_manifest(self.raw, self.manifest, {})
        self.assertEqual(result['folder_audit'], 'not_performed')
        self.assertIsNone(result['uncommitted_document_ids'])

    def test_owner_only_permission_and_exact_parent_are_required(self):
        metadata = {'shared': False, 'parent_ids': ['privateFolder'],
                    'permissions': [{'type': 'user', 'role': 'owner'}]}
        validate_owner_only_metadata(metadata, 'privateFolder')
        for change in ({'shared': True}, {'parent_ids': ['otherFolder']},
                       {'permissions': None},
                       {'permissions': [{'type': 'user', 'role': 'owner'},
                                        {'type': 'anyone', 'role': 'reader'}]}):
            bad = {**metadata, **change}
            with self.assertRaises(LedgerError):
                validate_owner_only_metadata(bad, 'privateFolder')


if __name__ == '__main__':
    unittest.main()
