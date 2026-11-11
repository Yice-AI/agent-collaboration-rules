"""Write-scope regressions using entirely fictional spreadsheet fixtures."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.confirmed_ledger import LedgerError
from scripts.holdings_guard import (capture_snapshot, check_preflight, prepare_update,
                                    validate_plan, verify_update)


class HoldingsGuardTests(unittest.TestCase):
    SHEET_ID = 37
    ROWS = 6
    COLUMNS = 7

    @staticmethod
    def text(value):
        return {'stringValue': value}

    @staticmethod
    def number(value):
        return {'numberValue': value}

    def setUp(self):
        def row(values):
            return {'values': [({'userEnteredValue': value} if value is not None else {})
                               for value in values]}

        rows = [
            row([self.text(label) for label in
                 ('account', 'asset', 'quantity', 'cost', 'cash', 'status', 'calculation')]),
            row([self.text('virtual-alpha'), self.text('DEMO-FUND'), self.number(3),
                 self.number(67), None, self.text('recorded'),
                 {'formulaValue': '=C2+D2'}]),
            row([self.text('virtual-alpha'), self.text('CASH'), None, None,
                 self.number(145), self.text('confirmed'), None]),
            row([self.text('virtual-beta'), self.text('OTHER-FUND'), self.number(8),
                 self.number(113), None, self.text('untouched'), None]),
            row([self.text('TOTAL'), None, None, None,
                 {'formulaValue': '=SUM(E2:E4)'}, None, None]),
        ]
        rows[1]['values'][3]['userEnteredFormat'] = {
            'numberFormat': {'type': 'NUMBER', 'pattern': '0.00'}}
        rows[1]['values'][5]['dataValidation'] = {
            'condition': {'type': 'ONE_OF_LIST', 'values': [
                {'userEnteredValue': 'recorded'}, {'userEnteredValue': 'confirmed'}]},
            'strict': True, 'showCustomUi': True}
        rows[3]['values'][3]['note'] = 'Fictional unrelated value must survive.'
        self.capture = {
            'spreadsheet_id': 'virtualSpreadsheetGuard001',
            'sheet_id': self.SHEET_ID,
            'read_range': {'sheetId': self.SHEET_ID, 'startRowIndex': 0,
                           'endRowIndex': self.ROWS, 'startColumnIndex': 0,
                           'endColumnIndex': self.COLUMNS},
            'read_fields': ('spreadsheetId,sheets(properties(sheetId,title,gridProperties),'
                            'data(startRow,startColumn,rowData(values('
                            'userEnteredValue,note,dataValidation,userEnteredFormat))))'),
            'response': {
                'spreadsheetId': 'virtualSpreadsheetGuard001',
                'sheets': [{
                    'properties': {'sheetId': self.SHEET_ID, 'title': 'Fictional holdings',
                                   'gridProperties': {'rowCount': self.ROWS,
                                                      'columnCount': self.COLUMNS,
                                                      'frozenRowCount': 1}},
                    'data': [{'startRow': 0, 'startColumn': 0, 'rowData': rows}],
                }],
            },
        }
        self.scope = {'account_column': 0, 'account_value': self.text('virtual-alpha')}
        self.changes = [
            {'row': 1, 'column': 2, 'old_value': self.number(3),
             'new_value': self.number(4)},
            {'row': 1, 'column': 3, 'old_value': self.number(67),
             'new_value': self.number(89)},
        ]
        self.before = capture_snapshot(self.capture)

    def cell(self, capture, row, column):
        return capture['response']['sheets'][0]['data'][0]['rowData'][row]['values'][column]

    def after_capture(self, changes=None):
        result = copy.deepcopy(self.capture)
        for change in self.changes if changes is None else changes:
            self.cell(result, change['row'], change['column'])['userEnteredValue'] = (
                copy.deepcopy(change['new_value']))
        return result

    def plan(self):
        return prepare_update(self.before, self.scope, self.changes)

    def assert_rejected_changes(self, changes):
        with self.assertRaises(LedgerError):
            prepare_update(self.before, self.scope, changes)

    def test_exact_single_cell_requests_and_verified_readback(self):
        original_capture = copy.deepcopy(self.capture)
        original_before = copy.deepcopy(self.before)
        original_changes = copy.deepcopy(self.changes)
        plan = self.plan()
        self.assertEqual(len(plan['requests']), 2)
        for request, change in zip(plan['requests'], self.changes):
            self.assertEqual(set(request), {'updateCells'})
            update = request['updateCells']
            self.assertEqual(set(update), {'range', 'rows', 'fields'})
            self.assertEqual(update['fields'], 'userEnteredValue')
            self.assertEqual(update['range'], {
                'sheetId': self.SHEET_ID,
                'startRowIndex': change['row'], 'endRowIndex': change['row'] + 1,
                'startColumnIndex': change['column'], 'endColumnIndex': change['column'] + 1})
            self.assertEqual(update['rows'], [
                {'values': [{'userEnteredValue': change['new_value']}]}])
        self.assertIsNone(validate_plan(plan, self.before))
        self.assertIsNone(check_preflight(plan, self.before, capture_snapshot(self.capture)))
        receipt = verify_update(plan, self.before, capture_snapshot(self.after_capture()))
        self.assertIsInstance(receipt, dict)
        self.assertEqual(self.capture, original_capture)
        self.assertEqual(self.before, original_before)
        self.assertEqual(self.changes, original_changes)

    def test_already_present_is_an_empty_validated_plan(self):
        unchanged = copy.deepcopy(self.changes)
        for change in unchanged:
            change['new_value'] = copy.deepcopy(change['old_value'])
        plan = prepare_update(self.before, self.scope, unchanged)
        self.assertEqual(plan['status'], 'already_present')
        self.assertEqual(plan['requests'], [])
        self.assertIsNone(validate_plan(plan, self.before))
        self.assertIsNone(check_preflight(plan, self.before, self.before))
        self.assertIsInstance(verify_update(plan, self.before, self.before), dict)

    def test_mixed_no_op_and_change_only_writes_changed_cell(self):
        changes = copy.deepcopy(self.changes)
        changes[0]['new_value'] = copy.deepcopy(changes[0]['old_value'])
        plan = prepare_update(self.before, self.scope, changes)
        self.assertEqual(len(plan['requests']), 1)
        self.assertEqual(plan['requests'][0]['updateCells']['range']['startColumnIndex'], 3)
        self.assertIsInstance(verify_update(
            plan, self.before, capture_snapshot(self.after_capture(changes))), dict)

    def test_blank_target_can_be_filled_and_zero_or_false_are_not_clears(self):
        for value in (self.number(0), {'boolValue': False}, self.text('new value')):
            with self.subTest(value=value):
                changes = [{'row': 1, 'column': 4, 'old_value': None, 'new_value': value}]
                plan = prepare_update(self.before, self.scope, changes)
                self.assertEqual(len(plan['requests']), 1)
                self.assertIsInstance(verify_update(
                    plan, self.before, capture_snapshot(self.after_capture(changes))), dict)

    def test_old_value_is_exact_and_typed(self):
        for value in (None, self.number(9), self.text('3'), {'boolValue': True}, {}):
            with self.subTest(value=value):
                changes = copy.deepcopy(self.changes)
                changes[0]['old_value'] = value
                self.assert_rejected_changes(changes)

    def test_another_accounts_row_and_account_column_are_rejected(self):
        for change in (
            {'row': 3, 'column': 2, 'old_value': self.number(8), 'new_value': self.number(9)},
            {'row': 1, 'column': 0, 'old_value': self.text('virtual-alpha'),
             'new_value': self.text('virtual-gamma')},
            {'row': 0, 'column': 2, 'old_value': self.text('quantity'),
             'new_value': self.text('changed heading')},
            {'row': 5, 'column': 2, 'old_value': None, 'new_value': self.number(9)},
        ):
            with self.subTest(change=change):
                self.assert_rejected_changes([change])

    def test_duplicate_cells_are_rejected_even_with_identical_values(self):
        self.assert_rejected_changes([self.changes[0], copy.deepcopy(self.changes[0])])

    def test_formula_targets_and_formula_new_values_are_rejected(self):
        self.assert_rejected_changes([
            {'row': 1, 'column': 6, 'old_value': {'formulaValue': '=C2+D2'},
             'new_value': self.number(99)}])
        changes = copy.deepcopy(self.changes)
        changes[0]['new_value'] = {'formulaValue': '=SUM(C2:C3)'}
        self.assert_rejected_changes(changes)

    def test_clear_nonfinite_and_malformed_new_values_are_rejected(self):
        values = (None, {}, self.text(''), self.number(float('nan')),
                  self.number(float('inf')), self.number(float('-inf')),
                  self.number(True), {'boolValue': 1}, {'stringValue': 4},
                  {'numberValue': 4, 'stringValue': '4'}, {'errorValue': 'invalid'})
        for value in values:
            with self.subTest(value=value):
                changes = copy.deepcopy(self.changes)
                changes[0]['new_value'] = value
                self.assert_rejected_changes(changes)

    def test_coordinates_are_bounded_nonboolean_integers(self):
        for key, value in (('row', -1), ('row', self.ROWS), ('row', True),
                           ('row', 1.5), ('column', -1), ('column', self.COLUMNS),
                           ('column', True), ('column', '2')):
            with self.subTest(key=key, value=value):
                changes = copy.deepcopy(self.changes)
                changes[0][key] = value
                self.assert_rejected_changes(changes)

    def test_scope_and_change_schema_do_not_accept_extra_keys(self):
        scope = {**self.scope, 'allow_other_accounts': True}
        with self.assertRaises(LedgerError):
            prepare_update(self.before, scope, self.changes)
        changes = copy.deepcopy(self.changes)
        changes[0]['clear_rest'] = True
        self.assert_rejected_changes(changes)

    def test_capture_requires_exact_schema_and_complete_read_range(self):
        variants = []
        extra = copy.deepcopy(self.capture)
        extra['trust_me'] = True
        variants.append(extra)
        for key in ('startRowIndex', 'endRowIndex', 'startColumnIndex', 'endColumnIndex'):
            incomplete = copy.deepcopy(self.capture)
            del incomplete['read_range'][key]
            variants.append(incomplete)
        for key, value in (('startRowIndex', 1), ('endRowIndex', self.ROWS - 1),
                           ('startColumnIndex', 1), ('endColumnIndex', self.COLUMNS - 1),
                           ('sheetId', self.SHEET_ID + 1)):
            partial = copy.deepcopy(self.capture)
            partial['read_range'][key] = value
            variants.append(partial)
        for capture in variants:
            with self.subTest(read_range=capture['read_range']):
                with self.assertRaises(LedgerError):
                    capture_snapshot(capture)

    def test_capture_requires_each_protected_cell_field(self):
        for field in ('userEnteredValue', 'note', 'dataValidation', 'userEnteredFormat'):
            with self.subTest(field=field):
                capture = copy.deepcopy(self.capture)
                capture['read_fields'] = capture['read_fields'].replace(field, 'effectiveValue')
                with self.assertRaises(LedgerError):
                    capture_snapshot(capture)

    def test_capture_rejects_partial_format_and_validation_field_masks(self):
        for complete, partial in (
            ('userEnteredFormat', 'userEnteredFormat(numberFormat)'),
            ('dataValidation', 'dataValidation(condition)'),
        ):
            with self.subTest(partial=partial):
                capture = copy.deepcopy(self.capture)
                capture['read_fields'] = capture['read_fields'].replace(complete, partial)
                with self.assertRaises(LedgerError):
                    capture_snapshot(capture)

    def test_existing_empty_string_is_readable_and_can_be_replaced(self):
        capture = copy.deepcopy(self.capture)
        self.cell(capture, 1, 4)['userEnteredValue'] = self.text('')
        self.cell(capture, 3, 4)['userEnteredValue'] = self.text('')
        before = capture_snapshot(capture)
        changes = [{'row': 1, 'column': 4, 'old_value': self.text(''),
                    'new_value': self.number(17)}]
        plan = prepare_update(before, self.scope, changes)
        self.assertIsNone(check_preflight(plan, before, capture_snapshot(capture)))
        after = copy.deepcopy(capture)
        self.cell(after, 1, 4)['userEnteredValue'] = self.number(17)
        self.assertIsInstance(verify_update(plan, before, capture_snapshot(after)), dict)
        clearing = [{'row': 1, 'column': 2, 'old_value': self.number(3),
                     'new_value': self.text('')}]
        with self.assertRaises(LedgerError):
            prepare_update(before, self.scope, clearing)

    def test_capture_rejects_mismatched_spreadsheet_or_sheet(self):
        for key in ('spreadsheet', 'sheet'):
            with self.subTest(key=key):
                capture = copy.deepcopy(self.capture)
                if key == 'spreadsheet':
                    capture['response']['spreadsheetId'] = 'virtualOtherSpreadsheet002'
                else:
                    capture['response']['sheets'][0]['properties']['sheetId'] += 1
                with self.assertRaises(LedgerError):
                    capture_snapshot(capture)

    def test_validate_plan_rejects_dangerous_request_mutations(self):
        plan = self.plan()
        mutations = ('open_row', 'open_column', 'start_mode', 'large_range', 'wildcard',
                     'extra_field', 'wrong_sheet', 'wrong_value', 'empty_rows',
                     'empty_values', 'empty_cell', 'extra_request', 'extra_cells')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                altered = copy.deepcopy(plan)
                update = altered['requests'][0]['updateCells']
                if mutation == 'open_row':
                    del update['range']['endRowIndex']
                elif mutation == 'open_column':
                    del update['range']['endColumnIndex']
                elif mutation == 'start_mode':
                    del update['range']
                    update['start'] = {'sheetId': self.SHEET_ID, 'rowIndex': 1,
                                       'columnIndex': 2}
                elif mutation == 'large_range':
                    update['range']['endRowIndex'] = self.ROWS
                elif mutation == 'wildcard':
                    update['fields'] = '*'
                elif mutation == 'extra_field':
                    update['fields'] = 'userEnteredValue,note'
                elif mutation == 'wrong_sheet':
                    update['range']['sheetId'] += 1
                elif mutation == 'wrong_value':
                    update['rows'][0]['values'][0]['userEnteredValue'] = self.number(999)
                elif mutation == 'empty_rows':
                    update['rows'] = []
                elif mutation == 'empty_values':
                    update['rows'][0]['values'] = []
                elif mutation == 'empty_cell':
                    update['rows'][0]['values'][0] = {}
                elif mutation == 'extra_request':
                    altered['requests'].append(copy.deepcopy(altered['requests'][0]))
                else:
                    update['rows'][0]['values'].append({'userEnteredValue': self.number(999)})
                with self.assertRaises(LedgerError):
                    validate_plan(altered, self.before)

    def test_preflight_rejects_target_or_unrelated_concurrent_changes(self):
        plan = self.plan()
        for row, column, field, value in (
            (1, 2, 'userEnteredValue', self.number(6)),
            (3, 3, 'userEnteredValue', self.number(117)),
            (3, 3, 'note', 'Changed by another writer'),
            (1, 3, 'userEnteredFormat', {'numberFormat': {'type': 'TEXT'}}),
            (1, 5, 'dataValidation', {'condition': {'type': 'BOOLEAN'}, 'strict': False}),
        ):
            with self.subTest(row=row, column=column, field=field):
                current = copy.deepcopy(self.capture)
                self.cell(current, row, column)[field] = value
                with self.assertRaises(LedgerError):
                    check_preflight(plan, self.before, capture_snapshot(current))

    def test_verify_rejects_missing_or_wrong_requested_value(self):
        for value in (None, self.number(5), self.text('4')):
            with self.subTest(value=value):
                after = self.after_capture()
                cell = self.cell(after, 1, 2)
                if value is None:
                    del cell['userEnteredValue']
                else:
                    cell['userEnteredValue'] = value
                with self.assertRaises(LedgerError):
                    verify_update(self.plan(), self.before, capture_snapshot(after))

    def test_verify_rejects_nontarget_clear_or_value_change(self):
        for value in (None, self.number(117)):
            with self.subTest(value=value):
                after = self.after_capture()
                if value is None:
                    del self.cell(after, 3, 3)['userEnteredValue']
                else:
                    self.cell(after, 3, 3)['userEnteredValue'] = value
                with self.assertRaises(LedgerError):
                    verify_update(self.plan(), self.before, capture_snapshot(after))

    def test_verify_rejects_note_format_validation_or_formula_damage(self):
        damage = (
            (3, 3, 'note', None),
            (1, 3, 'userEnteredFormat', None),
            (1, 5, 'dataValidation', None),
            (1, 6, 'userEnteredValue', self.number(70)),
            (4, 4, 'userEnteredValue', {'formulaValue': '=0'}),
            (1, 2, 'note', 'Unexpected target-cell note'),
        )
        for row, column, field, value in damage:
            with self.subTest(row=row, column=column, field=field):
                after = self.after_capture()
                cell = self.cell(after, row, column)
                if value is None:
                    del cell[field]
                else:
                    cell[field] = value
                with self.assertRaises(LedgerError):
                    verify_update(self.plan(), self.before, capture_snapshot(after))

    def test_verify_rejects_sheet_metadata_changes(self):
        after = self.after_capture()
        after['response']['sheets'][0]['properties']['title'] = 'Unexpected renamed tab'
        with self.assertRaises(LedgerError):
            verify_update(self.plan(), self.before, capture_snapshot(after))

    def test_verify_rejects_new_data_in_previously_empty_trailing_row(self):
        after = self.after_capture()
        after['response']['sheets'][0]['data'][0]['rowData'].append(
            {'values': [{'userEnteredValue': self.text('unrelated concurrent entry')}]})
        with self.assertRaises(LedgerError):
            verify_update(self.plan(), self.before, capture_snapshot(after))

    def test_cli_end_to_end_is_private_and_rejects_damage_without_value_output(self):
        root = Path(__file__).resolve().parents[1]
        private_root = root / '_private'
        created_private_root = not private_root.exists()
        if created_private_root:
            private_root.mkdir(mode=0o700)
        temporary_path = None

        def assert_public_output(output):
            for marker in ('virtual-alpha', 'virtual-beta', 'DEMO-FUND', 'OTHER-FUND',
                           'virtualSpreadsheetGuard001', 'userEnteredValue',
                           'Fictional unrelated value must survive.', 'Traceback',
                           str(root), str(temporary_path)):
                self.assertNotIn(marker, output)
            try:
                summary = json.loads(output)
            except json.JSONDecodeError:
                return

            def visit(value):
                if isinstance(value, dict):
                    for key, item in value.items():
                        self.assertNotIn(key, {'old_value', 'new_value', 'requests', 'cells'})
                        visit(item)
                elif isinstance(value, list):
                    for item in value:
                        visit(item)
                elif type(value) in (int, float):
                    self.assertNotIn(value, (67, 89, 113, 145))

            visit(summary)

        def run_cli(*args, expected_code=0):
            result = subprocess.run(
                [sys.executable, '-B', str(root / 'scripts' / 'holdings_guard.py'),
                 *[str(arg) for arg in args]],
                cwd=root, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, expected_code, result.stdout + result.stderr)
            assert_public_output(result.stdout + result.stderr)
            if expected_code == 0:
                self.assertIsInstance(json.loads(result.stdout), dict)
            return result

        try:
            with tempfile.TemporaryDirectory(prefix='holdings-guard-cli-',
                                             dir=private_root) as folder:
                temporary_path = Path(folder)

                def write_json(name, value):
                    path = temporary_path / name
                    path.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
                    path.chmod(0o600)
                    return path

                capture_file = write_json('capture-before.json', self.capture)
                scope_file = write_json('scope.json', self.scope)
                changes_file = write_json('changes.json', self.changes)
                original_input = capture_file.read_bytes()
                before_file = temporary_path / 'snapshot-before.json'
                current_file = temporary_path / 'snapshot-current.json'
                after_file = temporary_path / 'snapshot-after.json'
                plan_file = temporary_path / 'plan.json'
                run_cli('snapshot', '--input', capture_file, '--out', before_file)
                self.assertEqual(json.loads(before_file.read_text()), self.before)
                run_cli('prepare', '--before', before_file, '--scope', scope_file,
                        '--changes', changes_file, '--out', plan_file)
                plan = json.loads(plan_file.read_text())
                self.assertEqual(len(plan['requests']), 2)
                run_cli('check', '--before', before_file, '--plan', plan_file)
                run_cli('snapshot', '--input', capture_file, '--out', current_file)
                run_cli('preflight', '--before', before_file, '--plan', plan_file,
                        '--current', current_file)
                after_capture_file = write_json('capture-after.json', self.after_capture())
                run_cli('snapshot', '--input', after_capture_file, '--out', after_file)
                run_cli('verify', '--before', before_file, '--plan', plan_file,
                        '--after', after_file)

                tampered = copy.deepcopy(plan)
                del tampered['requests'][0]['updateCells']['range']['endRowIndex']
                tampered_file = write_json('tampered-plan.json', tampered)
                run_cli('check', '--before', before_file, '--plan', tampered_file,
                        expected_code=1)

                concurrent = copy.deepcopy(self.capture)
                self.cell(concurrent, 3, 3)['note'] = 'Fictional concurrent change'
                concurrent_capture_file = write_json('capture-concurrent.json', concurrent)
                concurrent_file = temporary_path / 'snapshot-concurrent.json'
                run_cli('snapshot', '--input', concurrent_capture_file, '--out', concurrent_file)
                run_cli('preflight', '--before', before_file, '--plan', plan_file,
                        '--current', concurrent_file, expected_code=1)

                damaged = self.after_capture()
                del self.cell(damaged, 3, 3)['userEnteredValue']
                damaged_capture_file = write_json('capture-damaged.json', damaged)
                damaged_file = temporary_path / 'snapshot-damaged.json'
                run_cli('snapshot', '--input', damaged_capture_file, '--out', damaged_file)
                run_cli('verify', '--before', before_file, '--plan', plan_file,
                        '--after', damaged_file, expected_code=1)

                self.assertEqual(capture_file.read_bytes(), original_input)
                self.assertEqual(json.loads(before_file.read_text()), self.before)
                self.assertEqual(json.loads(plan_file.read_text()), plan)
                for path in temporary_path.iterdir():
                    self.assertTrue(path.is_relative_to(private_root))
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(temporary_path.exists())
        finally:
            if created_private_root:
                try:
                    private_root.rmdir()
                except OSError:
                    pass


if __name__ == '__main__':
    unittest.main()
