"""Build bounded Sheets requests and verify full-sheet snapshots; never writes cloud data."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import re
from pathlib import Path

if __package__:
    from scripts.confirmed_ledger import LedgerError, decode_json, save_candidate
else:
    from confirmed_ledger import LedgerError, decode_json, save_candidate

CELL_FIELDS = ('userEnteredValue', 'note', 'dataValidation', 'userEnteredFormat')
RANGE_KEYS = {'sheetId', 'startRowIndex', 'endRowIndex', 'startColumnIndex', 'endColumnIndex'}
MAX_CELLS = 1_000_000
MAX_BYTES = 20_000_000
MAX_CHANGES = 256


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LedgerError(message)


def _canonical(value) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                          allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, OverflowError):
        raise LedgerError('Invalid JSON value') from None


def _integer(value, minimum: int = 0) -> bool:
    return type(value) is int and value >= minimum


def _value(value, *, formula: bool = True, blank: bool = True):
    if value is None and blank:
        return None
    _require(isinstance(value, dict) and len(value) == 1, 'Expected one typed input value')
    key, data = next(iter(value.items()))
    if key in {'stringValue', 'formulaValue'}:
        _require(type(data) is str, 'Expected string input')
        _require(key != 'formulaValue' or formula, 'Formula writes are forbidden')
        _require(blank or bool(data), 'Clearing input is forbidden')
    elif key == 'numberValue':
        _require(type(data) in (int, float), 'Expected finite number input')
        try:
            _require(math.isfinite(data) and abs(data) <= 2**53, 'Unsafe number input')
        except OverflowError:
            raise LedgerError('Unsafe number input') from None
        data = int(data) if data == int(data) else data
    elif key == 'boolValue':
        _require(type(data) is bool, 'Expected boolean input')
    else:
        raise LedgerError('Unsupported input value type')
    return {key: data}


def _read_fields(mask) -> None:
    """Require whole CellData fields, not a similarly named or partial subfield."""
    if isinstance(mask, list) and all(type(item) is str for item in mask):
        mask = ','.join(mask)
    _require(type(mask) is str and bool(mask), 'Missing read field mask')
    tokens = re.findall(r'[A-Za-z_][A-Za-z_0-9/]*|[(),]', mask)
    _require(''.join(tokens) == re.sub(r'\s+', '', mask), 'Unsupported read field mask')
    leaves, position = set(), 0

    def parse(prefix=()):
        nonlocal position
        while position < len(tokens):
            name = tokens[position]
            _require(name not in '(),', 'Invalid read field mask')
            position += 1
            path = prefix + tuple(name.split('/'))
            if position < len(tokens) and tokens[position] == '(':
                position += 1
                parse(path)
                _require(position < len(tokens) and tokens[position] == ')', 'Unclosed field mask')
                position += 1
            else:
                leaves.add(path)
            if position == len(tokens) or tokens[position] == ')':
                return
            _require(tokens[position] == ',', 'Invalid field separator')
            position += 1
            _require(position < len(tokens) and tokens[position] != ')', 'Empty field')

    parse()
    _require(position == len(tokens), 'Unexpected field suffix')
    for field in CELL_FIELDS:
        _require((field,) in leaves or ('sheets', 'data', 'rowData', 'values', field) in leaves,
                 'Read does not include all complete protected fields')


def _grid(metadata: dict, sheet_id: int, area: dict) -> tuple[int, int]:
    _require(isinstance(metadata, dict), 'Invalid sheet metadata')
    props = metadata.get('properties', {})
    _require(isinstance(props, dict) and _integer(props.get('sheetId')) and props.get('sheetId') == sheet_id,
             'Sheet identity mismatch')
    _require(type(props.get('title')) is str and bool(props['title']), 'Missing sheet title')
    _require(props.get('sheetType', 'GRID') == 'GRID', 'Only grid sheets are supported')
    grid = props.get('gridProperties', {})
    _require(isinstance(grid, dict), 'Missing grid properties')
    rows, columns = grid.get('rowCount'), grid.get('columnCount')
    _require(_integer(rows, 1) and _integer(columns, 1) and rows * columns <= MAX_CELLS,
             'Unsupported grid size')
    _require(isinstance(area, dict) and set(area) == RANGE_KEYS
             and all(_integer(v) for v in area.values()), 'Read range must have explicit bounds')
    _require(area == {'sheetId': sheet_id, 'startRowIndex': 0, 'endRowIndex': rows,
                      'startColumnIndex': 0, 'endColumnIndex': columns},
             'Read must cover the complete target grid')
    return rows, columns


def _cell(cell: dict) -> dict:
    _require(isinstance(cell, dict), 'Invalid CellData')
    result = {}
    for field in CELL_FIELDS:
        if field not in cell:
            continue
        value = cell[field]
        if field == 'userEnteredValue':
            result[field] = _value(value) if value else None
            _require(result[field] is not None, 'Ambiguous empty input object')
        elif field == 'note':
            _require(type(value) is str, 'Invalid note')
            if value:
                result[field] = value
        else:
            _require(isinstance(value, dict), 'Invalid cell metadata')
            if value:
                result[field] = copy.deepcopy(value)
    return result


def capture_snapshot(capture: dict) -> dict:
    _require(isinstance(capture, dict) and set(capture) == {
        'spreadsheet_id', 'sheet_id', 'read_range', 'read_fields', 'response'},
        'Unexpected capture fields')
    spreadsheet_id, sheet_id = capture['spreadsheet_id'], capture['sheet_id']
    _require(type(spreadsheet_id) is str and bool(spreadsheet_id.strip())
             and _integer(sheet_id), 'Invalid target identity')
    _read_fields(capture['read_fields'])
    native = capture['response']
    _require(isinstance(native, dict) and native.get('spreadsheetId') == spreadsheet_id,
             'Spreadsheet identity mismatch')
    sheets = native.get('sheets')
    _require(isinstance(sheets, list) and all(isinstance(s, dict) for s in sheets),
             'Missing native sheet data')
    _require(all(isinstance(s.get('properties'), dict) for s in sheets), 'Missing sheet properties')
    targets = [s for s in sheets if s.get('properties', {}).get('sheetId') == sheet_id]
    _require(len(targets) == 1, 'Target sheet must be unique')
    sheet = targets[0]
    metadata = copy.deepcopy({k: v for k, v in sheet.items() if k != 'data'})
    rows, columns = _grid(metadata, sheet_id, capture['read_range'])
    blocks = sheet.get('data')
    _require(isinstance(blocks, list) and len(blocks) == 1 and isinstance(blocks[0], dict),
             'Expected one complete grid data block')
    data = blocks[0]
    _require(type(data.get('startRow', 0)) is int and data.get('startRow', 0) == 0
             and type(data.get('startColumn', 0)) is int and data.get('startColumn', 0) == 0,
             'Grid data starts outside requested origin')
    row_data = data.get('rowData', [])
    _require(isinstance(row_data, list) and len(row_data) <= rows, 'Invalid native rows')
    cells = {}
    for r, row in enumerate(row_data):
        _require(isinstance(row, dict), 'Invalid native row')
        values = row.get('values', [])
        _require(isinstance(values, list) and len(values) <= columns, 'Invalid native columns')
        for c, cell in enumerate(values):
            value = _cell(cell)
            if value:
                cells[f'{r},{c}'] = value
    snapshot = {'schema_version': 1, 'spreadsheet_id': spreadsheet_id, 'sheet_id': sheet_id,
                'read_range': copy.deepcopy(capture['read_range']), 'read_fields': list(CELL_FIELDS),
                'sheet_metadata': metadata, 'cells': cells}
    _validate_snapshot(snapshot)
    return snapshot


def _validate_snapshot(snapshot: dict) -> None:
    _require(isinstance(snapshot, dict) and set(snapshot) == {
        'schema_version', 'spreadsheet_id', 'sheet_id', 'read_range', 'read_fields',
        'sheet_metadata', 'cells'}, 'Invalid snapshot schema')
    _require(type(snapshot['schema_version']) is int and snapshot['schema_version'] == 1
             and type(snapshot['spreadsheet_id']) is str and bool(snapshot['spreadsheet_id'].strip())
             and _integer(snapshot['sheet_id']) and snapshot['read_fields'] == list(CELL_FIELDS),
             'Invalid snapshot identity or fields')
    rows, columns = _grid(snapshot['sheet_metadata'], snapshot['sheet_id'], snapshot['read_range'])
    _require(isinstance(snapshot['cells'], dict), 'Invalid snapshot cells')
    for key, cell in snapshot['cells'].items():
        _require(type(key) is str and re.fullmatch(r'(0|[1-9][0-9]*),(0|[1-9][0-9]*)', key)
                 is not None, 'Invalid cell coordinate')
        row, column = map(int, key.split(','))
        _require(row < rows and column < columns and isinstance(cell, dict)
                 and bool(cell) and set(cell) <= set(CELL_FIELDS), 'Invalid snapshot cell')
        _require(_cell(cell) == cell, 'Noncanonical snapshot cell')
    _require(len(_canonical(snapshot)) <= MAX_BYTES, 'Snapshot exceeds supported size')


def prepare_update(snapshot: dict, scope: dict, changes: list) -> dict:
    _validate_snapshot(snapshot)
    rows, columns = _grid(snapshot['sheet_metadata'], snapshot['sheet_id'], snapshot['read_range'])
    _require(isinstance(scope, dict) and set(scope) == {'account_column', 'account_value'},
             'Invalid account scope')
    account_column = scope['account_column']
    _require(_integer(account_column) and account_column < columns, 'Invalid account column')
    account = _value(scope['account_value'], formula=False, blank=False)
    _require(set(account) == {'stringValue'}, 'Account identity must be text')
    _require(isinstance(changes, list) and 1 <= len(changes) <= MAX_CHANGES,
             'Expected a bounded nonempty change list')
    seen, normalized, requests = set(), [], []
    for change in changes:
        _require(isinstance(change, dict) and set(change) == {'row', 'column', 'old_value', 'new_value'},
                 'Invalid change fields')
        row, column = change['row'], change['column']
        _require(_integer(row) and row < rows and _integer(column) and column < columns,
                 'Change is outside grid')
        _require(column != account_column, 'Account identity is immutable')
        coordinate = f'{row},{column}'
        _require(coordinate not in seen, 'Duplicate change coordinate')
        seen.add(coordinate)
        _require(snapshot['cells'].get(f'{row},{account_column}', {}).get('userEnteredValue') == account,
                 'Change is outside selected account')
        current = snapshot['cells'].get(coordinate, {}).get('userEnteredValue')
        _require(not current or 'formulaValue' not in current, 'Formula targets are protected')
        old, new = _value(change['old_value']), _value(change['new_value'], formula=False, blank=False)
        _require(old == current, 'Old input value changed')
        normalized.append({'row': row, 'column': column, 'old_value': old, 'new_value': new})
        if old != new:
            requests.append({'updateCells': {
                'range': {'sheetId': snapshot['sheet_id'], 'startRowIndex': row, 'endRowIndex': row + 1,
                          'startColumnIndex': column, 'endColumnIndex': column + 1},
                'rows': [{'values': [{'userEnteredValue': new}]}], 'fields': 'userEnteredValue'}})
    return {'schema_version': 1, 'status': 'ready' if requests else 'already_present',
            'spreadsheet_id': snapshot['spreadsheet_id'], 'sheet_id': snapshot['sheet_id'],
            'before_sha256': hashlib.sha256(_canonical(snapshot)).hexdigest(),
            'scope': {'account_column': account_column, 'account_value': account},
            'changes': normalized, 'requests': requests}


def validate_plan(plan: dict, before: dict) -> None:
    _require(isinstance(plan, dict) and 'scope' in plan and 'changes' in plan, 'Invalid plan')
    expected = prepare_update(before, plan['scope'], plan['changes'])
    _require(_canonical(plan) == _canonical(expected), 'Plan differs from generated bounded requests')


def check_preflight(plan: dict, before: dict, current: dict) -> None:
    validate_plan(plan, before)
    _validate_snapshot(current)
    _require(_canonical(current) == _canonical(before), 'Full sheet changed before submission')


def verify_update(plan: dict, before: dict, after: dict) -> dict:
    validate_plan(plan, before)
    _validate_snapshot(after)
    expected = copy.deepcopy(before)
    for change in plan['changes']:
        cell = expected['cells'].setdefault(f"{change['row']},{change['column']}", {})
        cell['userEnteredValue'] = copy.deepcopy(change['new_value'])
    _require(_canonical(after) == _canonical(expected), 'Readback differs from approved full-sheet state')
    rows, columns = _grid(before['sheet_metadata'], before['sheet_id'], before['read_range'])
    return {'status': 'verified', 'checked_cells': rows * columns,
            'changed_cells': len(plan['requests']), 'unexpected_changes': 0, 'cloud_write_performed': False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='持仓写入范围保护；仅本地校验与请求生成')
    commands = parser.add_subparsers(dest='command', required=True)
    snap = commands.add_parser('snapshot')
    snap.add_argument('--input', type=Path, required=True)
    snap.add_argument('--out', type=Path, required=True)
    prepare = commands.add_parser('prepare')
    for flag in ('before', 'scope', 'changes', 'out'):
        prepare.add_argument('--' + flag, type=Path, required=True)
    for name in ('check', 'preflight', 'verify'):
        sub = commands.add_parser(name)
        sub.add_argument('--before', type=Path, required=True)
        sub.add_argument('--plan', type=Path, required=True)
        if name != 'check':
            sub.add_argument('--' + ('current' if name == 'preflight' else 'after'), type=Path, required=True)
    args = parser.parse_args(argv)

    def read(path):
        raw = path.read_bytes()
        _require(len(raw) <= MAX_BYTES, 'Input exceeds supported size')
        return decode_json(raw)

    try:
        if args.command == 'snapshot':
            snapshot = capture_snapshot(read(args.input))
            save_candidate(snapshot, args.out)
            result = {'status': 'local_snapshot_ready', 'populated_cells': len(snapshot['cells'])}
        elif args.command == 'prepare':
            plan = prepare_update(read(args.before), read(args.scope), read(args.changes))
            save_candidate(plan, args.out)
            result = {'status': plan['status'], 'changed_cells': len(plan['requests'])}
        else:
            plan, before = read(args.plan), read(args.before)
            if args.command == 'preflight':
                check_preflight(plan, before, read(args.current))
            elif args.command == 'verify':
                result = verify_update(plan, before, read(args.after))
            else:
                validate_plan(plan, before)
            if args.command != 'verify':
                result = {'status': 'local_check_passed', 'phase': args.command}
        print(json.dumps({**result, 'cloud_write_performed': False}))
        return 0
    except (LedgerError, OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        print('写入范围校验失败；停止表格写入。核对完整读取、账户、旧值、请求边界与全表差异；未自动提交。')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
