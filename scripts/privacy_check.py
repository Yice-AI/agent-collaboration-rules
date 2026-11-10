"""Offline, conservative privacy gate. Reports filenames/categories, never matched secrets."""
from __future__ import annotations
import argparse, csv, io, json, os, re, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES={'.xlsx','.xls','.pdf','.jpg','.jpeg','.png','.heic','.pem','.key','.p12','.pfx','.zip'}
PATTERNS={
 'unredacted_email':re.compile(r'(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}'),
 'mainland_mobile':re.compile(r'(?<![A-Za-z0-9])(?:\+?86[ -]*)?1[3-9]\d(?:[ -]*\d){8}(?![A-Za-z0-9])'),
 'identity_number':re.compile(r'(?<![A-Za-z0-9])\d{17}[0-9Xx](?![A-Za-z0-9])'),
 'private_key':re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
 'provider_token':re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9_-]{30,})\b'),
 'sensitive_assignment':re.compile(r'(?i)["\']?(?:password|private_key|mnemonic|otp_secret|cvv|recovery_code)["\']?\s*[:=]\s*["\'][^"\']{3,}["\']'),
}
# These rules apply to published files only. Private work-log sources may contain
# authorized Drive references; do not apply this gate inside walk_json().
PUBLIC_PATTERNS={
 'private_resource_url':re.compile(r'(?i)(?:docs\.google\.com/(?:document|spreadsheets|presentation)/d/|drive\.google\.com/(?:file/d/|drive/folders/))[A-Za-z0-9_-]{20,}'),
 'absolute_user_path':re.compile(r'(?:/(?:Users|home)/[^\s/"\']+/|[A-Za-z]:\\Users\\[^\\\s"\']+\\)'),
 'private_chat_url':re.compile(r'(?i)chatgpt\.com/c/[0-9a-f]{8}-[0-9a-f-]{27,}'),
}
PRIVATE_RESOURCE_KEYS={'file_id','document_id','spreadsheet_id','folder_id','fallback_document_id',
                       'head_document_id','drive_entry_file_id','work_context_document_id'}
SENSITIVE_KEYS={'注册姓名','注册邮箱','注册手机号','注册地址/地区','密码存放索引','存放位置索引','信息/号码'}
IDENTITY_KEYS={
 'legalname','fullname','realname','dateofbirth','birthdate',
 'streetaddress','addressline1','addressline2','mailingaddress','residentialaddress',
 'passportnumber','nationalid','bankaccountnumber',
 '真实姓名','姓名','出生日期','出生年月','出生年月日','生日',
 '详细地址','详细住址','家庭住址','居住地址','通讯地址','收件地址','开户姓名',
 '身份证号','身份证号码','护照号','护照号码','证件号码','银行卡号',
 'loginname','username','accountusername','登录名','用户名','用户名称',
}
CREDENTIAL_KEYS={
 'password','loginpassword','fundpassword','paymentpassword','pin','cvv','cvc',
 'privatekey','mnemonic','seedphrase','otpsecret','totpsecret',
 'recoverycode','backupcode','apikey','accesstoken','refreshtoken','clientsecret',
 '密码','登录密码','资金密码','支付密码','交易密码','私钥','助记词','恢复码',
 '备用码','验证码','验证码密钥','安全码','api密钥','2fa密钥',
}
EMPTY_SENSITIVE_VALUES=(None,'','[高敏字段不入库]','[凭据不入库]')

def field_category(key):
    if not isinstance(key, str):
        return None
    normalized = key.casefold().replace('_', '').replace('-', '').replace(' ', '')
    if key in SENSITIVE_KEYS or normalized in IDENTITY_KEYS:
        return 'unminimized_identity_field'
    if normalized in CREDENTIAL_KEYS:
        return 'unminimized_credential_field'
    return None

def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result

def walk_json(x):
    if isinstance(x, dict):
        for key, value in x.items():
            category = field_category(key)
            if category and value not in EMPTY_SENSITIVE_VALUES:
                yield category
            yield from walk_json(value)
    elif isinstance(x, list):
        for value in x:
            yield from walk_json(value)
    elif isinstance(x, str):
        for kind, pattern in PATTERNS.items():
            if pattern.search(x):
                yield kind

def walk_public_json(x):
    """Reject private pointers in public JSON, including escaped string values."""
    if isinstance(x, dict):
        for key, value in x.items():
            if (key in PRIVATE_RESOURCE_KEYS and isinstance(value, str)
                    and re.fullmatch(r'[A-Za-z0-9_-]{20,200}', value)
                    and not value.startswith(('REPLACE_', 'EXAMPLE_', 'VIRTUAL_'))):
                yield 'private_resource_id'
            yield from walk_public_json(value)
    elif isinstance(x, list):
        for value in x:
            yield from walk_public_json(value)
    elif isinstance(x, str):
        for kind, pattern in PUBLIC_PATTERNS.items():
            if pattern.search(x):
                yield kind

def scan(root: Path = ROOT, *, staged: bool = False):
    """Check eligible working files, or the exact bytes in Git's index."""
    root = root.resolve()
    findings = []
    is_repo = (root / '.git').exists()
    if staged and not is_repo:
        raise ValueError('Staged scan requires a Git repository')

    def git(*args):
        return subprocess.run(
            ['git', '-C', str(root), *args], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout

    if is_repo:
        if Path(os.fsdecode(git('rev-parse', '--show-toplevel')).strip()).resolve() != root:
            raise ValueError('Unexpected Git repository root')
        if staged:
            entries = []
            for row in git('ls-files', '--stage', '-z').split(b'\0'):
                if not row:
                    continue
                meta, name = row.split(b'\t', 1)
                mode, oid, stage = meta.split()
                rel = Path(os.fsdecode(name))
                if stage != b'0':
                    findings.append({'path': str(rel), 'type': 'unmerged_index'})
                    continue
                entries.append((rel, mode, oid.decode('ascii')))
        else:
            names = git('ls-files', '--cached', '--others', '--exclude-standard', '-z')
            entries = [(Path(os.fsdecode(n)), None, None) for n in sorted(set(names.split(b'\0'))) if n]
    else:
        entries = [(p.relative_to(root), None, None) for p in sorted(root.rglob('*'))]

    for rel, mode, oid in entries:
        if not staged and any(part in {'.git', '__pycache__'} for part in rel.parts):
            continue
        p = root / rel
        if rel.is_absolute() or '..' in rel.parts:
            findings.append({'path': str(rel), 'type': 'invalid_path'})
            continue
        if mode == b'120000' or (not staged and p.is_symlink()):
            findings.append({'path': str(rel), 'type': 'symlink_not_allowed'})
            continue
        if mode is not None and mode not in {b'100644', b'100755'}:
            findings.append({'path': str(rel), 'type': 'unsupported_index_mode'})
            continue
        if not staged and not p.is_file():
            continue
        if '.serena' in rel.parts or '__pycache__' in rel.parts or p.suffix in {'.pyc', '.pkl'}:
            findings.append({'path': str(rel), 'type': 'development_cache_not_allowed'})
            continue
        if (p.suffix.lower() in FORBIDDEN_SUFFIXES or p.name.startswith('.env')
                or rel.parts[0] in {'_private', 'private', 'secrets'}
                or str(rel).startswith('archive/originals/')):
            findings.append({'path': str(rel), 'type': 'raw_or_sensitive_file'})
            continue
        raw = git('cat-file', 'blob', oid) if staged else p.read_bytes()
        try:
            text = raw.decode('utf-8-sig')
        except UnicodeDecodeError:
            findings.append({'path': str(rel), 'type': 'unexpected_binary'})
            continue
        for kind, pattern in {**PATTERNS, **PUBLIC_PATTERNS}.items():
            if pattern.search(text):
                findings.append({'path': str(rel), 'type': kind})
        if p.suffix.lower() == '.json':
            try:
                parsed = json.loads(text, object_pairs_hook=unique_json_object)
                for kind in set(walk_json(parsed)) | set(walk_public_json(parsed)):
                    findings.append({'path': str(rel), 'type': kind})
            except (json.JSONDecodeError, ValueError):
                findings.append({'path': str(rel), 'type': 'invalid_json'})
        elif p.suffix.lower() == '.csv':
            try:
                reader = csv.reader(io.StringIO(text, newline=''), strict=True)
                header = next(reader, None)
                if not header or len(header) != len(set(header)):
                    findings.append({'path': str(rel), 'type': 'invalid_csv_header'})
                    continue
                sensitive = [(i, field_category(key)) for i, key in enumerate(header)]
                found = set()
                for row in reader:
                    if len(row) != len(header):
                        found.add('invalid_csv_row')
                        break
                    for i, category in sensitive:
                        if category and row[i] not in EMPTY_SENSITIVE_VALUES:
                            found.add(category)
                findings.extend({'path': str(rel), 'type': kind} for kind in sorted(found))
            except csv.Error:
                findings.append({'path': str(rel), 'type': 'invalid_csv'})
    return findings
if __name__=='__main__':
 parser=argparse.ArgumentParser(description='检查工作文件或 Git 暂存的实际内容')
 parser.add_argument('--staged',action='store_true',help='检查即将提交的文件原文')
 args=parser.parse_args()
 findings=scan(staged=args.staged)
 print(json.dumps({'scan':'local_rule_check_not_a_security_guarantee','scope':'git_index' if args.staged else 'eligible_working_files','passed':not findings,'findings':findings},ensure_ascii=False,indent=2))
 sys.exit(1 if findings else 0)
