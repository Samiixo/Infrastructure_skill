#!/usr/bin/env python3
"""Secret scanner for a documentation or config directory.

Scans markdown/config files for values that look like credentials. Every
matched value is MASKED in this tool's own output (first 6 chars + length).
Skipped directories are always named in the output with counts: a silent
skip is how a scan lies.

Exit codes: 0 = no findings, 1 = at least one FAIL finding, 2 = bad path.

All human-facing strings are Russian; the console writer replaces
unencodable characters, so a cp1251 console is safe.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = 1

SKIP_DIRS = ["node_modules", ".git", "vendor", "dist", "build", "__pycache__",
             ".venv", "venv", ".mypy_cache", ".pytest_cache", ".idea", ".next"]

SCAN_EXT = [".md", ".markdown", ".txt", ".env", ".yml", ".yaml", ".json",
            ".ini", ".cfg", ".conf", ".toml", ".properties", ".sh", ".py",
            ".js", ".ts", ".example", ".sample", ".template"]
SCAN_BASENAME = [".env", "env", ".env.local", ".env.example", "dockerfile"]

MAX_BYTES = 512 * 1024

# (rule name, regex). Order matters: the most specific shape wins first.
RULES = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("stripe_secret", re.compile(r"sk_live_[A-Za-z0-9]{8,}")),
    ("stripe_test_key", re.compile(r"sk_test_[A-Za-z0-9]{8,}")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{8,}")),
    ("private_key_block",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")),
    ("connection_string_password",
     re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s:/@]{3,}@")),
]

GENERIC_RE = re.compile(
    r"(?i)\b([a-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|apikey|"
    r"access[_-]?token|auth[_-]?token|token|credential)[a-z0-9_.-]*)"
    r"\s*[:=]\s*"
    r"([^\s\"'`,\)\]]{4,})"
)

# A generic hit is downgraded to INFO when the value is obviously a
# placeholder or a cross-reference rather than a live credential.
PLACEHOLDER_RE = re.compile(
    r"^(x{3,}|\*{3,}|\.{3,}|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|"
    r"your[_-]?\w*|my[_-]?\w*|example|placeholder|redacted|changeme|"
    r"todo|none|null|nil|true|false|\d+|dummy|test|abc123|secret|password|"
    r"see[_-]?\w+|env|dotenv|value|\[.*\]|%\w+%)$",
    re.IGNORECASE)

RULE_DOC = {
    "aws_access_key_id": "формат AWS access key id (AKIA + 16)",
    "stripe_secret": "формат боевого секретного ключа Stripe",
    "stripe_test_key": "формат тестового ключа Stripe (для документации он "
                       "все равно недопустим)",
    "github_token": "формат персонального токена доступа GitHub",
    "slack_token": "формат токена Slack",
    "private_key_block": "заголовок приватного ключа PEM",
    "jwt": "трехсегментный токен формата JWT",
    "connection_string_password":
        "строка подключения с паролем прямо в URI",
    "generic_assignment": "имя + (:|=) + значение длиной от 4 символов",
}


def mask(value):
    if value is None:
        return ""
    if len(value) <= 6:
        return "*** (len %d)" % len(value)
    return "%s... (len %d)" % (value[:6], len(value))


def should_scan(path):
    name = path.name.lower()
    if name in SCAN_BASENAME:
        return True
    suffix = path.suffix.lower()
    if suffix in SCAN_EXT:
        return True
    if not suffix and name.startswith(".env"):
        return True
    return False


def read_lines(path):
    data = path.read_bytes()[:MAX_BYTES]
    for enc in ("utf-8", "cp1251", "latin-1"):
        try:
            return data.decode(enc).splitlines(), True
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace").splitlines(), False


def finding(rule, severity, path, line_no, line, value):
    return {
        "rule": rule,
        "rule_doc": RULE_DOC.get(rule, rule),
        "severity": severity,
        "file": path,
        "line": line_no,
        "masked": mask(value),
        "context": " ".join(line.split())[:160],
        "excerpt": mask_value_in_line(" ".join(line.split())[:160], value),
    }


def mask_value_in_line(text, value):
    if not value:
        return text
    return text.replace(value, "***REDACTED***")


def scan_file(path, root):
    rel = _rel(path, root)
    findings = []
    try:
        lines, _ = read_lines(path)
    except OSError as exc:
        return [{"rule": "unreadable", "rule_doc": str(exc), "severity": "INFO",
                 "file": rel, "line": 0, "masked": "", "context": "",
                 "excerpt": ""}]
    for idx, line in enumerate(lines, 1):
        for rule, rx in RULES:
            m = rx.search(line)
            if m:
                findings.append(finding(rule, "FAIL", rel, idx, line,
                                       m.group(0)))
                break
        else:
            m = GENERIC_RE.search(line)
            if m:
                name, value = m.group(1), m.group(2)
                sev = "INFO" if PLACEHOLDER_RE.match(value) else "FAIL"
                findings.append(finding("generic_assignment", sev, rel, idx,
                                       line, value))
    return findings


def _rel(path, root):
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve()))
    except ValueError:
        return str(path)


def scan(root):
    root = Path(root)
    findings = []
    skipped = []
    scanned = 0
    unreadable = 0
    if root.is_file():
        # Single-file mode: used by doctor.py on one document.
        scanned = 1
        findings.extend(scan_file(root, root.parent))
        unreadable = len([f for f in findings if f["rule"] == "unreadable"])
        findings.sort(key=lambda f: (f["line"], f["rule"]))
        n_fail = len([f for f in findings if f["severity"] == "FAIL"])
        n_info = len([f for f in findings if f["severity"] == "INFO"])
        return {
            "tool": "guard_secrets",
            "schema": SCHEMA,
            "target": str(root),
            "ok": n_fail == 0,
            "exit_code": 1 if n_fail else 0,
            "counts": {"files_scanned": scanned, "fail": n_fail, "info": n_info,
                       "skipped_dirs": 0},
            "skipped": [],
            "unreadable_files": unreadable,
            "findings": findings,
            "rules": sorted(RULE_DOC.items()),
        }
    for dirpath, dirnames, filenames in os.walk(root):
        pruned = []
        for d in sorted(dirnames):
            if d in SKIP_DIRS:
                full = Path(dirpath) / d
                count = sum(len(f) for _, _, f in os.walk(full))
                skipped.append({"dir": _rel(full, root), "entries": count,
                                "reason": "исключенная по имени директория"})
            else:
                pruned.append(d)
        dirnames[:] = pruned
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if not should_scan(p):
                continue
            scanned += 1
            res = scan_file(p, root)
            if any(f["rule"] == "unreadable" for f in res):
                unreadable += 1
            findings.extend(res)
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    n_fail = len([f for f in findings if f["severity"] == "FAIL"])
    n_info = len([f for f in findings if f["severity"] == "INFO"])
    return {
        "tool": "guard_secrets",
        "schema": SCHEMA,
        "target": str(root),
        "ok": n_fail == 0,
        "exit_code": 1 if n_fail else 0,
        "counts": {
            "files_scanned": scanned,
            "fail": n_fail,
            "info": n_info,
            "skipped_dirs": len(skipped),
        },
        "skipped": skipped,
        "unreadable_files": unreadable,
        "findings": findings,
        "rules": sorted(RULE_DOC.items()),
    }


class Out(object):
    def __init__(self, stream):
        self.stream = stream

    def write(self, text):
        try:
            self.stream.write(text)
        except UnicodeEncodeError:
            enc = getattr(self.stream, "encoding", None) or "ascii"
            self.stream.write(text.encode(enc, "replace").decode(enc, "replace"))

    def line(self, text=""):
        self.write(text + "\n")


def report(result, out):
    out.line("secret guard - %s" % result["target"])
    out.line("проверено файлов: %d; все значения в этом выводе замаскированы"
             % result["counts"]["files_scanned"])
    out.line("")
    if result["skipped"]:
        out.line("ПРОПУЩЕНО (не проверено, не признано чистым):")
        for s in result["skipped"]:
            out.line("  - %s (записей: %d) - %s"
                     % (s["dir"], s["entries"], s["reason"]))
        out.line("")
    else:
        out.line("ПРОПУЩЕНО: нет")
        out.line("")
    if not result["findings"]:
        out.line("[PASS] в проверенных файлах не найдено значений, похожих "
                 "на секреты")
        if result["unreadable_files"]:
            out.line("[WARN] не удалось прочитать файлов: %d; чистыми они НЕ "
                     "считаются" % result["unreadable_files"])
    for f in result["findings"]:
        tag = "FAIL" if f["severity"] == "FAIL" else "INFO"
        out.line("[%s] %s %s:%d" % (tag, f["rule"], f["file"], f["line"]))
        out.line("        правило: %s" % f["rule_doc"])
        out.line("        значение: %s" % (f["masked"] or "(это не значение)"))
        out.line("        строка:  %s" % f["excerpt"])
    if result["findings"]:
        out.line("")
        out.line("INFO означает, что строка лишь НАЗЫВАЕТ шаблон в тексте "
                 "(плейсхолдер, имя переменной, пример). Оцените сами: строка "
                 "выведена именно для этого. FAIL означает значение, "
                 "похожее на боевое.")
    out.line("")
    out.line("итог: файлов %d, провалов %d, info %d, пропущенных директорий %d"
             % (result["counts"]["files_scanned"],
                result["counts"]["fail"], result["counts"]["info"],
                result["counts"]["skipped_dirs"]))
    if result["counts"]["fail"]:
        out.line("утёкший секрет считается скомпрометированным с момента "
                 "коммита: сначала смените его, потом уберите из файла.")
    return result["exit_code"]


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="guard_secrets.py",
        description="Ищет в директории значения, похожие на секреты, в "
                    "markdown- и конфигурационных файлах. Значения всегда "
                    "выводятся замаскированными. Исключенные директории всегда "
                    "перечисляются в выводе.",
    )
    ap.add_argument("path", nargs="?", help="директория для проверки")
    ap.add_argument("--json", action="store_true",
                    help="машиночитаемый вывод")
    ap.add_argument("--list-rules", action="store_true",
                    help="напечатать каталог правил и выйти с кодом 0")
    args = ap.parse_args(argv)

    out = Out(sys.stdout)
    if args.list_rules:
        for name, doc in sorted(RULE_DOC.items()):
            out.line("%-28s %s" % (name, doc))
        return 0

    if not args.path:
        msg = "путь не указан (используйте --list-rules, чтобы напечатать каталог правил)"
        if args.json:
            out.line(json.dumps({"tool": "guard_secrets", "schema": SCHEMA,
                                 "ok": False, "error": msg, "findings": [],
                                 "skipped": []}, ensure_ascii=True))
        else:
            out.line("[FAIL] " + msg)
        return 2

    p = Path(args.path)
    if not p.exists() or not p.is_dir():
        msg = "не директория: %s" % args.path
        if args.json:
            out.line(json.dumps({"tool": "guard_secrets", "schema": SCHEMA,
                                 "ok": False, "error": msg, "findings": [],
                                 "skipped": []}, ensure_ascii=True))
        else:
            out.line("[FAIL] target: " + msg)
        return 2

    result = scan(p)
    if not args.json:
        report(result, out)
    else:
        out.line(json.dumps(result, ensure_ascii=True, indent=2))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
