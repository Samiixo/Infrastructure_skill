#!/usr/bin/env python3
"""Install the infrastructure protocol into a target project.

Copies references/ and tools/ into place and, when templates/ is present,
materialises the documentation templates. Never clobbers an existing file
without --force; with --force the previous version is backed up to
<name>.bak first.

Exit codes: 0 = installed (or dry run clean), 1 = something was refused or
failed, 2 = bad target / bad usage.

All human-facing strings are Russian; the console writer replaces
unencodable characters, so a cp1251 console is safe.
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

SCHEMA = 1

SKILL_ROOT = Path(__file__).resolve().parent.parent

COPY_DIRS = ["references", "tools"]
TEMPLATE_DIR = "templates"
TEMPLATE_EXT = ".md"

# Doc names the protocol expects; used to report template coverage.
EXPECTED_TEMPLATES = ["README.md", "ARCHITECTURE.md", "API_CONTRACT.md",
                      "SECURITY.md", "ENVIRONMENTS.md", "CONTRIBUTING.md",
                      "DECISIONS.md", "CHECKLIST.md"]

# Docs the protocol requires, mapped to the template file that seeds them.
DOC_TO_TEMPLATE = {
    "README.md": "README.md",
    "ARCHITECTURE.md": "ARCHITECTURE.md",
    "API_CONTRACT.md": "API_CONTRACT.md",
    "SECURITY.md": "SECURITY.md",
    "ENVIRONMENTS.md": "ENVIRONMENTS.md",
    "CONTRIBUTING.md": "CONTRIBUTING.md",
    "DECISIONS.md": "DECISIONS.md",
    "CHECKLIST.md": "CHECKLIST.md",
}


def same_content(a, b):
    try:
        return a.read_bytes() == b.read_bytes()
    except OSError:
        return False


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


def plan(skill_root, target):
    """Build the list of (src, dest, category) operations."""
    ops = []
    missing_sources = []
    for d in COPY_DIRS:
        src_dir = skill_root / d
        if not src_dir.is_dir():
            missing_sources.append(d)
            continue
        for src in sorted(src_dir.rglob("*")):
            if not src.is_file():
                continue
            rel = src.relative_to(src_dir)
            if any(p in SKIP for p in rel.parts):
                continue
            ops.append((src, target / d / rel, d))

    tpl_dir = skill_root / TEMPLATE_DIR
    templates_present = tpl_dir.is_dir() and any(
        p.is_file() and p.suffix.lower() == TEMPLATE_EXT
        for p in sorted(tpl_dir.iterdir()))
    if not templates_present:
        return ops, missing_sources, False, []
    seeded = []
    for src in sorted(tpl_dir.iterdir()):
        if not src.is_file() or src.suffix.lower() != TEMPLATE_EXT:
            continue
        dest = target / src.name
        ops.append((src, dest, "templates"))
        seeded.append(src.name)
    return ops, missing_sources, True, seeded


SKIP = {"__pycache__", ".git", ".pytest_cache"}


def run(skill_root, target, dry_run, force):
    ops, missing_sources, templates_present, seeded = plan(skill_root, target)
    results = []
    refused = 0
    for src, dest, category in ops:
        rec = {"source": str(src), "dest": str(dest), "category": category,
               "action": None, "detail": ""}
        if dest.exists():
            if same_content(src, dest):
                rec["action"] = "unchanged"
            elif force:
                if dry_run:
                    rec["action"] = "would-back-up-and-overwrite"
                    rec["detail"] = str(dest) + ".bak"
                else:
                    bak = dest.with_name(dest.name + ".bak")
                    try:
                        shutil.copy2(str(dest), str(bak))
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(str(src), str(dest))
                        rec["action"] = "overwritten"
                        rec["detail"] = "резервная копия: " + str(bak)
                    except OSError as exc:
                        rec["action"] = "error"
                        rec["detail"] = str(exc)
                        refused += 1
            else:
                rec["action"] = "refused"
                rec["detail"] = ("в цели уже лежит другая версия; повторите с "
                                 "--force, чтобы сохранить ее как <name>.bak "
                                 "и заменить")
                refused += 1
        else:
            if dry_run:
                rec["action"] = "would-create"
            else:
                try:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(src), str(dest))
                    rec["action"] = "created"
                except OSError as exc:
                    rec["action"] = "error"
                    rec["detail"] = str(exc)
                    refused += 1
        results.append(rec)
    return {
        "tool": "install",
        "schema": SCHEMA,
        "target": str(target),
        "skill_root": str(skill_root),
        "dry_run": dry_run,
        "force": force,
        "templates_present": templates_present,
        "templates_seeded": seeded,
        "templates_missing": ([] if templates_present else
                              list(EXPECTED_TEMPLATES)) or
                             [d for d in EXPECTED_TEMPLATES
                              if d not in seeded],
        "missing_source_dirs": missing_sources,
        "operations": results,
        "counts": {
            "total": len(results),
            "created": len([r for r in results if r["action"] == "created"]),
            "overwritten": len([r for r in results
                                if r["action"] == "overwritten"]),
            "unchanged": len([r for r in results if r["action"] == "unchanged"]),
            "refused": refused,
            "errors": len([r for r in results if r["action"] == "error"]),
        },
        "ok": refused == 0 and not missing_sources,
        "exit_code": 0 if refused == 0 and not missing_sources else 1,
    }


def report(res, out):
    out.line("установка %s" % ("(dry run: ничего не пишет)"
                                if res["dry_run"] else ""))
    out.line("корень скилла: %s" % res["skill_root"])
    out.line("цель:          %s" % res["target"])
    out.line("")
    if res["missing_source_dirs"]:
        out.line("[WARN] в корне скилла не найдены исходные директории: %s"
                 % ", ".join(res["missing_source_dirs"]))
    if not res["templates_present"]:
        out.line("[WARN] %s/ отсутствует или пуст в корне скилла, поэтому "
                 "шаг с шаблонами ПРОПУЩЕН. Шаблоны документации не "
                 "придумывались: для них ничего не записано." % TEMPLATE_DIR)
    for r in res["operations"]:
        out.line("[%s] %s -> %s" % (r["action"].upper(), r["source"],
                                    r["dest"]))
        if r["detail"]:
            out.line("        %s" % r["detail"])
    out.line("")
    c = res["counts"]
    out.line("итог: операций %d: создано %d, перезаписано %d, без изменений "
             "%d, отказано %d, ошибок %d"
             % (c["total"], c["created"], c["overwritten"], c["unchanged"],
                c["refused"], c["errors"]))
    if res["templates_present"]:
        out.line("шаблоны разложены: %s" % (", ".join(res["templates_seeded"])
                                            or "не найдено"))
    if c["refused"]:
        out.line("ничего не перезаписано. Повторите с --force, если существующие "
                 "файлы действительно нужно заменить; предыдущая версия "
                 "сохраняется как <name>.bak.")
    elif res["dry_run"]:
        out.line("dry run: ни одного байта не записано.")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="install.py",
        description="Устанавливает протокол инфраструктуры (references/, "
                    "tools/ и, если есть, templates/) в проект. Никогда не "
                    "перезаписывает файлы без --force.",
    )
    ap.add_argument("--target", required=True,
                    help="директория проекта для установки (создается, если "
                         "ее нет)")
    ap.add_argument("--dry-run", action="store_true",
                    help="напечатать план и не записать вообще ничего")
    ap.add_argument("--force", action="store_true",
                    help="сохранить существующий отличающийся файл как "
                         "<name>.bak и заменить его")
    ap.add_argument("--skill-root", default=None,
                    help="переопределить корень скилла (по умолчанию: "
                         "родительская директория этого файла)")
    ap.add_argument("--json", action="store_true",
                    help="машиночитаемый вывод")
    args = ap.parse_args(argv)

    out = Out(sys.stdout)
    root = Path(args.skill_root).resolve() if args.skill_root else SKILL_ROOT
    if not root.is_dir():
        msg = "корень скилла не найден: %s" % root
        if args.json:
            out.line(json.dumps({"tool": "install", "schema": SCHEMA,
                                 "ok": False, "error": msg, "operations": []},
                                ensure_ascii=True))
        else:
            out.line("[FAIL] " + msg)
        return 2

    target = Path(args.target).resolve()
    if not args.dry_run:
        if target.exists() and not target.is_dir():
            msg = "цель существует и не является директорией: %s" % target
            if args.json:
                out.line(json.dumps({"tool": "install", "schema": SCHEMA,
                                     "ok": False, "error": msg,
                                     "operations": []}, ensure_ascii=True))
            else:
                out.line("[FAIL] " + msg)
            return 2
        try:
            target.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            if args.json:
                out.line(json.dumps({"tool": "install", "schema": SCHEMA,
                                     "ok": False, "error": str(exc),
                                     "operations": []}, ensure_ascii=True))
            else:
                out.line("[FAIL] не удалось создать цель: %s" % exc)
            return 2

    res = run(root, target, args.dry_run, args.force)
    if args.json:
        out.line(json.dumps(res, ensure_ascii=True, indent=2))
    else:
        report(res, out)
    return res["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
