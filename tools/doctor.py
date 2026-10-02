#!/usr/bin/env python3
"""Coverage auditor for an infrastructure design output.

Inverse of a linter. Silence means "probably fine". A FAIL means:
this decision was never made, and it will be discovered painfully later.

Exit codes: 0 = no failures (warnings allowed), 1 = at least one FAIL,
2 = bad target / bad usage.

Note: the console writer replaces unencodable characters, so Cyrillic
prose survives a cp1251 console (Windows) without a UnicodeEncodeError.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guard_secrets  # noqa: E402  (same directory, installed together)

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

# --------------------------------------------------------------------------
# docs
# --------------------------------------------------------------------------

DOC_README = "README.md"
DOC_ARCH = "ARCHITECTURE.md"
DOC_API = "API_CONTRACT.md"
DOC_SEC = "SECURITY.md"
DOC_ENV = "ENVIRONMENTS.md"
DOC_CONTRIB = "CONTRIBUTING.md"
DOC_DECISIONS = "DECISIONS.md"
DOC_CHECKLIST = "CHECKLIST.md"

REQUIRED_DOCS = [
    ("doc_readme", DOC_README, "описание продукта, таблица стека, локальный запуск"),
    ("doc_architecture", DOC_ARCH, "компоненты, потоки данных, сжатые обоснования"),
    ("doc_api_contract", DOC_API, "именование эндпоинтов, версионирование, ошибки, пагинация"),
    ("doc_security", DOC_SEC, "модель угроз, покрытие OWASP, план реагирования на инциденты"),
    ("doc_environments", DOC_ENV, "локальная среда / staging / прод, имена переменных окружения, деплой"),
    ("doc_contributing", DOC_CONTRIB, "стандарты кода, git flow, ревью, коммиты"),
    ("doc_decisions", DOC_DECISIONS, "записи ADR: дата / решение / контекст / статус"),
    ("doc_checklist", DOC_CHECKLIST, "живой реестр объема: что входит, что отложено"),
]

ALL_DOCS = [d[1] for d in REQUIRED_DOCS]

# --------------------------------------------------------------------------
# keyword banks (cyrillic is escaped later, the file stays pure ASCII)
# --------------------------------------------------------------------------

KW_ALTERNATIVES = [
    "\u0430\u043b\u044c\u0442\u0435\u0440\u043d\u0430\u0442\u0438\u0432",  # \u0430\u043b\u044c\u0442\u0435\u0440\u043d\u0430\u0442\u0438\u0432
    "\u043e\u0442\u043a\u043b\u043e\u043d",  # \u043e\u0442\u043a\u043b\u043e\u043d
    "\u043f\u043e\u0447\u0435\u043c\u0443 \u043d\u0435",  # \u043f\u043e\u0447\u0435\u043c\u0443 \u043d\u0435
    "rejected",
    "considered",
    "alternatives",
    "why not",
    "options considered",
]

KW_WHY = [
    "\u043f\u043e\u0447\u0435\u043c\u0443",  # \u043f\u043e\u0447\u0435\u043c\u0443
    "\u043e\u0431\u043e\u0441\u043d\u043e\u0432",  # \u043e\u0431\u043e\u0441\u043d\u043e\u0432\u0430\u043d
    "because",
    "rationale",
    "trade-off",
    "tradeoff",
    "\u0430\u0440\u0433\u0443\u043c\u0435\u043d\u0442",  # \u0430\u0440\u0433\u0443\u043c\u0435\u043d\u0442
    "\u043f\u0440\u0438\u0447\u0438\u043d\u0430",
    "reason for",
    "why:",
    "justification",
    "reasoning",
]

KW_SCALE = [
    "\u043c\u0430\u0441\u0448\u0442\u0430\u0431",  # \u043c\u0430\u0441\u0448\u0442\u0430\u0431
    "scale",
    "x10",
    "growth",
    "load path",
    "\u0440\u043e\u0441\u0442 \u043d\u0430\u0433\u0440\u0443\u0437\u043a",  # \u0440\u043e\u0441\u0442 \u043d\u0430\u0433\u0440\u0443\u0437\u043a\u0438
    "\u0433\u043e\u0440\u0438\u0437\u043e\u043d\u0442\u0430\u043b",  # \u0433\u043e\u0440\u0438\u0437\u043e\u043d\u0442\u0430\u043b\u044c\u043d
]

KW_THRESHOLD = [
    "\u043f\u043e\u0440\u043e\u0433",  # \u043f\u043e\u0440\u043e\u0433
    "threshold",
    "rps",
    "req/s",
    "requests per second",
    "\u0438\u043d\u0441\u0442\u0430\u043d\u0441",  # \u0438\u043d\u0441\u0442\u0430\u043d\u0441
    "worker",
    "\u0441\u0440\u043e\u043a\u0430 \u043f\u043e\u043b\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044c\u0441\u0442\u0432",
    "once we hit",
    "\u043f\u0440\u0438 \u0443\u0441\u0442\u043e\u0439\u0447\u0438\u0432\u043e\u0439",
    "at 10",
    "trigger",
]

KW_AUTH = [
    "jwt",
    "session",
    "\u0441\u0435\u0441\u0441",  # \u0441\u0435\u0441\u0441
    "oauth2",
    "oauth",
    "oidc",
    "bearer",
    "cookie",
    "passkey",
    "auth scheme",
    "\u0430\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446",  # \u0430\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446
]

KW_ROLE = [
    "\u0440\u043e\u043b\u044c",  # \u0440\u043e\u043b\u044c
    "\u0440\u043e\u043b\u0435\u0439",
    "\u043f\u0440\u0430\u0432\u0430",  # \u043f\u0440\u0430\u0432\u0430
    "rbac",
    "permission",
    "scope",
    "\u0434\u043e\u0441\u0442\u0443\u043f",
    "acl",
    "role",
    "roles",
]

KW_RESIDENCY = [
    "152",
    "\u0440\u0444",  # \u0440\u0444
    "\u0440\u043e\u0441\u0441\u0438\u0439\u0441\u043a",  # \u0440\u043e\u0441\u0441\u0438\u0439\u0441\u043a
    "\u043b\u043e\u043a\u0430\u043b\u0438\u0437\u0430\u0446",  # \u043b\u043e\u043a\u0430\u043b\u0438\u0437\u0430\u0446
    "\u0440\u0435\u0437\u0438\u0434\u0435\u043d\u0442",  # \u0440\u0435\u0437\u0438\u0434\u0435\u043d\u0442
    "\u044e\u0440\u0438\u0441\u0434\u0438\u043a\u0446",  # \u044e\u0440\u0438\u0441\u0434\u0438\u043a\u0446
    "\u0434\u0430\u0442\u0430-\u0446\u0435\u043d\u0442\u0440",  # \u0434\u0430\u0442\u0430-\u0446\u0435\u043d\u0442\u0440
    "\u0442\u0435\u0440\u0440\u0438\u0442\u043e\u0440\u0438\u0438 \u0440\u0444",  # \u0442\u0435\u0440\u0440\u0438\u0442\u043e\u0440\u0438\u0438 \u0440\u0444
    "data residency",
    "russia",
    "russian",
]

KW_RESIDENCY_EXEMPT = [
    "\u0438\u0441\u043a\u043b\u044e\u0447",  # \u0438\u0441\u043a\u043b\u044e\u0447
    "exempt",
    "\u043d\u0435 \u043f\u043e\u0434\u043f\u0430\u0434\u0430\u0435\u0442",
    "\u043d\u0435 \u043f\u0440\u0438\u043c\u0435\u043d\u044f\u0435\u0442\u0441\u044f",
    "does not apply",
    "no personal data",
    "out of scope of",
]

KW_PERSONAL_DATA = [
    "152",
    "\u0444\u0435\u0434\u0435\u0440\u0430\u043b\u044c\u043d",  # \u0444\u0435\u0434\u0435\u0440\u0430\u043b\u044c\u043d
    "\u043f\u0435\u0440\u0441\u043e\u043d\u0430\u043b\u044c\u043d",  # \u043f\u0435\u0440\u0441\u043e\u043d\u0430\u043b\u044c\u043d
    "\u0441\u043e\u0433\u043b\u0430\u0441\u0438",  # \u0441\u043e\u0433\u043b\u0430\u0441\u0438
    "\u0440\u043a\u043d",  # \u0440\u043a\u043d
    "gdpr",
    "personal data",
]

KW_PAYMENT = [
    "\u043f\u043b\u0430\u0442\u0435\u0436",  # \u043f\u043b\u0430\u0442\u0435\u0436
    "\u043f\u043b\u0430\u0442\u0451\u0436",
    "\u043e\u043f\u043b\u0430\u0442",  # \u043e\u043f\u043b\u0430\u0442
    "\u044d\u043a\u0432\u0430\u0439\u0440",  # \u044d\u043a\u0432\u0430\u0439\u0440
    "billing",
    "payment",
    "checkout",
    "subscription",
    "\u0441\u0443\u0431\u0441\u043a\u0440\u0438\u043f",
]

PAY_RU = [
    "\u044e\u043a\u0430\u0441\u0441\u0430",  # \u044e\u043a\u0430\u0441\u0441\u0430
    "yookassa",
    "cloudpayments",
    "cloudpayments.ru",
    "\u0442\u0438\u043d\u044c\u043a\u043e\u0444\u0444",  # \u0442\u0438\u043d\u044c\u043a\u043e\u0444\u0444
    "tbank",
    "\u0441\u0431\u043f",  # \u0441\u0431\u043f
    "sbp",
    "\u0430\u043a\u0432\u0438\u0440",  # \u0430\u043a\u0432\u0438\u0440
    "alfabank",
    "raiffeisen",
    "\u0441\u0431\u0435\u0440\u0431\u0430\u043d\u043a",
]

PAY_FOREIGN = [
    "stripe",
    "paypal",
    "braintree",
    "adyen",
    "razorpay",
    "paddle",
    "2checkout",
]

KW_STUB = [
    "\u0437\u0430\u0433\u043b\u0443\u0448\u043a",  # \u0437\u0430\u0433\u043b\u0443\u0448\u043a
    "\u043c\u043e\u043a",  # \u043c\u043e\u043a
    "mock",
    "todo",
    "fixme",
    "\u0432\u0440\u0435\u043c\u0435\u043d\u043d",  # \u0432\u0440\u0435\u043c\u0435\u043d\u043d
    "\u043f\u043e\u0437\u0436\u0435 \u0434\u043e\u043f\u0438\u0448",  # \u043f\u043e\u0437\u0436\u0435 \u0434\u043e\u043f\u0438\u0448
    "\u043f\u043e\u0442\u043e\u043c \u0437\u0430\u043c\u0435\u043d\u0438\u043c",
    "workaround",
    "\u0443\u0441\u043b\u043e\u0432\u043d\u043e",
]

KW_BACKUP = [
    "backup",
    "\u0431\u044d\u043a\u0430\u043f",  # \u0431\u044d\u043a\u0430\u043f
    "\u0440\u0435\u0437\u0435\u0440\u0432\u043d",  # \u0440\u0435\u0437\u0435\u0440\u0432\u043d
    "rpo",
    "rto",
    "\u0432\u043e\u0441\u0441\u0442\u0430\u043d\u043e\u0432",  # \u0432\u043e\u0441\u0441\u0442\u0430\u043d\u043e\u0432
    "snapshot",
    "\u0434\u0430\u043c\u043f",  # \u0434\u0430\u043c\u043f
    "pitr",
    "\u0442\u043e\u0447\u043a\u0430 \u0432\u043e\u0441\u0441\u0442\u0430\u043d\u043e\u0432\u043b",
]

KW_COST = [
    "\u0441\u0442\u043e\u0438\u043c\u043e\u0441\u0442",  # \u0441\u0442\u043e\u0438\u043c\u043e\u0441\u0442
    "\u0440\u0443\u0431\u043b",  # rouble stem; bare "rub" collided with "foreign"
    "\u0440\u0443\u0431\u002e",  # rouble abbreviation "300 rub."
    "\u20bd",  # RUR sign
    "cost",
    "tco",
    "\u043d\u0430 \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044f",  # \u043d\u0430 \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044f
    "\u0432\u0020\u043c\u0435\u0441\u044f\u0446",  # per month; bare "month" collided with "months of work"
    "\u0442\u0430\u0440\u0438\u0444",  # \u0442\u0430\u0440\u0438\u0444
    "\u0446\u0435\u043d\u0430",  # \u0446\u0435\u043d\u0430
    "usd",
    "eur",
    "month",
    "budget",
]

KW_LAYER = [
    "\u0441\u043b\u043e",  # \u0441\u043b\u043e
    "layer",
    "\u043c\u043e\u0434\u0443\u043b",  # \u043c\u043e\u0434\u0443\u043b
    "domain",
    "presentation",
    "\u043a\u043e\u043d\u0442\u0440\u043e\u043b\u043b\u0435\u0440",  # \u043a\u043e\u043d\u0442\u0440\u043e\u043b\u043b\u0435\u0440
    "\u0440\u0435\u043f\u043e\u0437\u0438\u0442\u043e\u0440",  # \u0440\u0435\u043f\u043e\u0437\u0438\u0442\u043e\u0440
    "usecase",
    "entity",
    "handler",
]

KW_ENV = [
    "\u043b\u043e\u043a\u0430\u043b\u044c\u043d",  # \u043b\u043e\u043a\u0430\u043b\u044c\u043d
    "local",
    "docker-compose",
    "production",
    "\u043f\u0440\u043e\u0434",  # \u043f\u0440\u043e\u0434
    "\u043e\u043a\u0440\u0443\u0436\u0435\u043d\u0438",  # \u043e\u043a\u0440\u0443\u0436\u0435\u043d\u0438
    "staging",
    "certificate",
    "deploy",
    "\u043f\u0435\u0440\u0435\u043d\u043e\u0441",  # \u043f\u0435\u0440\u0435\u043d\u043e\u0441
    "dns",
    "\u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442",  # \u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442
    "\u0434\u0435\u043f\u043b\u043e\u0439",  # \u0434\u0435\u043f\u043b\u043e\u0439
]

KW_PUBLIC = [
    "seo",
    "ssr",
    "ssg",
    "\u043f\u0443\u0431\u043b\u0438\u0447\u043d",  # \u043f\u0443\u0431\u043b\u0438\u0447\u043d
    "\u043b\u0435\u043d\u0434\u0438\u043d\u0433",  # \u043b\u0435\u043d\u0434\u0438\u043d\u0433
    "\u0430\u0432\u0442\u043e\u0440\u0438\u0437\u043e\u0432\u0430\u043d",  # \u0430\u0432\u0442\u043e\u0440\u0438\u0437\u043e\u0432\u0430\u043d
    "\u0437\u0430 \u043b\u043e\u0433\u0438\u043d\u043e\u043c",  # \u0437\u0430 \u043b\u043e\u0433\u0438\u043d\u043e\u043c
    "csr",
    "prerender",
]

KW_DEFERRED = [
    "deferred",
    "\u043e\u0442\u043b\u043e\u0436\u0435\u043d",  # \u043e\u0442\u043b\u043e\u0436\u0435\u043d
    "ledger",
    "\u0432\u043d\u0435 \u043e\u0431\u044a\u0451\u043c\u0430",  # \u0432\u043d\u0435 \u043e\u0431\u044a\u0451\u043c\u0430
    "\u0432\u043d\u0435 \u043e\u0431\u044a\u0435\u043c\u0430",
    "\u043d\u0435 \u0432 \u0441\u043a\u043e\u0443\u043f",  # \u043d\u0435 \u0432 \u0441\u043a\u043e\u0443\u043f
    "\u0432 \u043e\u0431\u044a\u0451\u043c",  # \u0432 \u043e\u0431\u044a\u0451\u043c
    "out of scope",
    "later phase",
    "post-mvp",
    "post mvp",
    "\u043f\u043e\u0441\u043b\u0435 \u043c\u0432\u043f",  # \u043f\u043e\u0441\u043b\u0435 \u043c\u0432\u043f
]

KW_COMPLEX = [
    "kubernetes",
    "k8s",
    "kafka",
    "service mesh",
    "\u043c\u0438\u043a\u0440\u043e\u0441\u0435\u0440\u0432\u0438\u0441",  # \u043c\u0438\u043a\u0440\u043e\u0441\u0435\u0440\u0432\u0438\u0441
    "event sourcing",
    "graphql federation",
    "multi-region",
    "\u0448\u0430\u0440\u0434\u0438\u0440",  # \u0448\u0430\u0440\u0434\u0438\u0440
    "istio",
    "envoy",
    "consul",
    "nomad",
    "zookeeper",
    "raft",
]

# near-term words that weaken a stub hit (a doc may talk about them as forbidden)
STUB_NEGATION = [
    "\u0437\u0430\u043f\u0440\u0435\u0449\u0435\u043d",  # \u0437\u0430\u043f\u0440\u0435\u0449\u0435\u043d
    "\u0437\u0430\u043f\u0440\u0435\u0449\u0430\u0442\u044c",
    "\u043d\u0435\u0434\u043e\u043f\u0443\u0441\u0442\u0438\u043c",
    "\u0431\u0435\u0437 \u043c\u043e\u043a\u043e\u0432",
    "\u043d\u0435 \u0434\u043e\u043b\u0436\u043d\u043e \u0431\u044b\u0442\u044c",
    "\u0437\u0430\u043f\u0440\u0435\u0449\u0435\u043d\u0438",
    "forbidden",
    "no stubs",
    "no stub",
    "no mock",
    "never",
    "\u043d\u0435\u043b\u044c\u0437\u044f",
    "prohibited",
]

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


class Out(object):
    """Console writer that can never raise UnicodeEncodeError.

    On a cp1251 console (or any narrow codepage) an unencodable char is
    replaced with a visible marker, never dropped silently. This is what lets
    the Russian prose below print on a default Windows console.
    """

    def __init__(self, stream):
        self.stream = stream

    def write(self, text):
        try:
            self.stream.write(text)
        except UnicodeEncodeError:
            enc = getattr(self.stream, "encoding", None) or "ascii"
            safe = text.encode(enc, "replace").decode(enc, "replace")
            try:
                self.stream.write(safe)
            except UnicodeEncodeError:
                self.stream.write(
                    text.encode("ascii", "backslashreplace").decode("ascii")
                )

    def line(self, text=""):
        self.write(text + "\n")


def read_text(path):
    for enc in ("utf-8", "cp1251", "latin-1"):
        try:
            with open(path, "r", encoding=enc) as fh:
                return fh.read()
        except (UnicodeDecodeError, LookupError):
            continue
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def read_lines(path):
    return read_text(path).splitlines()


def clip(line, limit=90):
    line = " ".join(line.split())
    if len(line) > limit:
        line = line[: limit - 3] + "..."
    return line


def find_keyword(lines, keywords, doc_names, docs, window=0):
    """Return (hit_dict_or_None, all_hits). Hit carries file and line."""
    hits = []
    for name in doc_names:
        text_lines = docs.get(name, [])
        for idx in range(len(text_lines)):
            line = text_lines[idx]
            low = line.lower()
            kw = line_has(low, keywords)
            if kw:
                hits.append(
                    {"file": name, "line": idx + 1, "keyword": kw,
                     "excerpt": clip(line)}
                )
    if not hits:
        return None, []
    return hits[0], hits


def has_number(line):
    return bool(re.search(r"\d", line))


_BOUNDARY_RX = {}


def kw_hit(low_line, kw):
    """True if kw occurs in the line.

    Keywords of 3 characters or fewer match on word boundaries only, so
    'rf' does not fire on 'performance' and 'mok' does not fire inside a
    Russian word. Longer keywords match as substrings, which is what makes
    stems like '\u043c\u0430\u0441\u0448\u0442\u0430\u0431' work for '\u043c\u0430\u0441\u0448\u0442\u0430\u0431\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u0435'.
    """
    if len(kw) > 3:
        return kw in low_line
    rx = _BOUNDARY_RX.get(kw)
    if rx is None:
        rx = re.compile(r"(?<![0-9a-z_])" + re.escape(kw) +
                        r"(?![0-9a-z_])", re.IGNORECASE)
        _BOUNDARY_RX[kw] = rx
    return bool(rx.search(low_line))


def line_has(low_line, keywords):
    for kw in keywords:
        if kw_hit(low_line, kw):
            return kw
    return None


def window_has(text_low, keywords):
    for kw in keywords:
        if kw in text_low:
            return kw
        for m in re.finditer(r"(?<![0-9a-z_])" + re.escape(kw) +
                             r"(?![0-9a-z_])", text_low):
            return kw
    return None


# --------------------------------------------------------------------------
# check registry
# --------------------------------------------------------------------------


class Check(object):
    def __init__(self, cid, title, severity, reason, action=None, evidence=None,
                 detail=None):
        self.cid = cid
        self.title = title
        self.severity = severity
        self.reason = reason
        self.action = action
        self.evidence = evidence
        self.detail = detail

    def as_dict(self):
        out = {
            "id": self.cid,
            "title": self.title,
            "status": self.severity,
            "reason": self.reason,
        }
        if self.action:
            out["next_action"] = self.action
        if self.evidence:
            out["evidence"] = self.evidence
        if self.detail:
            out["detail"] = self.detail
        return out


def run_checks(target, jurisdiction):
    checks = []
    rf = (jurisdiction == "rf")
    docs = {}
    for name in ALL_DOCS:
        p = target / name
        docs[name] = read_lines(p) if p.is_file() else []

    # ---- required docs -------------------------------------------------
    for cid, name, why in REQUIRED_DOCS:
        p = target / name
        if not p.is_file():
            checks.append(Check(
                cid, "обязательный документ: " + name, FAIL,
                "файл не найден в директории проектирования",
                "напишите %s (%s)" % (name, why),
            ))
        elif not "\n".join(docs[name]).strip():
            checks.append(Check(
                cid, "обязательный документ: " + name, FAIL,
                "файл существует, но пуст",
                "заполните %s (%s)" % (name, why),
            ))
        else:
            checks.append(Check(
                cid, "обязательный документ: " + name, PASS,
                "на месте, %d строк" % len(docs[name]),
            ))

    arch_ok = bool(docs[DOC_ARCH])
    sec_ok = bool(docs[DOC_SEC])
    env_ok = bool(docs[DOC_ENV])
    check_ok = bool(docs[DOC_CHECKLIST])
    decisions_ok = bool(docs[DOC_DECISIONS])
    any_ok = any(docs.values())

    # ---- stack_justified ----------------------------------------------
    cid_stub = "stack_justified"
    if not arch_ok:
        checks.append(Check(
            cid_stub, "у каждой технологии стека есть обоснование", FAIL,
            "ARCHITECTURE.md отсутствует, проверять нечего",
            "создайте ARCHITECTURE.md с одной строкой на слой: технология + почему",
        ))
    else:
        units, justified = count_justifications(docs[DOC_ARCH])
        if units == 0:
            checks.append(Check(
                cid_stub, "у каждой технологии стека есть обоснование", FAIL,
                "не найдено ни таблицы слоев стека, ни разделов с обоснованиями "
                "(эвристика: 0 решений обнаружено)",
                "добавьте в ARCHITECTURE.md таблицу по слоям: слой | выбор | почему | "
                "отклоненные альтернативы | известные ограничения | путь масштабирования",
            ))
        else:
            ratio = float(justified) / float(units)
            detail = ("эвристика, а не доказательство: %d из %d решений в "
                      "ARCHITECTURE.md имеют обоснование в стиле «почему» "
                      "(%.0f%%); инструмент не читает смысл, только форму"
                      % (justified, units, ratio * 100.0))
            if ratio >= 0.6:
                checks.append(Check(
                    cid_stub, "у каждой технологии стека есть обоснование",
                    PASS, detail, detail=detail,
                    evidence=first_why(docs[DOC_ARCH]),
                ))
            else:
                checks.append(Check(
                    cid_stub, "у каждой технологии стека есть обоснование",
                    FAIL,
                    detail,
                    "в каждой строке с технологией добавьте, почему она "
                    "подходит под ограничения ИМЕННО этого проекта "
                    "(один разработчик, хостинг в РФ, один бэкенд на "
                    "web/iOS/Android), а не общее место",
                    evidence=first_why(docs[DOC_ARCH]), detail=detail,
                ))

    # ---- alternatives_rejected ----------------------------------------
    cid_stub = "alternatives_rejected"
    scope = [DOC_ARCH, DOC_DECISIONS, DOC_README, DOC_SEC, DOC_API]
    hit, hits = find_keyword(docs, KW_ALTERNATIVES, scope, docs)
    if hit:
        checks.append(Check(
            cid_stub, "отклоненные альтернативы зафиксированы", PASS,
            "найдено утверждений об отказе: %d" % len(hits), evidence=hit,
        ))
    elif not any_ok:
        checks.append(Check(
            cid_stub, "отклоненные альтернативы зафиксированы", FAIL,
            "документов для просмотра нет",
            "зафиксируйте по слоям, какие варианты вы сравнивали и почему они проиграли",
        ))
    else:
        checks.append(Check(
            cid_stub, "отклоненные альтернативы зафиксированы", FAIL,
            "нет ни одной зафиксированной отклоненной альтернативы; дизайн, "
            "который ничего не сравнивает, обычно означает, что не сравнивали ничего",
            "в ARCHITECTURE.md или DECISIONS.md добавьте минимум 2 отклоненных "
            "варианта на слой с причиной проигрыша каждого",
        ))

    # ---- scaling_path --------------------------------------------------
    cid_stub = "scaling_path"
    scope = [DOC_ARCH, DOC_README, DOC_ENV, DOC_API]
    sh, _ = find_keyword(docs, KW_SCALE, scope, docs)
    th, thits = find_keyword(docs, KW_THRESHOLD, scope, docs)
    if sh and th:
        numbered = [h for h in thits if has_number(h["excerpt"])]
        if numbered:
            checks.append(Check(
                cid_stub, "зафиксирован путь от 1k до 10k пользователей", PASS,
                "путь масштабирования и числовой порог перехода присутствуют",
                evidence=numbered[0],
            ))
        else:
            checks.append(Check(
                cid_stub, "зафиксирован путь от 1k до 10k пользователей", FAIL,
                "путь масштабирования есть, но нет конкретного числа: путь "
                "роста без порога - это пожелание, а не план",
                "укажите число, например: переход на управляемую БД или "
                "второй инстанс при устойчивых 800 RPS или на 6 инстансах",
                evidence=sh,
            ))
    else:
        missing = []
        if not sh:
            missing.append("путь масштабирования")
        if not th:
            missing.append("числовой порог")
        checks.append(Check(
            cid_stub, "зафиксирован путь от 1k до 10k пользователей", FAIL,
            "отсутствует: " + " и ".join(missing),
            "в ARCHITECTURE.md напишите, что происходит при нагрузке x10 и "
            "x100 и при каком измеренном числе вы меняете топологию",
            evidence=sh,
        ))

    # ---- overengineering_thresholds ------------------------------------
    cid_stub = "overengineering_thresholds"
    if not arch_ok:
        checks.append(Check(
            cid_stub, "сложность включается по записанному числу", FAIL,
            "ARCHITECTURE.md отсутствует",
            "для каждого названного сложного компонента укажите число, "
            "начиная с которого он начинает окупаться",
        ))
    else:
        gated, ungated = complexity_scan(docs)
        if ungated:
            checks.append(Check(
                cid_stub, "сложность включается по записанному числу", FAIL,
                "названо сложных компонентов без порога внедрения: %d (%s)"
                % (len(ungated), ", ".join(u["term"] for u in ungated)),
                "для каждого: «<термин> сейчас не используется; включаем при "
                "устойчивых X RPS / Y инстансов / Z ГБ состояния»",
                evidence=ungated[0],
            ))
        elif gated:
            checks.append(Check(
                cid_stub, "сложность включается по записанному числу", PASS,
                "названо сложных компонентов с порогом рядом: %d"
                % len(gated),
                evidence=gated[0],
            ))
        else:
            checks.append(Check(
                cid_stub, "сложность включается по записанному числу", PASS,
                "избыточно сложных компонентов не заявлено (проверено: %s)"
                % ", ".join(KW_COMPLEX[:6]) + " ...",
            ))

    # ---- auth_scheme ---------------------------------------------------
    cid_stub = "auth_scheme"
    scope = [DOC_ARCH, DOC_SEC, DOC_API, DOC_README]
    ah, _ = find_keyword(docs, KW_AUTH, scope, docs)
    rh, _ = find_keyword(docs, KW_ROLE, scope, docs)
    if ah and rh:
        checks.append(Check(
            cid_stub, "конкретная схема аутентификации и модель ролей", PASS,
            "названы и схема аутентификации, и модель ролей/прав",
            evidence=ah,
        ))
    else:
        miss = []
        if not ah:
            miss.append("схема аутентификации (JWT / session / OAuth2 / OIDC)")
        if not rh:
            miss.append("модель ролей или прав")
        checks.append(Check(
            cid_stub, "конкретная схема аутентификации и модель ролей", FAIL,
            "отсутствует: " + " и ".join(miss),
            "в ARCHITECTURE.md и API_CONTRACT.md назовите схему, время жизни "
            "токена и модель ролей (кто пользователь, админ, сервис)",
            evidence=ah,
        ))

    # ---- data_residency ------------------------------------------------
    cid_stub = "data_residency"
    scope = [DOC_SEC, DOC_ARCH, DOC_ENV, DOC_README]
    rh, _ = find_keyword(docs, KW_RESIDENCY, scope, docs)
    if rh:
        checks.append(Check(
            cid_stub, "персональные данные физически хранятся в РФ", PASS,
            "локализация данных (data residency) заявлена явно", evidence=rh,
        ))
    else:
        sev = FAIL if rf else WARN
        if rf:
            why = ("нет утверждения о том, что персональные данные хранятся "
                   "на серверах, физически расположенных в Российской "
                   "Федерации (152-ФЗ, ст. 18 ч. 5). Это самый "
                   "последственный пробел в протоколе: штрафы достигают 6 млн "
                   "рублей, а решение о размещении трудно откатить")
            act = ("добавьте в SECURITY.md: названного провайдера хостинга в "
                   "РФ и регион, хост базы данных и точную формулировку о том, "
                   "что ПД остаются на инфраструктуре в РФ")
        else:
            why = ("jurisdiction=none: заявления о локализации данных нет, но "
                   "этот проект явно настроен как выведенный из-под требований "
                   "РФ по персональным данным, поэтому проверка по 152-ФЗ "
                   "ст. 18.5 понижена до предупреждения. Если допущение "
                   "окажется неверным, проверка станет FAIL: данные придется "
                   "переносить между провайдерами")
            act = ("сохраните решение о не-РФ юрисдикции в DECISIONS.md вместе "
                   "с причиной, чтобы предупреждение было решением, а не "
                   "упущением")
        checks.append(Check(
            cid_stub, "персональные данные физически хранятся в РФ", sev,
            why, act,
        ))

    # ---- pdn_law -------------------------------------------------------
    cid_stub = "pdn_law"
    pd, _ = find_keyword(docs, KW_PERSONAL_DATA, [DOC_SEC], docs)
    pay_hit, _ = find_keyword(docs, KW_PAYMENT, [DOC_ARCH, DOC_SEC, DOC_API], docs)
    foreign, _ = find_keyword(docs, PAY_FOREIGN, [DOC_ARCH, DOC_SEC, DOC_API], docs)
    if not sec_ok:
        checks.append(Check(
            cid_stub, "закон о персональных данных и платежный провайдер в РФ", FAIL,
            "SECURITY.md отсутствует",
            "раскройте 152-ФЗ (согласие, баннер cookie, политика "
            "конфиденциальности, уведомление РКН, трансграничная передача) в "
            "SECURITY.md",
        ))
    else:
        problems = []
        if not pd:
            problems.append("в SECURITY.md нет ссылок на закон о "
                            "персональных данных (152-ФЗ)")
        if foreign:
            problems.append(
                "назван зарубежный платежный провайдер (%s), хотя эквайринг в "
                "РФ обязателен" % foreign["keyword"])
        if pay_hit and not foreign:
            pay, _ = find_keyword(docs, PAY_RU, [DOC_ARCH, DOC_SEC, DOC_API], docs)
            if not pay:
                problems.append("платежи входят в объем работ, но не назван "
                                "ни один сертифицированный в РФ провайдер")
        if not problems:
            checks.append(Check(
                cid_stub, "закон о персональных данных и платежный провайдер в РФ", PASS,
                "требования 152-ФЗ раскрыты в SECURITY.md, платежный контур чист",
                evidence=pd,
            ))
        else:
            sev = FAIL if rf else WARN
            prefix = ("" if rf else
                      "jurisdiction=none: находки, специфичные для РФ, ниже "
                      "понижены до предупреждений, потому что проект "
                      "настроен как выведенный из-под требований РФ по "
                      "персональным данным; ")
            if rf and foreign:
                act = ("назовите сертифицированного в РФ эквайера "
                       "(YooKassa, CloudPayments, T-Bank, СБП) и перенесите "
                       "зарубежного в заметку о не-РФ рынке либо запишите "
                       "прямое исключение с причиной")
            elif rf:
                act = ("добавьте в SECURITY.md: 152-ФЗ ст. 9 (согласие и "
                       "cookie), ст. 18.1 (политика конфиденциальности), "
                       "ст. 22 (уведомление РКН), ст. 12 (трансграничная "
                       "передача) и, если есть платежи, эквайера в РФ")
            else:
                act = "зафиксируйте применимую юрисдикцию в DECISIONS.md"
            checks.append(Check(
                cid_stub, "закон о персональных данных и платежный провайдер в РФ", sev,
                prefix + "; ".join(problems),
                act, evidence=foreign or pd,
            ))

    # ---- no_stubs_in_prod ----------------------------------------------
    cid_stub = "no_stubs_in_prod"
    if not any_ok:
        checks.append(Check(
            cid_stub, "заглушки и моки не выдаются за продакшн-план",
            FAIL, "документов для просмотра нет",
            "выкатывайте работающий срез на каждой стадии роадмапа, "
            "в порядке зависимостей",
        ))
    else:
        real, noted = stub_scan(docs)
        if real:
            checks.append(Check(
                cid_stub, "заглушки и моки не выдаются за продакшн-план",
                FAIL,
                "строк с языком заглушек/моков/временных решений, поданным как "
                "план: %d (эвристика: соседние слова отрицания переводят "
                "находку в INFO)"
                % len(real),
                "уберите временную строку из плана или явно зафиксируйте "
                "порядок зависимостей в CHECKLIST.md: наполовину "
                "подключенное не выкатывается",
                evidence=real[0],
            ))
        else:
            reason = "языка заглушек в качестве плана не найдено"
            if noted:
                reason += " (упоминаний найдено %d, но рядом отрицание, " \
                          "например правило «заглушки запрещены»)" % len(noted)
            checks.append(Check(
                cid_stub, "заглушки и моки не выдаются за продакшн-план",
                PASS, reason, evidence=(noted[0] if noted else None),
            ))

    # ---- backup_restore ------------------------------------------------
    cid_stub = "backup_restore"
    scope = [DOC_ENV, DOC_ARCH, DOC_SEC]
    bk, _ = find_keyword(docs, KW_BACKUP, scope, docs)
    if bk:
        checks.append(Check(
            cid_stub, "история бэкапов и восстановления", PASS,
            "бэкап и восстановление раскрыты", evidence=bk,
        ))
    else:
        checks.append(Check(
            cid_stub, "история бэкапов и восстановления", FAIL,
            "нигде нет ни бэкапа, ни восстановления, ни RPO, ни RTO; о "
            "бэкапах вы узнаете впервые в тот день, когда они понадобятся",
            "в ENVIRONMENTS.md укажите, что бэкапится, как часто, где лежит "
            "копия, каковы RPO и RTO и какое учение по восстановлению вы "
            "проводили",
        ))

    # ---- cost_model ----------------------------------------------------
    cid_stub = "cost_model"
    scope = [DOC_ARCH, DOC_README, DOC_ENV, DOC_SEC]
    cst, _ = find_keyword(docs, KW_COST, scope, docs)
    if cst:
        checks.append(Check(
            cid_stub, "ожидание по стоимости", PASS,
            "ожидание по стоимости заявлено", evidence=cst,
        ))
    else:
        checks.append(Check(
            cid_stub, "ожидание по стоимости", WARN,
            "ожидание по стоимости не найдено (соло-разработчик платит по "
            "всем счетам, поэтому это вход для решения, а не деталь)",
            "добавьте в ARCHITECTURE.md месячную оценку по средам и стоимость "
            "на пользователя при 1k / 10k пользователей",
        ))

    # ---- env_var_secrets -----------------------------------------------
    cid_stub = "env_var_secrets"
    if not env_ok:
        checks.append(Check(
            cid_stub, "в ENVIRONMENTS.md нет секретов", WARN,
            "ENVIRONMENTS.md отсутствует, утекать пока нечему",
            "когда будете писать его, перечислите только имена переменных и их "
            "назначение",
        ))
    else:
        scan = guard_secrets.scan(target / DOC_ENV)
        leaks = [f for f in scan["findings"] if f["severity"] in ("FAIL",)]
        infos = [f for f in scan["findings"] if f["severity"] == "INFO"]
        if leaks:
            masked = leaks[0]
            checks.append(Check(
                cid_stub, "в ENVIRONMENTS.md нет секретов", FAIL,
                "похожих на секрет значений в ENVIRONMENTS.md: %d (значения "
                "замаскированы: %s)" % (len(leaks), masked["masked"]),
                "замените значение именем переменной и ссылкой на хранилище "
                "секретов; этот файл попадает в коммит",
                evidence={"file": DOC_ENV, "line": masked["line"],
                          "keyword": masked["rule"]},
            ))
        else:
            checks.append(Check(
                cid_stub, "в ENVIRONMENTS.md нет секретов", PASS,
                "значений нет, только имена и назначение"
                         + (" (упоминаний в тексте: %d, не значения)" % len(infos)
                            if infos else ""),
            ))

    # ---- layered_separation --------------------------------------------
    cid_stub = "layered_separation"
    scope = [DOC_ARCH, DOC_README, DOC_CONTRIB]
    ly, lyhits = find_keyword(docs, KW_LAYER, scope, docs)
    distinct = len(set(h["keyword"] for h in lyhits))
    if distinct >= 3:
        checks.append(Check(
            cid_stub, "данные / логика / API / представление разделены", PASS,
            "использовано разных терминов слоев: %d в %d строк(ах)"
            % (distinct, len(lyhits)), evidence=ly,
        ))
    else:
        checks.append(Check(
            cid_stub, "данные / логика / API / представление разделены", FAIL,
            "разделение слоев не видно: найдено всего %d разных терминов слоя "
            "(нужно минимум 3)" % distinct,
            "в ARCHITECTURE.md прочертите путь запроса через data / domain "
            "/ API / presentation с названными границами и разрешенными "
            "зависимостями",
            evidence=ly,
        ))

    # ---- local_to_prod -------------------------------------------------
    cid_stub = "local_to_prod"
    if not env_ok:
        checks.append(Check(
            cid_stub, "описаны локальная разработка и прод в РФ", FAIL,
            "ENVIRONMENTS.md отсутствует",
            "опишите локальную среду, staging и прод, а также что меняется и "
            "что не меняется на пути в прод",
        ))
    else:
        lo, _ = find_keyword(docs, KW_ENV, [DOC_ENV], docs)
        env_text = "\n".join(docs[DOC_ENV]).lower()
        need = {
            "локальная разработка": ["local", "localhost", "docker-compose",
                                     "\u043b\u043e\u043a\u0430\u043b\u044c\u043d"],
            "продовый контур": ["production", "prod", "\u043f\u0440\u043e\u0434"],
            "переход в него": ["dns", "certificate",
                               "\u043f\u0435\u0440\u0435\u043d\u043e\u0441", "\u0434\u0435\u043f\u043b\u043e\u0439"],
        }
        absent = []
        for label, kws in need.items():
            if window_has(env_text, kws) is None:
                absent.append(label)
        if absent:
            checks.append(Check(
                cid_stub, "описаны локальная разработка и прод в РФ", FAIL,
                "ENVIRONMENTS.md не описывает: " + ", ".join(absent),
                "добавьте недостающие среды и раздел о переходе: что меняется "
                "(переменные окружения, DNS, TLS-сертификат, провайдер БД) и "
                "что не меняется (код, схема, контракты API)",
                evidence=lo,
            ))
        else:
            checks.append(Check(
                cid_stub, "описаны локальная разработка и прод в РФ", PASS,
                "локальная среда, прод и переход между ними описаны",
                evidence=lo,
            ))

    # ---- public_vs_authed ----------------------------------------------
    cid_stub = "public_vs_authed"
    scope = [DOC_ARCH, DOC_API, DOC_README]
    pb, pbhits = find_keyword(docs, KW_PUBLIC, scope, docs)
    if pb:
        checks.append(Check(
            cid_stub, "решение по публичной SEO-поверхности против приложения", PASS,
            "разделение публичной и авторизованной частей затронуто "
            "(находок: %d)" % len(pbhits), evidence=pb,
        ))
    else:
        checks.append(Check(
            cid_stub, "решение по публичной SEO-поверхности против приложения", FAIL,
            "решение не зафиксировано: публичная SEO-поверхность (SSR/SSG) и "
            "авторизованная CSR-поверхность - это два разных приложения, и "
            "обнаружить это после постройки одного SPA дорого",
            "в ARCHITECTURE.md явно и письменно решите: либо продукту нужна "
            "публичная индексируемая поверхность и понятно, как она "
            "рендерится, либо ему нужна только авторизованная",
        ))

    # ---- deferred_ledger ------------------------------------------------
    cid_stub = "deferred_ledger"
    if not check_ok:
        checks.append(Check(
            cid_stub, "реестр возможностей с разделением «в объеме / отложено»", FAIL,
            "CHECKLIST.md отсутствует",
            "создайте реестр: что входит в v1, что отложено и почему, а также "
            "что уже подготовлено в контрактах и данных под отложенное",
        ))
    else:
        dh, _ = find_keyword(docs, KW_DEFERRED, [DOC_CHECKLIST], docs)
        if dh:
            checks.append(Check(
                cid_stub, "реестр возможностей с разделением «в объеме / отложено»", PASS,
                "реестр отделяет отложенную работу", evidence=dh,
            ))
        else:
            checks.append(Check(
                cid_stub, "реестр возможностей с разделением «в объеме / отложено»", FAIL,
                "в CHECKLIST.md нет разделения «в объеме / отложено / "
                "подготовлено на потом»",
                "сделайте CHECKLIST.md источником истины: что входит в v1, "
                "что отложено и почему, а какие контракты и поля данных уже "
                "учитывают отложенное",
            ))

    # ---- adrs ----------------------------------------------------------
    cid_stub = "adrs"
    if not decisions_ok:
        checks.append(Check(
            cid_stub, "не менее 3 записей в формате ADR", WARN,
            "DECISIONS.md отсутствует, поэтому через полгода рассуждения за "
            "стеком уже не восстановить",
            "создайте DECISIONS.md с записями вида дата / решение / контекст / "
            "альтернативы / статус",
        ))
    else:
        n = count_adrs(docs[DOC_DECISIONS])
        if n >= 3:
            checks.append(Check(
                cid_stub, "не менее 3 записей в формате ADR", PASS,
                "записей в формате ADR найдено: %d (дата + решение)" % n,
            ))
        else:
            checks.append(Check(
                cid_stub, "не менее 3 записей в формате ADR", WARN,
                "записей в формате ADR найдено %d, ожидается 3: дизайн с одним "
                "или двумя зафиксированными решениями - это дизайн, чьи "
                "рассуждения будут потеряны" % n,
                "добавьте записи ADR для решений, которые дорого откатывать: "
                "основная БД, схема аутентификации, версионирование API, "
                "локализация данных, стратегия идентификаторов",
            ))

    return checks


def count_justifications(lines):
    """Heuristic: count decision units and how many carry a why.

    Decision units = rows of the first markdown table that looks like a stack
    table, plus bullets under a heading whose title contains a why-word.
    """
    low = [l.lower() for l in lines]
    in_why_section = False
    units = 0
    justified = 0
    table_rows = 0
    table_just = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            title = stripped.lstrip("#").strip().lower()
            in_why_section = line_has(title, KW_WHY) is not None
            continue
        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if not cells or all(set(c) <= set("-: ") for c in cells):
                continue
            head = cells[0].lower()
            if head in ("layer", "\u0441\u043b\u043e\u0439", "stack", "\u0441\u0442\u0435\u043a", "area", "component",
                        "\u0442\u0435\u0445\u043d\u043e\u043b\u043e\u0433\u0438\u044f", "technology", "decision"):
                continue
            table_rows += 1
            if any(line_has(c.lower(), KW_WHY) for c in cells[1:]):
                table_just += 1
            continue
        if in_why_section and (stripped.startswith("-") or
                               stripped.startswith("*")):
            units += 1
            if line_has(low[i], KW_WHY):
                justified += 1
    return table_rows + units, table_just + justified


def first_why(lines):
    for i, line in enumerate(lines):
        kw = line_has(line.lower(), KW_WHY)
        if kw:
            return {"file": DOC_ARCH, "line": i + 1, "keyword": kw,
                    "excerpt": clip(line)}
    return None


DATE_PATTERNS = [
    r"\d{4}-\d{2}-\d{2}",
    r"\d{2}\.\d{2}\.\d{4}",
]
DATE_MONTHS = (
    "\u044f\u043d\u0432\u0430\u0440\u044f"
    "\u0444\u0435\u0432\u0440\u0430\u043b\u044c"
    "\u043c\u0430\u0440\u0442\u0430"
    "\u0430\u043f\u0440\u0435\u043b\u044f"
    "\u0438\u044e\u043d\u044f"
    "\u0438\u044e\u043b\u044c"
    "\u043c\u0430\u044f"
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
)
DATE_RE = re.compile("|".join(DATE_PATTERNS))
MONTH_RE = re.compile(r"\d{1,2}\s+(" + "|".join(DATE_MONTHS) + ")",
                      re.IGNORECASE)


def count_adrs(lines):
    """Heuristic: headings or bold entries that also carry a date."""
    n = 0
    for line in lines:
        s = line.strip()
        if not s:
            continue
        is_entry = s.startswith("#") or s.startswith("-") or s.startswith("*") \
            or s.startswith("|")
        if not is_entry:
            continue
        if DATE_RE.search(s) or MONTH_RE.search(s):
            n += 1
    return n


def complexity_scan(docs):
    """Find complex components and whether a threshold sits nearby."""
    gated = []
    ungated = []
    scope = [DOC_ARCH, DOC_README, DOC_DECISIONS]
    for name in scope:
        lines = docs.get(name, [])
        for i, line in enumerate(lines):
            low = line.lower()
            term = line_has(low, KW_COMPLEX)
            if term:
                lo = max(0, i - 3)
                hi = min(len(lines), i + 4)
                window = "\n".join(lines[lo:hi]).lower()
                hit = {"file": name, "line": i + 1, "keyword": term,
                       "excerpt": clip(line)}
                ok = window_has(window, KW_THRESHOLD) or has_number(window)
                if ok:
                    gated.append(hit)
                else:
                    ungated.append(hit)
    return gated, ungated


def stub_scan(docs):
    real = []
    negated = []
    for name in ALL_DOCS:
        lines = docs.get(name, [])
        for i, line in enumerate(lines):
            kw = line_has(line.lower(), KW_STUB)
            if kw:
                lo = max(0, i - 1)
                hi = min(len(lines), i + 2)
                window = "\n".join(lines[lo:hi]).lower()
                hit = {"file": name, "line": i + 1, "keyword": kw,
                       "excerpt": clip(line)}
                if window_has(window, STUB_NEGATION):
                    negated.append(hit)
                else:
                    real.append(hit)
    return real, negated


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

NEXT_ACTION_FALLBACK = "запишите решение вместе с числом, которое его " \
                       "изменит"


def report_text(checks, out, jurisdiction):
    out.line("infrastructure doctor - аудит полноты")
    out.line("тип цели: комплект проектной документации (юрисдикция: %s)"
             % jurisdiction)
    out.line("")
    order = {PASS: 0, WARN: 1, FAIL: 2}
    for c in sorted(checks, key=lambda c: (order[c.severity], c.cid)):
        out.line("[%-4s] %-28s %s" % (c.severity, c.cid, c.reason))
        if c.evidence:
            ev = c.evidence
            if isinstance(ev, dict):
                out.line("        основание: %s:%s: %s"
                         % (ev.get("file", "?"), ev.get("line", "?"),
                            ev.get("excerpt", "")))
            else:
                out.line("        основание: %s" % ev)
        if c.severity == FAIL:
            out.line("        что делать: %s"
                     % (c.action or NEXT_ACTION_FALLBACK))
    n_fail = len([c for c in checks if c.severity == FAIL])
    n_warn = len([c for c in checks if c.severity == WARN])
    n_pass = len([c for c in checks if c.severity == PASS])
    out.line("")
    out.line("итог: проверок %d, успешно %d, предупреждений %d, провалов %d"
             % (len(checks), n_pass, n_warn, n_fail))
    fails = [c for c in checks if c.severity == FAIL]
    if not fails:
        out.line("провалов нет. Это значит, что решения записаны, а не что "
                 "они хороши - прежде чем доверять, перечитайте историю "
                 "FAIL у стека самого этого протокола.")
        return 0
    out.line("чините в таком порядке:")
    for i, c in enumerate(fails[:3], 1):
        out.line("  %d. %s - %s" % (i, c.cid, c.action or NEXT_ACTION_FALLBACK))
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="doctor.py",
        description="Проверяет комплект проектной документации на "
                    "полноту решений, которые протокол требует принять и "
                    "записать. Сообщает о пробелах; отсутствие сообщений не "
                    "является доказательством качества.",
    )
    ap.add_argument("target", help="директория с проектной документацией")
    ap.add_argument("--jurisdiction", default="rf", choices=["rf", "none"],
                    help="rf (по умолчанию): проверки локализации данных и "
                         "платежей в РФ считаются провалом (FAIL). none: "
                         "проект явно выведен из-под требований РФ по "
                         "персональным данным, поэтому эти две проверки "
                         "понижаются до WARN, и вывод объясняет почему.")
    ap.add_argument("--json", action="store_true",
                    help="машиночитаемый вывод")
    args = ap.parse_args(argv)

    out = Out(sys.stdout)
    target = Path(args.target)
    if not target.exists():
        msg = "цель не существует: %s" % args.target
        if args.json:
            out.line(json.dumps({"tool": "doctor", "ok": False, "error": msg,
                                 "checks": []}))
        else:
            out.line("[FAIL] target: " + msg)
        return 2
    if not target.is_dir():
        msg = "цель не является директорией: %s" % args.target
        if args.json:
            out.line(json.dumps({"tool": "doctor", "ok": False, "error": msg,
                                 "checks": []}))
        else:
            out.line("[FAIL] target: " + msg)
        return 2

    checks = run_checks(target, args.jurisdiction)
    n_fail = len([c for c in checks if c.severity == FAIL])
    n_warn = len([c for c in checks if c.severity == WARN])
    code = report_text(checks, out, args.jurisdiction) if not args.json else \
        (1 if n_fail else 0)

    if args.json:
        payload = {
            "tool": "doctor",
            "schema": 1,
            "ok": n_fail == 0,
            "target": str(target),
            "jurisdiction": args.jurisdiction,
            "counts": {
                "total": len(checks),
                "pass": len(checks) - n_fail - n_warn,
                "warn": n_warn,
                "fail": n_fail,
            },
            "exit_code": code,
            "checks": [c.as_dict() for c in checks],
        }
        out.line(json.dumps(payload, ensure_ascii=True, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
