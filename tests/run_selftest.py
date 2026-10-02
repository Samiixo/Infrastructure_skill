#!/usr/bin/env python3
"""Self-test for the infrastructure skill tools. stdlib only.

Fixtures are built at run time inside tempfile.mkdtemp() and removed in a
finally block. Nothing secret-shaped is ever committed: the detection strings
are GENERATED here, and tests/fixtures/ holds only __FAKE_*__ placeholders.

Run: python tests/run_selftest.py
Exit: 0 only if every test passes.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
TOOLS = ROOT / "tools"
FIXTURES = HERE / "fixtures"

sys.path.insert(0, str(TOOLS))
import doctor  # noqa: E402
import guard_secrets  # noqa: E402

PY = sys.executable

# --------------------------------------------------------------------------
# fixture content
# --------------------------------------------------------------------------

DOCS = ["README.md", "ARCHITECTURE.md", "API_CONTRACT.md", "SECURITY.md",
        "ENVIRONMENTS.md", "CONTRIBUTING.md", "DECISIONS.md", "CHECKLIST.md"]

COMPLETE = {}

COMPLETE["README.md"] = """# Ledgerloop

Personal finance tracker for freelance engineers.

## Stack

| Layer | Choice |
| --- | --- |
| Backend | Python 3.12 + FastAPI |
| Database | PostgreSQL 16 |
| Hosting | Selectel, RU region, two VMs |

## Run locally

    docker compose up

## Repository layout

    app/      backend, layer by layer
    web/      public SSR pages
    mobile/   deferred, see CHECKLIST.md
"""

COMPLETE["ARCHITECTURE.md"] = """# Architecture

## Stack table

| Layer | Choice | Why | Alternatives rejected | Limits |
| --- | --- | --- | --- | --- |
| Backend | Python 3.12 + FastAPI | reason for: fastest correct async HTTP service for a solo maintainer, and the contract layer is generated for all three clients | Node/NestJS (two languages), Go (slower domain logic) | CPU bound jobs leave the request path |
| Database | PostgreSQL 16 | reason for: one store for relational core, JSON metadata and full text, self hosted on the RF VPS | MongoDB (multi-document transactions), ClickHouse (not a store of record) | single writer until we add a replica |
| Cache | Redis 7 | reason for: one well known key value service for session lookups, and a small operational footprint | No cache (database absorbs it at 1k users) | state is lost on restart |
| Search | PostgreSQL trigram | reason for: content volume at launch does not justify a second index service | Meilisearch, Elasticsearch (operational weight) | weak ranking |
| API | REST + OpenAPI 3 | reason for: three clients, one contract, no resolver layer | GraphQL (N+1 traps), gRPC (browser gateway) | over fetching on list endpoints |
| Auth | self hosted JWT, short lived plus refresh | reason for: verification happens inside RF jurisdiction, revocation via refresh denylist | Sessions (CSRF surface), foreign hosted IdP (PD leaves the jurisdiction) | refresh denylist is a small extra store |
| Roles | three roles, user, admin, service | reason for: only three tiers exist today, so a simple permission table is enough | Full RBAC engine (nothing to configure) | no per resource policy |
| Web | Next.js SSR for public pages, React CSR behind login | reason for: the public catalog needs SEO and share previews, the dashboard does not | One SPA for both (public pages would not index), two frameworks (second build pipeline) | two deploys |
| Mobile | deferred | reason for: the API contract already carries the fields the app will need | React Native, Flutter (nothing to build yet) | none until the web product is validated |
| Hosting | two VMs, Docker Compose, no orchestrator | reason for: 1000 active users is a few hundred RPS, which two VMs absorb; a solo maintainer cannot operate more | Kubernetes (adopt at a sustained 900 RPS across 6 instances or 4 VMs), managed container platform (vendor floor cost) | a deploy needs a short drain window |
| Storage | S3 compatible RF object storage | reason for: survives instance loss and is CDN ready | Local disk (files die with the instance) | egress costs |
| Queues | database table as a job queue | reason for: email and export are the only slow operations at launch, and a table gives transactional enqueue | RabbitMQ (a broker to secure and upgrade) | we own the claiming loop |
| Payments | YooKassa acquiring, webhook with idempotency keys | reason for: RF certified provider, required for the target audience, webhook dedupe is a unique index on the event id | Foreign processors (cannot be the primary channel for RF customers) | settlement delay of one day |
| CDN and DDoS | RF CDN with L7 filtering in front of both VMs | reason for: absorbs a flood at the edge instead of at the origin | Foreign CDN (terminates user traffic outside RF), origin only (origin pays the full cost) | RU PoP coverage is narrower |
| Rate limiting | gateway limits per IP plus per account limits in middleware | reason for: signup and password routes need per IP, expensive reads need per account | Middleware only (every instance shares counters) | counters live in Redis |
| Observability | error tracking plus metrics and uptime checks | reason for: the three signals a solo maintainer acts on, and no cluster to run | Full self hosted traces stack (several services) | no distributed tracing |
| CI/CD | hosted CI, one pipeline, build then deploy to the staging VM | reason for: shortest path from commit to a running environment, secrets in CI storage | Self hosted CI (the build box is under attack), manual deploy (no audit trail) | vendor dependency |
| Testing | unit plus integration against a throwaway PostgreSQL | reason for: catches migration and SQL bugs for real, which unit tests cannot | E2E for everything (slow and flaky), unit only (SQL bugs survive) | the integration suite needs a database |

## Layered separation

Request path: presentation (controller) -> application service (domain rules)
-> repository -> PostgreSQL. The controller never touches SQL, the repository
never knows about HTTP. Each layer is a separate module with a declared
interface, and the dependency direction only points inward.

## Scale path

Target: 1000 concurrent active users at launch, about 400 RPS at peak.
Growth to 10k active users: move the read path to a replica, put the CDN in
front of the static and catalog reads, and raise the pool ceiling per VM.
Growth to 100k: shard by tenant id, which the data model already carries.
Threshold to move off the current topology: a sustained 900 RPS across the two
VMs, measured as a 5 minute average, is the trigger to adopt Kubernetes.

## Cost

Launch environment: about 4500 RUB per month, of which 3200 RUB is the two
VMs and 900 RUB is object storage plus backups. At 1000 active users that is
under 5 RUB per user per month. At 10k active users the same topology costs
roughly 38000 RUB per month, which is still cheaper than the engineer time an
orchestrator would consume. Cost is a decision input here, not an afterthought.
"""

COMPLETE["API_CONTRACT.md"] = """# API contract

Base path: /api/v1. Versioning is in the path, and a breaking change means
/api/v2 with a documented overlap window of 60 days.

Naming: plural nouns, snake_case fields, verbs only where an action is not a
CRUD read.

Errors: {"error": {"code": "machine_readable_code", "message": "human text",
"request_id": "uuid"}} with the HTTP status carrying the class.

Pagination: cursor based, `?cursor=<opaque>&limit=50`, limit max 200, and a
`next_cursor: null` marks the last page.

Authentication: Bearer JWT, 15 minute access token plus a rotating refresh
token, every endpoint except /auth/* and the public catalog requires it.
Roles: user, admin, service. A service token carries a scope, a user token
carries its role, and the gateway checks the scope before the handler runs.
"""

COMPLETE["SECURITY.md"] = """# Security

## Threat model

Account takeover, credential stuffing on the login route, scraping of the
public catalog, promo abuse, and an exfiltrated database dump.

## OWASP Top 10 coverage

Injection: parameterised queries only. Broken auth: rate limits plus refresh
denylist. Sensitive data exposure: TLS 1.3 in transit, disk encryption at
rest, secrets only from the environment. XXE: no XML parser is used. Broken
access: every endpoint declares its role. Security misconfiguration: the
production VM runs only the app and a reverse proxy. SSRF: outbound calls
are allowlisted. Authentication is JWT with the role model above.

## Data residency

152-FZ article 18 part 5: all personal data of RF citizens is stored in
PostgreSQL on a Selectel VM physically located in the Russian Federation, and
object storage is the RF region of the same provider. No personal data is
written to any service hosted outside the Russian Federation. Analytics is
self hosted for the same reason.

## Personal data law

152-FZ article 9: the cookie banner asks for explicit consent before any
tracker loads. 152-FZ article 18.1: the privacy policy is published on the
public site and inside both mobile apps. 152-FZ article 22: the RKN
notification is filed before launch. 152-FZ article 12: there is one
cross-border transfer, transactional email through a non RF provider, and it
is listed as a risk with an RF alternative as the fix.

## Payments

Acquiring is YooKassa, an RF certified provider. Webhooks are deduplicated on
the provider event id with a unique index, so a replay cannot double credit
an account.

## Incident plan

A leaked credential means rotation first, then history review. A suspected
breach means: disable the affected role, snapshot the database, and write the
timeline within 24 hours.
"""

COMPLETE["ENVIRONMENTS.md"] = """# Environments

## local

docker compose brings up the API, PostgreSQL and Redis on the developer
machine. The local database is a throwaway file, seeded from the migrations
and nothing more. No production data is ever copied to a laptop.

## staging

One VM in the RF region, same image as production, seeded with generated
fake records only.

## production

Two VMs behind the RF CDN in the Selectel region. The TLS certificate is
issued for the public domain and renewed automatically.

## Environment variables (names and purposes only)

    DATABASE_URL         connection string, injected at deploy from the secret store
    REDIS_URL            cache and rate limit counter store
    JWT_SIGNING_KEY      signs access and refresh tokens
    YOOKASSA_SHOP_ID     acquiring provider shop identifier
    YOOKASSA_SECRET_KEY  acquiring provider webhook signing key
    S3_ENDPOINT          RF object storage endpoint
    SENTRY_DSN           error tracking ingest target

Values live in the provider secret store, never in this file and never in
git.

## Backup and restore

PostgreSQL: daily logical dump plus continuous WAL archiving to a second RF
region, retained 14 days. Objects: versioning on the bucket with 30 day
retention. RPO is 15 minutes, RTO is 2 hours. The restore drill runs
quarterly on staging and is documented in the incident runbook.

## Moving from local to production

What changes: environment variables and their values, the DNS record to the
load balancer, the TLS certificate, and the database host to the managed RF
instance. What does not change: the code, the schema migrations, and the API
contracts. The deploy step is the same script in both environments.
"""

COMPLETE["CONTRIBUTING.md"] = """# Contributing

## Code standards

Every backend module is split into presentation, application and repository
modules. A module may import inward only. Line length 88, type hints on
public functions, and no business rules inside a controller.

## Git flow and commits

Branch from main, one topic per branch. Commit messages: `type(scope): what
changed and why`, with the why in the body when it is not obvious. Reviews
before merge, one approval, and CI green.

## Review

The reviewer checks the tests, the migration, and whether the change respects
the layer boundaries above.
"""

COMPLETE["DECISIONS.md"] = """# Decision records

## ADR-001 2026-02-11: PostgreSQL as the primary store

Context: the core model is relational with JSON metadata. Decision:
PostgreSQL 16 self hosted. Alternatives: MongoDB, ClickHouse. Status:
accepted.

## ADR-002 2026-02-14: Self hosted JWT auth with a role table

Context: personal data must not leave RF jurisdiction, and the product has
three roles. Decision: short lived JWT plus refresh denylist, roles in the
database. Alternatives: foreign hosted IdP, server sessions. Status:
accepted.

## ADR-003 2026-02-19: REST with an OpenAPI contract for three clients

Context: web, iOS and Android share one contract. Decision: REST, cursor
pagination, generated typed clients. Alternatives: GraphQL, gRPC.
Status: accepted.

## ADR-004 2026-02-25: Two VMs, no orchestrator yet

Context: 400 RPS peak at 1000 active users, one maintainer. Decision: two
VMs with Docker Compose. Alternatives: Kubernetes, managed container
platform. Status: accepted, revisit at a sustained 900 RPS.

## ADR-005 2026-03-02: Public SSR surface is separate from the logged in app

Context: the catalog must be indexable and previewable in chat. Decision:
Next.js SSR for the public surface, React CSR for the dashboard.
Alternatives: one SPA. Status: accepted.
"""

COMPLETE["CHECKLIST.md"] = """# Checklist and capability ledger

Source of truth for scope. Update it whenever scope changes, not after.

## In scope for v1

- Auth with the three roles
- The ledger core entity and transactions
- The public catalog, SSR, indexable
- Payments through YooKassa with webhook dedupe
- Backup and restore with the stated RPO and RTO

## Deferred, with the reason

- Mobile apps. Deferred because the web product is not validated yet. The
  API contract already carries every field the apps need, and the auth
  refresh flow is device agnostic, so adding them needs no backend change.
- Multi-currency. Deferred until a second currency is actually needed. The
  money tables already store a currency column, so this is a UI and
  reporting change, not a migration.
- Kafka. Out of scope: a database job table covers the two slow operations
  we have, and the threshold to revisit is 50 jobs per second sustained.

## Prepared for later

- Tenant id exists on every core table, so sharding is a routing change
  rather than a schema change.
- Age marking field exists on user generated content for 436-FZ.
"""

THIN = {}

THIN["README.md"] = """# Ledgerloop

A personal finance tracker. Stack: Python, Postgres, Redis, Docker.

Run it with docker compose up. See the code for details.
"""

THIN["ARCHITECTURE.md"] = """# Architecture

The app is a monolith. A frontend talks to a backend, the backend talks to
PostgreSQL and Redis. Payments go through Stripe. Deploy it on a cloud VM.

The stack is Node.js, Express, PostgreSQL, Redis, Docker and GitHub Actions.
"""

THIN["API_CONTRACT.md"] = """# API

GET /users, POST /users, GET /transactions. All endpoints return JSON.
Errors return 500.
"""

THIN["SECURITY.md"] = """# Security

We follow the OWASP Top 10. Passwords are hashed. HTTPS is on. Tokens are
signed. Rate limiting protects the login route. Secrets are in environment
variables, not in the repository.
"""

THIN["ENVIRONMENTS.md"] = """# Environments

There is a local environment and a production environment. Deploy with the
CI pipeline.
"""

THIN["CONTRIBUTING.md"] = """# Contributing

Write tests. Open a pull request. Follow the existing style.
"""

THIN["DECISIONS.md"] = """# Decisions

We use Postgres. We use Docker. That is the stack.
"""

THIN["CHECKLIST.md"] = """# Checklist

- [x] auth
- [x] transactions
- [ ] mobile app eventually
"""


def write_docs(root, mapping):
    root.mkdir(parents=True, exist_ok=True)
    for name, body in mapping.items():
        (root / name).write_text(body, encoding="utf-8")
    return root


def make_complete(root):
    return write_docs(root, COMPLETE)


def make_thin(root):
    return write_docs(root, THIN)


# --------------------------------------------------------------------------
# harness
# --------------------------------------------------------------------------

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print("[%d/%d] %-52s %s" % (len(RESULTS), TOTAL_TESTS, name,
                                "PASS" if ok else "FAIL"))
    if not ok and detail:
        for line in detail.splitlines():
            print("        %s" % line)
    sys.stdout.flush()


def run_tool(script, args, env=None, cp=None):
    cmd = [PY, str(TOOLS / script)] + list(args)
    e = dict(os.environ)
    e.pop("PYTHONIOENCODING", None)
    e["PYTHONUTF8"] = "0"
    if env:
        e.update(env)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=e)
    if cp is not None:
        import io
        data = proc.stdout.read().decode(cp, "replace")
    else:
        data = proc.stdout.read().decode("utf-8", "replace")
    proc.wait()
    return proc.returncode, data


def fails_of(payload):
    out = {}
    for c in payload["checks"]:
        if c["status"] == "FAIL":
            out[c["id"]] = c
    return out


def status_map(payload):
    return dict((c["id"], c["status"]) for c in payload["checks"])


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------

TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


@test
def t1_doctor_complete_project(tmp):
    """doctor on a complete synthetic project: exit 0, zero FAIL"""
    d = make_complete(tmp / "complete")
    code, out = run_tool("doctor.py", [str(d), "--json"])
    try:
        payload = json.loads(out)
    except ValueError:
        return False, "output was not JSON:\n" + out[:2000]
    fails = fails_of(payload)
    if code != 0:
        return False, ("exit %d, expected 0; failing checks: %s"
                       % (code, sorted(fails)))
    if fails:
        return False, "unexpected FAIL: %s" % sorted(fails)
    ids = [c["id"] for c in payload["checks"]]
    doc_ids = [i for i in ids if i.startswith("doc_")]
    if len(doc_ids) != 8:
        return False, "expected 8 doc checks, got %s" % doc_ids
    if payload["counts"]["fail"] != 0:
        return False, "counts disagree with the check list: %s" % payload["counts"]
    return True, ""


@test
def t2_doctor_thin_project(tmp):
    """doctor on the classic v1 failure mode: data_residency and pdn_law FAIL"""
    d = make_thin(tmp / "thin")
    code, out = run_tool("doctor.py", [str(d), "--json"])
    payload = json.loads(out)
    fails = fails_of(payload)
    if code != 1:
        return False, "exit %d, expected 1" % code
    for cid in ("data_residency", "pdn_law"):
        if cid not in fails:
            return False, ("%s was not FAIL; status map was %s"
                           % (cid, status_map(payload)))
    if "stripe" not in fails["pdn_law"]["reason"].lower():
        return False, ("pdn_law FAIL did not name the foreign provider: %s"
                       % fails["pdn_law"]["reason"])
    for cid in ("scaling_path", "backup_restore", "stack_justified",
                "alternatives_rejected", "local_to_prod",
                "public_vs_authed", "deferred_ledger"):
        if cid not in fails:
            return False, "%s should also FAIL on the thin fixture" % cid
    for cid, c in fails.items():
        if not c.get("next_action"):
            return False, "FAIL %s carries no next_action" % cid
    return True, ""


@test
def t3_doctor_bad_targets(tmp):
    """missing dir -> 2, empty dir -> 1 and no crash"""
    code_missing, out_missing = run_tool(
        "doctor.py", [str(tmp / "does_not_exist"), "--json"])
    ok = code_missing == 2
    try:
        json.loads(out_missing)
    except ValueError:
        ok = False
    if not ok:
        return False, "missing dir: exit %d, out=%s" % (code_missing,
                                                        out_missing[:400])
    empty = tmp / "empty"
    empty.mkdir()
    code_empty, out_empty = run_tool("doctor.py", [str(empty), "--json"])
    if code_empty != 1:
        return False, "empty dir: exit %d, expected 1" % code_empty
    payload = json.loads(out_empty)
    if len(payload["checks"]) < 8:
        return False, "empty dir: too few checks emitted"
    code_human, out_human = run_tool("doctor.py", [str(empty)])
    if "Traceback" in out_human:
        return False, "empty dir human output crashed"
    return True, ""


@test
def t4_doctor_jurisdiction_none(tmp):
    """--jurisdiction none downgrades the RF checks to WARN and says why"""
    d = make_thin(tmp / "thin2")
    code_rf, out_rf = run_tool("doctor.py", [str(d), "--json"])
    code_n, out_n = run_tool("doctor.py", [str(d), "--jurisdiction", "none",
                                           "--json"])
    rf_map = status_map(json.loads(out_rf))
    n_map = status_map(json.loads(out_n))
    for cid in ("data_residency", "pdn_law"):
        if rf_map.get(cid) != "FAIL":
            return False, "%s should be FAIL under rf, was %s" % (
                cid, rf_map.get(cid))
        if n_map.get(cid) != "WARN":
            return False, "%s should be WARN under none, was %s" % (
                cid, n_map.get(cid))
    code_n2, out_human = run_tool("doctor.py", [str(d), "--jurisdiction",
                                                "none"])
    if "jurisdiction=none" not in out_human:
        return False, "human output does not explain the downgrade"
    code_bad, out_bad = run_tool("doctor.py", [str(d), "--jurisdiction", "xx"])
    if code_bad != 2:
        return False, "bad --jurisdiction value: exit %d, expected 2" % code_bad
    return True, ""


@test
def t5_guard_secrets(tmp):
    """guard_secrets: detects, masks, reports INFO, names skipped dirs"""
    # A shaped-but-fake secret, GENERATED here, never committed.
    fake_aws = "AKIA" + "Q7WERTYUIOPASDFGH"          # noqa: E501
    fake_stripe = "sk_live_" + "0FAKEfakeFAKEfake1234"
    d = tmp / "secrets"
    d.mkdir()
    (d / "leak.md").write_text(
        "Deployment key: %s\nStripe: %s\n" % (fake_aws, fake_stripe),
        encoding="utf-8")
    code, out = run_tool("guard_secrets.py", [str(d)])
    if code != 1:
        return False, "exit %d, expected 1" % code
    if fake_aws in out or fake_stripe in out:
        return False, "the raw secret value leaked into the output"
    if "AKIAQ7" not in out and "sk_liv" not in out:
        return False, "output does not show a masked prefix"

    # prose that only names a pattern -> INFO, not FAIL
    p = tmp / "prose"
    p.mkdir()
    (p / "ENVIRONMENTS.md").write_text(
        "Never commit a password: <redacted>\n"
        "api_key = ${API_KEY} is injected at deploy time\n",
        encoding="utf-8")
    code_p, out_p = run_tool("guard_secrets.py", [str(p)])
    if code_p != 0:
        return False, "prose-only dir: exit %d, expected 0\n%s" % (code_p,
                                                                 out_p)
    if "INFO" not in out_p:
        return False, "prose hit was not reported as INFO"
    if "password" not in out_p:
        return False, "INFO finding did not print the line for a human to judge"

    # clean dir
    c = tmp / "clean"
    c.mkdir()
    (c / "README.md").write_text("# nothing sensitive here\n", encoding="utf-8")
    code_c, out_c = run_tool("guard_secrets.py", [str(c), "--json"])
    if code_c != 0:
        return False, "clean dir: exit %d, expected 0" % code_c
    payload = json.loads(out_c)
    if payload["ok"] is not False and payload["counts"]["fail"]:
        return False, "clean dir reported failures"

    # skipped directories must be named
    s = tmp / "skipped"
    (s / "node_modules").mkdir(parents=True)
    (s / "node_modules" / "pkg.md").write_text("secret: %s\n" % fake_stripe,
                                              encoding="utf-8")
    (s / "top.md").write_text("clean\n", encoding="utf-8")
    code_s, out_s = run_tool("guard_secrets.py", [str(s)])
    if "node_modules" not in out_s:
        return False, "skipped directory was not named in the output"
    if code_s != 0:
        return False, "skipping a dir must not itself be a finding"

    # bad path
    code_x, _ = run_tool("guard_secrets.py", [str(tmp / "nope")])
    if code_x != 2:
        return False, "bad path: exit %d, expected 2" % code_x
    return True, ""


@test
def t6_stack_matrix(tmp):
    """stack_matrix: every mandatory layer, and no winner declared"""
    code, out = run_tool("stack_matrix.py", [])
    if code != 0:
        return False, "exit %d, expected 0" % code
    mandatory = ["backend", "database", "api_style", "auth", "cache", "search",
                 "storage", "queues", "hosting", "payments", "cdn_ddos",
                 "rate_limiting", "observability", "ci_cd", "testing",
                 "mobile"]
    for lid in mandatory:
        if "[%s]" % lid not in out:
            return False, "layer %s missing from the human output" % lid
    banned = ["\u0432\u044b\u0431\u0440\u0430\u043d", "\u0440\u0435\u043a\u043e\u043c\u0435\u043d\u0434\u0443\u0435\u043c", "recommended", "recommendation",
              "winner", "\u043f\u043e\u0431\u0435\u0434\u0438\u0442\u0435\u043b", "we chose", "our pick", "the best choice"]
    low = out.lower()
    for b in banned:
        if b in low:
            return False, "stack_matrix declared a winner: found %r" % b
    for marker in ("deciding question:", "what would settle it:",
                   "comparison axes"):
        if marker not in out:
            return False, "missing section marker %r" % marker
    code_j, out_j = run_tool("stack_matrix.py", ["--json"])
    payload = json.loads(out_j)
    if payload.get("declares_winner") is not False:
        return False, "JSON does not declare declares_winner=false"
    if len(payload["layers"]) < len(mandatory):
        return False, "JSON layer list is short"
    for layer in payload["layers"]:
        for field in ("deciding_question", "evidence_that_settles_it",
                      "options", "axes"):
            if not layer.get(field):
                return False, "layer %s has empty %s" % (layer["id"], field)
        if len(layer["options"]) < 2:
            return False, "layer %s has fewer than 2 options" % layer["id"]
    code_f, out_f = run_tool("stack_matrix.py", ["--layers",
                                                "backend,nope"])
    if code_f != 2:
        return False, "unknown layer id: exit %d, expected 2" % code_f
    return True, ""


@test
def t7_install(tmp):
    """install: dry-run writes nothing, real install, no clobber, --force .bak"""
    target = tmp / "proj"
    target.mkdir()
    code, out = run_tool("install.py", ["--target", str(target), "--dry-run"])
    if code not in (0, 1):
        return False, "dry run exit %d" % code
    leftovers = list(target.rglob("*"))
    if leftovers:
        return False, "dry run wrote: %s" % leftovers[:5]
    if "dry run" not in out.lower():
        return False, "dry run did not say it is a dry run"

    code, out = run_tool("install.py", ["--target", str(target), "--json"])
    if code != 0:
        return False, "first install exit %d: %s" % (code, out[:600])
    payload = json.loads(out)
    if not (target / "tools" / "doctor.py").is_file():
        return False, "doctor.py was not installed"
    if not (target / "references").exists():
        return False, "references/ was not installed"

    # simulate a local modification, then re-install without --force
    victim = target / "tools" / "doctor.py"
    victim.write_text("# local edit\n", encoding="utf-8")
    code2, out2 = run_tool("install.py", ["--target", str(target)])
    if code2 != 1:
        return False, "second install should refuse, exit %d" % code2
    if victim.read_text(encoding="utf-8") != "# local edit\n":
        return False, "the modified file was clobbered without --force"

    code3, out3 = run_tool("install.py", ["--target", str(target), "--force"])
    if code3 != 0:
        return False, "--force install exit %d: %s" % (code3, out3[:600])
    bak = target / "tools" / "doctor.py.bak"
    if not bak.is_file():
        return False, "--force did not create doctor.py.bak"
    if bak.read_text(encoding="utf-8") != "# local edit\n":
        return False, "the .bak does not hold the previous version"
    if "# local edit" in victim.read_text(encoding="utf-8"):
        return False, "--force did not replace the file"
    return True, ""


@test
def t8_cp1251_regression(tmp):
    """child on a cp1251 console, no PYTHONIOENCODING, no UnicodeEncodeError"""
    d = make_complete(tmp / "console")
    # Push characters that cp1251 cannot encode into a file the tool will echo.
    (d / "ARCHITECTURE.md").write_text(
        COMPLETE["ARCHITECTURE.md"]
        + "\nCost line: 1200 RUB/month, >= 5 instances, 1 GB/second. "
          "Marker: \u20bd \u2014 \u2265 \u00abquoted\u00bb \U0001F512\n",
        encoding="utf-8")
    boot = ("import sys, runpy;"
            "sys.stdout.reconfigure(encoding='cp1251');"
            "sys.stderr.reconfigure(encoding='cp1251');"
            "sys.argv=%r;"
            "runpy.run_path(%r, run_name='__main__')")
    printed = []
    for args in ([str(d), "--json"], [str(d)]):
        code = boot % (["doctor.py"] + args,
                       str(TOOLS / "doctor.py"))
        env = dict(os.environ)
        env.pop("PYTHONIOENCODING", None)
        env["PYTHONUTF8"] = "0"
        proc = subprocess.Popen([PY, "-c", code], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=env)
        raw = proc.stdout.read()
        proc.wait()
        text = raw.decode("cp1251", "replace")
        printed.append("---- child: python doctor.py %s (cp1251, no "
                       "PYTHONIOENCODING) -> exit %d" % (" ".join(args),
                                                         proc.returncode))
        if "--json" in args:
            shown = text.splitlines()
            printed.extend(shown[:24])
            printed.append("    ... [%d more lines of the real JSON output, "
                           "truncated here only] ..." % max(0, len(shown) - 24))
        else:
            printed.append(text)
        if "UnicodeEncodeError" in text:
            return False, "UnicodeEncodeError raised:\n" + text[:2000]
        if "Traceback" in text:
            return False, "traceback in child output:\n" + text[:2000]
        if proc.returncode != 0:
            return False, "child exit %d on a complete fixture" % proc.returncode
    print("")
    for line in printed:
        print("    " + line.rstrip())
    print("")
    return True, ""


@test
def t9_fixtures_gitignore(tmp):
    """tests/fixtures/.gitignore ignores logs/pycache but not fixture md"""
    gi = FIXTURES / ".gitignore"
    if not gi.is_file():
        return False, "tests/fixtures/.gitignore is missing"
    import fnmatch
    patterns = []
    for raw in gi.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    for p in patterns:
        for name in ("README.md", "ARCHITECTURE.md", "SECURITY.md"):
            if fnmatch.fnmatch(name, p):
                return False, ".gitignore pattern %r would ignore %s" % (p,
                                                                         name)
    if not any(p.endswith(".log") or p == "*.log" for p in patterns):
        return False, ".gitignore does not ignore *.log"
    if not any("__pycache__" in p for p in patterns):
        return False, ".gitignore does not ignore __pycache__"
    md = [p for p in FIXTURES.glob("*.md")]
    if not md:
        return False, "no committed fixture markdown to protect"
    for f in md:
        body = f.read_text(encoding="utf-8")
        if "sk_live_" in body or "AKIA" in body:
            return False, "%s contains a realistic secret literal" % f.name
    return True, ""


@test
def t10_utf8_and_charset(tmp):
    """every .py and authored .md is valid UTF-8 with no forbidden chars"""
    # Typographic characters that must not appear: use -, ", ', ..., -> instead.
    forbidden = {
        0x2014: "U+2014 em dash",
        0x2013: "U+2013 en dash",
        0x2018: "U+2018 curly single quote",
        0x2019: "U+2019 curly single quote",
        0x201C: "U+201C curly double quote",
        0x201D: "U+201D curly double quote",
        0x2026: "U+2026 ellipsis",
        0x2192: "U+2192 arrow",
        0x2713: "U+2713 check mark",
        0x2717: "U+2717 ballot mark",
    }
    # Emoji/arrow ranges below U+2300 (the > U+2300 rule covers the rest).
    emoji_ranges = [(0x2190, 0x21FF), (0x2600, 0x27BF), (0x2B00, 0x2BFF),
                    (0xFE00, 0xFE0F), (0x1F000, 0x1FAFF)]
    bad = []
    files = sorted(list(TOOLS.glob("*.py")) + list(HERE.glob("*.py")))
    for f in files:
        data = f.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            bad.append("%s: not valid UTF-8 (%s)" % (f.name, exc))
            continue
        hits = set()
        for ch in text:
            cp = ord(ch)
            if cp <= 126:
                continue
            if cp in forbidden:
                hits.add(forbidden[cp])
            elif 0x0400 <= cp <= 0x04FF:
                continue  # legitimate Cyrillic
            elif cp > 0x2300:
                hits.add("codepoint above U+2300: U+%04X" % cp)
            else:
                for lo, hi in emoji_ranges:
                    if lo <= cp <= hi:
                        hits.add("emoji/arrow U+%04X" % cp)
                        break
        for h in sorted(hits):
            bad.append("%s: %s" % (f.name, h))
    if bad:
        return False, "\n".join(bad)
    if not files:
        return False, "no .py files found to check"

    # The same rule must hold for the authored markdown: references/, the
    # templates, SKILL.md, README.md, examples/. This was a real gap - box
    # drawing glyphs (U+2500 family) reached README.md, which are absent from
    # cp1251 and render as garbage on a Windows console. The .py-only check
    # could not see them because README is legitimately Russian and was
    # exempted from the non-ASCII rule.
    # docs/PROMPT_v1_original.md is a verbatim historical artifact and is
    # deliberately exempt.
    EXEMPT = {"PROMPT_v1_original.md"}
    md_targets = []
    for rel in ("references", "templates", "examples", "docs"):
        d = ROOT / rel
        if d.is_dir():
            md_targets.extend(sorted(d.rglob("*.md")))
    for name in ("SKILL.md", "README.md", "CHANGELOG.md", "NOTICE.md"):
        f = ROOT / name
        if f.is_file():
            md_targets.append(f)

    md_bad = []
    for f in md_targets:
        if f.name in EXEMPT:
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            md_bad.append("%s: not valid UTF-8 (%s)" % (f.name, exc))
            continue
        hits = set()
        for ch in text:
            cp = ord(ch)
            if cp <= 126:
                continue
            if cp in forbidden:
                hits.add(forbidden[cp])
            elif 0x0400 <= cp <= 0x04FF:
                continue  # legitimate Cyrillic
            elif cp > 0x2300:
                hits.add("codepoint above U+2300: U+%04X" % cp)
            else:
                for lo, hi in emoji_ranges:
                    if lo <= cp <= hi:
                        hits.add("emoji/arrow U+%04X" % cp)
                        break
        for h in sorted(hits):
            md_bad.append("%s: %s" % (f.name, h))
    if md_bad:
        return False, "markdown: " + "; ".join(md_bad[:8])
    return True, ""


@test
def t11_keyword_collisions(tmp):
    """keyword matching does not report a PASS on unfilled placeholders"""
    # Regression for three measured false PASSes. Each pair is (text, should
    # the keyword list fire). The failures were substring collisions:
    #   "rub" inside "foreign", "month" inside "months of work",
    #   "catalog" inside "directory tree".
    cost_cases = [
        ("\u0437\u0430\u0440\u0443\u0431\u0435\u0436\u043d\u044b\u0445", False),
        ("\u0441\u0442\u043e\u0438\u0442 \u043c\u0435\u0441\u044f\u0446\u044b "
         "\u0440\u0430\u0431\u043e\u0442\u044b", False),
        ("\u0441\u0442\u043e\u0438\u043c\u043e\u0441\u0442\u044c 300 "
         "\u0440\u0443\u0431\u043b\u0435\u0439 \u0432 \u043c\u0435\u0441\u044f\u0446", True),
        ("300 \u0440\u0443\u0431.", True),
    ]
    for text, want in cost_cases:
        got = bool(doctor.line_has(text.lower(), doctor.KW_COST))
        if got != want:
            return False, ("KW_COST on %r: got %s, want %s (a substring "
                           "collision is back)" % (text, got, want))

    public_cases = [
        ("\u0434\u0435\u0440\u0435\u0432\u043e \u043a\u0430\u0442\u0430\u043b\u043e\u0433\u043e\u0432", False),
        ("\u043a\u0430\u0442\u0430\u043b\u043e\u0433 \u0442\u043e\u0432\u0430\u0440\u043e\u0432", False),
        ("\u043f\u0443\u0431\u043b\u0438\u0447\u043d\u0430\u044f SEO-\u043f\u043e\u0432\u0435\u0440\u0445\u043d\u043e\u0441\u0442\u044c", True),
    ]
    for text, want in public_cases:
        got = bool(doctor.line_has(text.lower(), doctor.KW_PUBLIC))
        if got != want:
            return False, ("KW_PUBLIC on %r: got %s, want %s (a substring "
                           "collision is back)" % (text, got, want))

    # The integration assertion that matters most: the shipped templates are
    # unfilled placeholders, so these two decisions have NOT been made and the
    # doctor must say FAIL. A PASS here means the tool reports success on an
    # empty project, which is the exact theatre it exists to prevent.
    templates = ROOT / "templates"
    if not templates.is_dir():
        return False, "templates/ missing, cannot check the unfilled project"
    code, out = run_tool("doctor.py", [str(templates), "--json"])
    payload = json.loads(out)
    status = {c["id"]: c["status"] for c in payload["checks"]}
    for cid in ("cost_model", "public_vs_authed"):
        if status.get(cid) == "PASS":
            return False, ("doctor reports PASS for %s on the unfilled "
                           "templates: a false success" % cid)
    return True, "collisions fixed; unfilled templates fail both checks"


TOTAL_TESTS = len(TESTS)


def main():
    start = time.time()
    tmp = tempfile.mkdtemp(prefix="infra_selftest_")
    print("temp fixtures: %s" % tmp)
    print("")
    try:
        for fn in TESTS:
            sub = Path(tmp) / fn.__name__
            sub.mkdir(parents=True, exist_ok=True)
            try:
                ok, detail = fn(sub)
            except Exception as exc:  # a crashed test is a failed test
                import traceback
                ok = False
                detail = traceback.format_exc()
            record(fn.__doc__.strip().splitlines()[0], ok, detail)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    passed = len([r for r in RESULTS if r[1]])
    total = len(RESULTS)
    print("")
    print("summary: %d/%d passed in %.1fs" % (passed, total,
                                               time.time() - start))
    if passed != total:
        print("FAILED: %s" % ", ".join(r[0] for r in RESULTS if not r[1]))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
