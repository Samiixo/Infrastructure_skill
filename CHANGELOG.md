# CHANGELOG

All notable changes to this project are documented here.

## [2.0.0] - 2026-10-02

The verifiable release. v1 was a single 400-line prompt with no way to check
whether the agent had actually made the decisions it claimed. v2.0 keeps the
protocol and its substance, and makes the output auditable.

### Added - verification toolchain

- `tools/doctor.py` - audits the **decisions recorded in documentation**
  rather than the code. This is the inverse of a linter: silence means
  "probably fine", a FAIL means "this was never decided and you will find out
  painfully later". Checks include data residency, personal data law, migration
  thresholds for any added complexity, backup and RPO/RTO, rejected
  alternatives, no stubs in the production plan, the local-to-production
  transition, the public-vs-authenticated decision, the capability ledger, and
  secret leakage into environment documentation. Every FAIL prints a concrete
  next action. `--jurisdiction none` downgrades the RF-specific checks to
  warnings with an explanation, rather than silently skipping them. Exit 0/1/2,
  `--json` supported.
- `tools/stack_matrix.py` - per-layer decision matrix: candidates, the deciding
  question, and what evidence would settle it. Deliberately does **not** pick a
  winner, because the most common failure in this domain is asserting a stack
  choice with no comparison.
- `tools/guard_secrets.py` - secret scanner that masks every matched value in
  its own output and names the directories it skipped, because a silent skip is
  how a scan lies.
- `tools/install.py` - installs the protocol into a project. `--dry-run` is
  provably a no-op, `--force` backs up before overwriting, and it never clobbers
  a modified file without being told.
- `tests/run_selftest.py` - the suite, including a cp1251 console regression
  that deliberately runs its child **without** forcing `PYTHONIOENCODING`,
  because a test that forces it hides the bug it exists to catch.

### Added - modern-reality supplements

`references/modern-reality.md` covers gaps identified against 2026 practice,
each written to be folded into the stage that owns it:

- **Backups, PITR, RPO/RTO** with a date of last restore test. An untested
  backup is the absence of a backup.
- **Cost modelling** - cost per active user per month, budget alerts. The
  solo-maintainer constraint dies of cloud spend, not of code complexity.
- **OpenTelemetry** as the tracing standard rather than logs plus an error
  tracker.
- **Terraform/OpenTofu** with remote state, because a production environment
  configured by hand over SSH is not reproducible.
- **Progressive delivery** - feature flags, blue-green, canary, and
  expand/contract database migrations instead of an irreversible step.
- **The AI layer**, when the product has one - provider, model routing, per
  request cost ceilings, an eval loop against quality regressions, prompt and
  personal data handling, and degradation when the provider is unavailable.
- **Data model decisions that are expensive to reverse** - UUID vs
  autoincrement, money in integer minor units (never float), time in UTC.
- **Accessibility** as an architectural constraint with numbers, not a
  later task.
- **Supply chain** - pinned versions, lockfiles, dependency vulnerability
  scanning.
- **Timeout and retry discipline** - a timeout on every network call, circuit
  breakers, idempotency on retried operations.

### Added - documentation and structure

- `SKILL.md` - the core protocol: when it applies, the 13 constraints, the
  gated stage list, the justification template, and the commands.
- `references/constraints.md` - the 13 technical constraints and the Russian
  legal section, with an explicit verification date and an instruction to
  re-check the law with a qualified lawyer.
- `references/doc-templates.md` - the skeletons of the eight documents, plus
  the rule of one home: a decision is recorded in one document and referenced
  from the others.
- `examples/` - a filled example of the protocol output.
- `assets/` - three diagrams with their HTML sources.

### Changed

- The protocol is split by stage instead of delivered as one wall of text. An
  agent now loads the stage it is executing, not 400 lines every turn.
- Each stage file gained a **"Готовность этапа"** section with binary exit
  conditions, so a weak gate is visible rather than implied, and a
  **"Связанные"** section for navigation.
- The "Известные ограничения этого выбора" line is now mandatory and cannot
  be empty: an agent that cannot name a single drawback has not understood the
  subject rather than having found a perfect option.
- Typographic dashes, curly quotes, ellipsis characters and arrow glyphs were
  removed from all authored text, because they corrupt on a cp1251 Windows
  console. Cyrillic is retained; only the punctuation is constrained.
- The v1 prompt is preserved verbatim at `docs/PROMPT_v1_original.md` for
  provenance, and is explicitly exempt from the punctuation rule as a
  historical artifact.

### Fixed

- The v1 prompt asked the agent to check domain availability "logically", which
  invites a fabricated claim. The stage 1 file now states plainly that the
  agent cannot verify availability and must not claim it did.
- The v1 prompt's scaling requirement said "documented path to 10k and 100k"
  without requiring a number. The stage 2 file now requires a numeric trigger
  for every scaling step, and every piece of added complexity.
- The v1 prompt named Stripe and PayPal as examples alongside Russian
  providers in a way that left the constraint ambiguous. `tools/doctor.py` now
  fails a Russian-jurisdiction project that names a foreign payment provider.

### Known limitations

- The content checks in `tools/doctor.py` are heuristics over text, not proofs.
  Every one is labelled as a heuristic in the output and prints its matches
  rather than reporting a confident PASS. They cannot establish that a written
  decision is correct, only that one was written down.
- The toolchain is tested on Windows, Python 3.9.9, cp1251 console. It has not
  been run on macOS or Linux, or on any other Python version.
- The protocol is written in Russian, because its domain is Russian law and
  Russian providers. It is not translated.

### Fixed during verification (after the first green run)

Each of these was found by checking the tool against an **unfilled** project
rather than only against a correct one, and each now has a regression test
that was proved to redden by mutation.

- **Three false PASSes from substring collisions in the keyword matcher.**
  `kw_hit()` applies a word-boundary regex only to keywords of three characters
  or fewer, and that regex uses an ASCII-only boundary class, so longer Russian
  stems are matched as plain substrings. Measured on the shipped templates,
  which are empty placeholders:

  | Keyword | Collided with | Effect |
  |---|---|---|
  | `руб` | `зарубежных` (foreign) | `cost_model` reported PASS |
  | `месяц` | `месяцами работы` (months of work) | `cost_model` reported PASS |
  | `каталог` | `каталогов` (directory tree) | `public_vs_authed` reported PASS |

  A blanket Cyrillic word boundary would have been wrong, because legitimate
  stems such as `сло` must still match `слои`. The keywords were made
  unambiguous instead: `руб` became `рубл` plus `руб.`, `месяц` became `в месяц`,
  and `каталог` was removed as too ambiguous. The malformed shape is what
  shipped; the tool that reports success on an empty project is exactly the
  theatre it exists to prevent.
- **Box-drawing glyphs reached `README.md`.** The directory tree used the
  U+2500 family, which is absent from cp1251 and renders as garbage on a
  Windows console. The rule forbidding them was enforced only over `.py` files,
  and `README.md` was exempted from the non-ASCII check because it is
  legitimately Russian. The check now covers the authored markdown as well
  (`references/`, `templates/`, `examples/`, `docs/`, and the root documents),
  with the verbatim v1 original as the single explicit exemption.
- **The human-readable output was English in a Russian protocol.** The primary
  reader of `doctor.py` is a Russian-speaking developer deciding which
  architectural decision is still missing. All four tools now emit Russian,
  while check ids, JSON keys, CLI flags, regexes and exit codes stay
  byte-identical, because those are the contract.
- **A syntax error in `doctor.py`** (an unbalanced parenthesis in a date
  regex) briefly made three tests fail for an unrelated reason. Worth recording
  because the failing tests were reporting the wrong cause, which is how a
  real defect hides behind a plausible one.
- The `--json` output was briefly suspected of emitting a UTF-8 BOM. It was
  not: the bytes came from a PowerShell redirect (`>` writes UTF-16), not from
  the tools. Recorded so nobody re-investigates it.

## [1.0.0] - original

A single 400-line Russian-language prompt: "УНИВЕРСАЛЬНЫЙ ПРОМТ: Первичная
настройка инфраструктуры приложения". 13 hard constraints, 6 gated stages,
13 mandatory stack layers, an 8-document set, a brandbook, an HTML prototype,
and a dependency-ordered API roadmap. Preserved verbatim at
`docs/PROMPT_v1_original.md`.
