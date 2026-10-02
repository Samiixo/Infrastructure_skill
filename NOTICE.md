# NOTICE

## What this is

`Infrastructure_skill` is a portable protocol that tells an AI coding agent how
to design a product's infrastructure from zero: stack selection with written
justification, data model, auth, deployment, an eight-document set, and a
dependency-ordered API roadmap. The code, prose, and tooling in this repository
were written by the author of this repository and are licensed MIT (see
`LICENSE`, Copyright (c) 2026 Samiixo).

No third-party code is vendored, imported, or required at runtime. This is a
prompt and a toolchain, not a fork of any agent framework or hosting product.

## The v1 original

The protocol originates as a single 400-line Russian-language prompt authored by
the repository owner: "УНИВЕРСАЛЬНЫЙ ПРОМТ: Первичная настройка инфраструктуры
приложения". That file is preserved verbatim at
`docs/PROMPT_v1_original.md` for provenance and diffing. It is a historical
artifact, not an active instruction file: it is allowed to keep the typographic
dashes and arrows it was written with, while every file authored for v2.0 is
held to a stricter rule.

v2.0 adds no idea that was not in that prompt, except for the toolchain and the
`modern-reality.md` supplements, both of which are new work described in
`CHANGELOG.md`.

## Legal content and its date

This repository contains references to Russian federal law, principally
152-ФЗ "О персональных данных":

- Article 18 part 5 - localization of personal data of Russian citizens;
- Article 9 - consent and cookies;
- Article 12 - cross-border transfer;
- Article 18.1 - privacy policy;
- Article 22 - notification to Roskomnadzor.

Also referenced: 436-ФЗ (age marking), 347-ФЗ article 18.1 (ERID labelling in
advertising), Law on Consumer Protection articles 9 and 26.1, 149-ФЗ article 10,
and the Civil Code article 437 (public offer).

**These references were carried over from the v1 prompt as of 2 September 2026.
They have not been machine-updated, and they are not legal advice.** Norms
change, judicial interpretation changes, and administrative penalties are
revised. Any figure, article number, or requirement quoted here must be
re-verified with a qualified lawyer before it is relied upon. The tooling never
treats a legal assertion as verified: `tools/doctor.py` reports the presence of
a statement, never its correctness.

The protocol's substantive reading of article 18 part 5 - that the requirement
governs the physical location of the data centre rather than the brand,
provenance, or licence of the software, and therefore that self-hosted
PostgreSQL or MongoDB on a Russian-hosted server is permitted while the
foreign managed equivalents are not - is carried over from the v1 prompt and
is the author's reading, not a citation of settled practice.

## Third-party product names

Vendor and product names appear throughout as **candidates to be evaluated**,
not as endorsements, and never as requirements. Where a document names options
(Russian cloud providers, payment providers, databases, observability tools),
the naming is illustrative of the decision the protocol asks the agent to make.
The protocol explicitly forbids choosing a technology by popularity or habit.

## What v2.0 added

- A verifiable result: `tools/doctor.py` audits recorded decisions rather than
  code, and fails on what is missing.
- A decision matrix (`tools/stack_matrix.py`) that deliberately does not pick
  a winner.
- A secret scanner with masked output (`tools/guard_secrets.py`).
- An installer and a test suite.
- `references/modern-reality.md` - gaps identified against 2026 practice:
  backups and RPO/RTO, cost modelling, OpenTelemetry, infrastructure as code,
  progressive delivery, the AI layer, and data-model decisions that are
  expensive to reverse.

None of these are ports of existing software; all were written for this
repository.
