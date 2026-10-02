# Committed fixture policy

This directory is committed. Anything in it must be safe to push.

Rules the test suite enforces (`t9_fixtures_gitignore`):

1. No realistic secret literal may ever be committed. Anything secret-shaped
   is written as a `__FAKE_*__` placeholder, like the lines below.
2. Detection strings are GENERATED at run time inside a temp dir by
   `tests/run_selftest.py`, then deleted in a `finally` block. That is why the
   scanner has something real to find without the repository holding it.
3. `.gitignore` here ignores `*.log`, `__pycache__` and friends. It must NOT
   ignore `*.md`: a fixture markdown file is an input to an assertion, and an
   ignore rule that swallows it turns a test into a no-op.

Example of a committed, deliberately fake credential line:

    AWS_ACCESS_KEY_ID=__FAKE_AWS_KEY_DO_NOT_USE__
    PAYMENT_API_KEY=__FAKE_PAYMENT_KEY_DO_NOT_USE__

The guard_secrets scanner reports both as placeholders (INFO, not FAIL) so a
reviewer can judge the line by eye, which is the intended behaviour for prose
that merely names a secret-shaped pattern.
