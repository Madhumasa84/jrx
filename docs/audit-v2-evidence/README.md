# Audit V2 evidence

Verification transcripts use an explicit tracked exception to the repository's generic
`*.log` ignore rule. Trailing terminal whitespace is normalized; substantive output is retained. Reproductions use synthetic secrets and disposable files only.

- `*-before.log`: failing reproductions before the associated fix.
- `baseline-unrestricted.log`: starting-commit full suite.
- `final-pytest.log`: complete post-change verification.
- `clean-make-test.log`: complete suite and golden cases from a clean implementation clone.
- `final-adversarial.log`: all 68 added regression/adversarial cases.
- `wheel-cli-checks.json` / `sdist-cli-checks.json`: 28 installed checks each, including
  both entrypoints (the alias check is asserted separately by the driver).
- `docker-smoke.json`: offline default broker startup, fail-closed self-check and
  old/new synthetic Docker context assertions. Expected old-context failure is recorded.
- `source-scan.txt`: reviewed stubs, cleanup handlers, protocol/CLI prints and skip conditions.

Drivers are retained as `.py.txt` evidence artifacts. They can be run with Python using
the arguments shown in the driver; Docker driver requires the local audit image and
recorded base commit. Paths identify disposable audit environments, not deployment defaults.
