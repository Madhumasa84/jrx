# Complete verification evidence

See [the follow-up report](../../../COMPLETE_TEST_REPORT.md). Original and repaired run logs, exact command records, JUnit XML, dependency/module origins, artifact comparisons and drivers are retained. The one intermittent broker failure and external Docker driver timeout are retained alongside passing retries.

Drivers are saved as `.py.txt`; copy them to a temporary `.py` path and adapt the recorded local paths before rerunning. Generated package binaries are not committed; artifact SHA256s are in `final-artifacts.json`. `fallback-path.txt` describes the optional scanner-unavailable environment. No real credential values or host key files are included.

Console/JUnit transcripts normalize trailing whitespace for git checks. Where changed, adjacent `.raw.gz` files preserve the exact original bytes; `console-normalization.json` records original and formatted SHA256s. Production audit logs, implementation and test code were not modified.
