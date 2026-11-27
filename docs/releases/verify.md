# Verifying a release

`scripts/verify-release.sh vX.Y.Z` checks a published release the way an operator
should before deploying it. It needs `gh`, `cosign` 2.6+ or 3.x, `docker`, Python 3.11+,
`helm` and `yq`, and stops at the first failure.

| Check | What it proves | Exercised for v0.3.0 |
| --- | --- | --- |
| `cosign verify` of the broker image digest with `--certificate-identity https://github.com/Madhumasa84/jrx/.github/workflows/release.yml@refs/tags/vX.Y.Z` and `--certificate-oidc-issuer https://token.actions.githubusercontent.com` | The image was signed by the tag-triggered release workflow of this repository (keyless; the signature is in the Rekor transparency log) | Yes: `sha256:32b3f1cb10557fa613966e37105034e4ad6ec94edc8868a33ae85eab7596e4e7`, workflow commit `54cdf57`, 2026-11-28 |
| `cosign verify-attestation --type spdxjson` with the same identity | The SPDX SBOM attached to the image came from the same workflow | Yes |
| The same signature fails for `…@refs/heads/main` | The identity pin is effective | Yes (cosign exit 12) |
| Release wheel installs into a clean virtualenv, `pip check` passes, `jrx check` holds `rm -rf ./cache` | The published wheel is complete and enforces | Yes |
| The image starts healthy with the release's Helm configuration, `--read-only`, `--network none`, `--cap-drop ALL` | The published image runs under the chart's security context | Yes (healthy in 4 polls, `pip check` clean) |

**Not covered, because the release does not produce it:** the wheel and sdist are not
signed and have no provenance attestation; the SBOM describes the image, not the Python
distributions; the Helm chart is not published. The script prints the wheel and sdist
SHA-256 so they can be compared with another copy. As of 2026-11-28 PyPI has only
`jev-reflex` 0.2.0; the v0.3.0 Python artifacts exist only on the GitHub release.
