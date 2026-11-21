"""Exercise release shell steps without contacting a registry or signing service."""

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

from jev_reflex import __version__


def test_release_builds_validated_python_artifacts_before_publishing():
    root = Path(__file__).parents[1]
    chart = yaml.safe_load((root / "helm/jrx-broker/Chart.yaml").read_text())
    assert chart["appVersion"] == __version__
    workflow = yaml.safe_load((root / ".github/workflows/release.yml").read_text())
    assert workflow["jobs"]["verify"]["uses"] == "./.github/workflows/ci.yml"
    assert workflow["jobs"]["verify"]["with"]["release_tag"] == "${{ github.ref_name }}"
    assert workflow["jobs"]["release"]["needs"] == "verify"
    steps = workflow["jobs"]["release"]["steps"]
    build_index = next(
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Build and validate Python distributions"
    )
    assert "python -m build" in steps[build_index]["run"]
    assert "python -m twine check dist/*" in steps[build_index]["run"]
    assert build_index < next(i for i, step in enumerate(steps) if step.get("id") == "build")
    assets = next(
        step["with"]["files"]
        for step in steps
        if step.get("uses", "").startswith("softprops/action-gh-release@")
    )
    assert {"sbom.spdx.json", "dist/*.whl", "dist/*.tar.gz"} <= set(assets.splitlines())


def test_release_tag_must_match_installed_package(tmp_path):
    workflow = yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/ci.yml").read_text())
    step = next(
        step
        for step in workflow["jobs"]["package"]["steps"]
        if step.get("name") == "Verify release tag matches installed package"
    )
    (tmp_path / "jev-reflex-clean").symlink_to(sys.prefix, target_is_directory=True)
    for tag, expected in [(f"v{__version__}", 0), ("v999.0.0", 1)]:
        result = subprocess.run(
            ["/bin/bash", "-ec", step["run"]],
            cwd=tmp_path,
            env={**os.environ, "RELEASE_TAG": tag, "RUNNER_TEMP": str(tmp_path)},
        )
        assert result.returncode == expected


def test_release_signs_and_attests_the_built_digest(tmp_path):
    workflow = yaml.safe_load(
        (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    )
    image = "ghcr.io/madhumasa84/jrx-broker"
    digest = "sha256:" + "a" * 64
    reference = f"{image}@{digest}"
    log = tmp_path / "commands.jsonl"
    stub = (
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        "with open(os.environ['RELEASE_TEST_LOG'], 'a') as stream:\n"
        "    stream.write(json.dumps([pathlib.Path(sys.argv[0]).name, *sys.argv[1:]]) + '\\n')\n"
    )
    for name in ("syft", "cosign"):
        executable = tmp_path / name
        executable.write_text(stub)
        executable.chmod(0o700)
    (tmp_path / "sbom.spdx.json").write_text("{}")
    substitutions = {
        "${{ steps.build.outputs.digest }}": digest,
        "${{ github.ref_name }}": "v1.2.3",
        "${{ steps.meta.outputs.tags }}": f"{image}:v1.2.3\n{image}:1.2.3\n{image}:1.2",
    }
    for step in workflow["jobs"]["release"]["steps"]:
        if step.get("name") not in {
            "Generate SBOM",
            "Sign the published Docker image with keyless OIDC",
            "Attach SBOM to image and sign",
        }:
            continue
        assert "run" in step, "signing must execute the installed cosign CLI"
        script = step["run"]
        environment = {**os.environ, "PATH": str(tmp_path), "RELEASE_TEST_LOG": str(log)}
        for key, value in step.get("env", {}).items():
            for expression, replacement in substitutions.items():
                value = value.replace(expression, replacement)
            environment[key] = value
        for expression, replacement in substitutions.items():
            script = script.replace(expression, replacement)
        subprocess.run(["/bin/bash", "-e", "-c", script], cwd=tmp_path, env=environment, check=True)
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert calls == [
        ["syft", reference, "--output", "spdx-json", "--file", "sbom.spdx.json"],
        ["cosign", "sign", "--yes", reference],
        [
            "cosign",
            "attest",
            "--yes",
            "--type",
            "spdxjson",
            "--predicate",
            "sbom.spdx.json",
            reference,
        ],
    ]
