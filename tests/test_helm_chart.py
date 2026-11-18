import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from jev_reflex.config import ReflexConfig

HELM_BIN = shutil.which("helm")
CHART_DIR = Path(__file__).resolve().parents[1] / "helm" / "jrx-broker"


def _render_chart(*args: str) -> list[dict]:
    if not HELM_BIN:
        pytest.skip("helm CLI not found in PATH")
    cmd = [HELM_BIN, "template", "test-release", str(CHART_DIR), *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    docs = list(yaml.safe_load_all(proc.stdout))
    return [doc for doc in docs if doc is not None]


@pytest.mark.skipif(not HELM_BIN, reason="helm CLI required")
def test_helm_default_deployment_mount_paths():
    docs = _render_chart()
    deployments = [d for d in docs if d.get("kind") == "Deployment"]
    assert len(deployments) == 1
    dep = deployments[0]
    container = dep["spec"]["template"]["spec"]["containers"][0]
    mounts = {m["name"]: m["mountPath"] for m in container["volumeMounts"]}

    # Verify tmp and data do not collide
    assert mounts["tmp"] == "/tmp"
    assert mounts["data"] == "/home/jrx/.jev-reflex"
    assert mounts["tmp"] != mounts["data"]

    # Verify default data volume is an emptyDir when data persistence is disabled
    volumes = {v["name"]: v for v in dep["spec"]["template"]["spec"]["volumes"]}
    assert "emptyDir" in volumes["tmp"]
    assert "emptyDir" in volumes["data"]


@pytest.mark.skipif(not HELM_BIN, reason="helm CLI required")
def test_helm_deployment_with_persistent_data_volume():
    docs = _render_chart("--set", "volumes.data.enabled=true")
    pvcs = [d for d in docs if d.get("kind") == "PersistentVolumeClaim"]
    assert len(pvcs) == 1
    pvc = pvcs[0]
    assert pvc["metadata"]["name"] == "test-release-jrx-broker-data"

    deployments = [d for d in docs if d.get("kind") == "Deployment"]
    dep = deployments[0]
    volumes = {v["name"]: v for v in dep["spec"]["template"]["spec"]["volumes"]}

    # data volume must use persistentVolumeClaim referencing the generated claim, NOT emptyDir
    assert "persistentVolumeClaim" in volumes["data"]
    assert volumes["data"]["persistentVolumeClaim"]["claimName"] == "test-release-jrx-broker-data"
    assert "emptyDir" not in volumes["data"]


@pytest.mark.skipif(not HELM_BIN, reason="helm CLI required")
def test_helm_deployment_with_existing_claim():
    docs = _render_chart(
        "--set",
        "volumes.data.enabled=true",
        "--set",
        "volumes.data.existingClaim=custom-pvc-claim",
    )
    # When existingClaim is provided, no new PVC template should be rendered
    pvcs = [d for d in docs if d.get("kind") == "PersistentVolumeClaim"]
    assert len(pvcs) == 0

    deployments = [d for d in docs if d.get("kind") == "Deployment"]
    dep = deployments[0]
    volumes = {v["name"]: v for v in dep["spec"]["template"]["spec"]["volumes"]}
    assert volumes["data"]["persistentVolumeClaim"]["claimName"] == "custom-pvc-claim"


@pytest.mark.skipif(not HELM_BIN, reason="helm CLI required")
def test_helm_statefulset_with_data_volume_claim_template():
    docs = _render_chart(
        "--set",
        "kind=StatefulSet",
        "--set",
        "volumes.data.enabled=true",
    )
    statefulsets = [d for d in docs if d.get("kind") == "StatefulSet"]
    assert len(statefulsets) == 1
    sts = statefulsets[0]

    # StatefulSet must have volumeClaimTemplates with name 'data'
    vcts = sts["spec"].get("volumeClaimTemplates", [])
    assert any(vct["metadata"]["name"] == "data" for vct in vcts)

    # volumes in pod spec must NOT duplicate 'data' when volumeClaimTemplates is used
    volumes = {v["name"]: v for v in sts["spec"]["template"]["spec"]["volumes"]}
    assert "data" not in volumes

    # container volumeMounts still mount 'data' at /home/jrx/.jev-reflex and 'tmp' at /tmp
    container = sts["spec"]["template"]["spec"]["containers"][0]
    mounts = {m["name"]: m["mountPath"] for m in container["volumeMounts"]}
    assert mounts["tmp"] == "/tmp"
    assert mounts["data"] == "/home/jrx/.jev-reflex"


@pytest.mark.parametrize("kind", ["Deployment", "StatefulSet"])
def test_helm_broker_tls_configuration_and_local_probes(kind):
    docs = _render_chart(
        "--set",
        f"kind={kind},config.jev.transport=broker-tls,config.policy.allowHoldOverride=true",
        "--set",
        "config.jev.brokerTls.listenAddr=0.0.0.0:9443",
        "--set",
        "volumes.tls.enabled=true,secrets.tls.existingSecret=test-tls",
        "--set",
        "secrets.tls.certKey=server-cert,secrets.tls.keyKey=server-key,secrets.tls.caKey=client-ca",
        "--set-json",
        "config.holdOn=[]",
        "--set-json",
        "config.reviewOn=[]",
    )
    by_kind = {doc["kind"]: doc for doc in docs}
    config = ReflexConfig.model_validate(
        yaml.safe_load(by_kind["ConfigMap"]["data"]["reflex.yaml"])
    )
    assert config.policy.allow_hold_override is True
    assert config.hold_on == config.review_on == []
    assert config.jev.socket == "/tmp/jrx/reflex.sock"
    assert config.jev.broker_tls.listen_addr == "0.0.0.0:9443"

    pod = by_kind[kind]["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert next(p for p in container["ports"] if p["name"] == "broker")["containerPort"] == 9443
    for probe in ("livenessProbe", "readinessProbe"):
        assert container[probe]["exec"]["command"] == [
            "jrx",
            "broker",
            "status",
            "--local",
            "--json",
        ]
    assert pod["securityContext"]["fsGroup"] == 1000
    secret = next(volume["secret"] for volume in pod["volumes"] if volume["name"] == "tls")
    assert secret["secretName"] == "test-tls"
    assert secret["defaultMode"] == 0o440
    assert {item["key"]: item["path"] for item in secret["items"]} == {
        "server-cert": "tls.crt",
        "server-key": "tls.key",
        "client-ca": "ca.crt",
    }


@pytest.mark.parametrize("kind", ["Deployment", "StatefulSet"])
def test_helm_autoscaling_targets_the_selected_workload(kind):
    docs = _render_chart("--set", f"kind={kind},autoscaling.enabled=true")
    by_kind = {doc["kind"]: doc for doc in docs}
    workload = by_kind[kind]
    assert "replicas" not in workload["spec"]
    scaling = by_kind["HorizontalPodAutoscaler"]["spec"]
    assert scaling["scaleTargetRef"] == {
        "apiVersion": "apps/v1",
        "kind": kind,
        "name": workload["metadata"]["name"],
    }
    assert {metric["resource"]["name"] for metric in scaling["metrics"]} == {"cpu", "memory"}
