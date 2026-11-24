import json

import pytest
from conftest import EXAMPLES, fixture

from aws_msk_cluster_audit.loader import InputError, load
from aws_msk_cluster_audit.model import PROVISIONED, SERVERLESS


def test_describe_cluster_v2_envelope():
    bundle = load([fixture("hardened.json")])
    assert len(bundle.clusters) == 1
    cluster = bundle.clusters[0]
    assert cluster.name == "orders-prod"
    assert cluster.cluster_type == PROVISIONED
    assert cluster.region == "eu-west-1"
    assert cluster.kafka_version == "3.6.0"
    assert cluster.client_broker == "TLS"
    assert cluster.in_cluster_encryption is True
    assert cluster.auth.iam is True
    assert cluster.auth.unauthenticated is False
    assert cluster.broker_logs.cloudwatch is True
    assert cluster.client_subnets == [
        "subnet-0a1private", "subnet-0b2private", "subnet-0c3private"
    ]
    assert bundle.autoscaling_known is True
    assert cluster.storage_autoscaling is True


def test_list_clusters_v2_envelope_with_several_clusters():
    bundle = load([fixture("unauthenticated.json")])
    assert [c.name for c in bundle.clusters] == ["legacy-ingest", "mixed-auth"]


def test_flat_v1_shape_is_read_without_a_provisioned_key():
    cluster = load([fixture("v1_describe.json")]).clusters[0]
    assert cluster.name == "v1-cluster"
    assert cluster.cluster_type == PROVISIONED
    assert cluster.region == "us-east-1"  # from the ARN
    assert cluster.state == "UPDATING"
    assert cluster.kafka_version == "3.6.0"


def test_serverless_shape_leaves_broker_fields_unset():
    cluster = load([fixture("serverless.json")]).clusters[0]
    assert cluster.cluster_type == SERVERLESS
    assert cluster.auth.iam is True
    # None, not False: the checks must be able to tell absent from disabled.
    assert cluster.broker_count is None
    assert cluster.enhanced_monitoring is None
    assert cluster.in_cluster_encryption is None
    assert cluster.broker_logs.known is False


def test_region_keyed_bundle():
    bundle = load([fixture("multi_region.json")])
    assert {c.name: c.region for c in bundle.clusters} == {
        "eu-orders": "eu-west-1",
        "us-orders": "us-east-1",
    }


def test_region_falls_back_to_the_filename(tmp_path):
    payload = json.loads(open(fixture("hardened.json"), encoding="utf-8").read())
    payload["ClusterInfo"].pop("ClusterArn")
    path = tmp_path / "ap-southeast-2-clusters.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert load([str(path)]).clusters[0].region == "ap-southeast-2"


def test_directory_input_loads_every_json_file():
    bundle = load([str(EXAMPLES)])
    names = sorted(c.name for c in bundle.clusters)
    assert names == [
        "events-migrating", "legacy-ingest", "orders-prod", "serverless-events", "us-orders"
    ]
    assert sorted({c.region for c in bundle.clusters}) == ["eu-west-1", "us-east-1"]


def test_stdin_input(monkeypatch):
    raw = open(fixture("hardened.json"), encoding="utf-8").read()

    class FakeStdin:
        def read(self):
            return raw

    monkeypatch.setattr("sys.stdin", FakeStdin())
    assert load(["-"]).clusters[0].name == "orders-prod"


def test_same_cluster_in_list_and_describe_output_is_audited_once(tmp_path):
    payload = json.loads(open(fixture("hardened.json"), encoding="utf-8").read())
    entry = payload["ClusterInfo"]
    combined = {"ClusterInfoList": [entry], "ClusterInfo": entry}
    path = tmp_path / "eu-west-1-both.json"
    path.write_text(json.dumps(combined), encoding="utf-8")
    assert len(load([str(path)]).clusters) == 1


def test_missing_cluster_name_is_kept_as_malformed():
    bundle = load([fixture("malformed.json")])
    assert len(bundle.clusters) == 2
    assert bundle.clusters[0].malformed is True
    assert bundle.clusters[0].name is None
    assert bundle.clusters[1].malformed is False


def test_autoscaling_is_unknown_without_scalable_targets():
    bundle = load([fixture("tls_plaintext.json")])
    assert bundle.autoscaling_known is False
    assert bundle.clusters[0].storage_autoscaling is None


def test_empty_scalable_targets_means_known_and_absent():
    bundle = load([fixture("no_autoscaling.json")])
    assert bundle.autoscaling_known is True
    assert bundle.clusters[0].storage_autoscaling is False


def test_non_msk_input_raises():
    with pytest.raises(InputError, match="no MSK clusters"):
        load([fixture("not_msk.json")])


def test_invalid_json_raises():
    with pytest.raises(InputError, match="not valid JSON"):
        load([fixture("broken.json.txt")])


def test_missing_path_raises():
    with pytest.raises(InputError, match="no such file"):
        load(["/nonexistent/dump.json"])


def test_empty_directory_raises(tmp_path):
    with pytest.raises(InputError, match="no .json files"):
        load([str(tmp_path)])
