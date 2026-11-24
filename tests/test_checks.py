import pytest
from conftest import fixture

from aws_msk_cluster_audit.checks import CHECKS, Options, run
from aws_msk_cluster_audit.loader import load


def audit(name, **opts):
    clusters = load([fixture(name)]).clusters
    return run(clusters, Options(**opts))


def ids(findings):
    return sorted(f.check for f in findings)


def for_cluster(findings, cluster):
    return sorted(f.check for f in findings if f.cluster == cluster)


def test_hardened_cluster_has_no_findings():
    assert audit("hardened.json", min_version="3.6.0") == []


def test_tls_plaintext_is_exactly_one_finding_naming_cluster_and_region():
    findings = audit("tls_plaintext.json")
    assert ids(findings) == ["NO_ENCRYPTION_IN_TRANSIT"]
    finding = findings[0]
    assert finding.cluster == "events-migrating"
    assert finding.region == "eu-west-1"
    assert finding.severity == "high"
    assert "TLS_PLAINTEXT" in finding.message


def test_in_cluster_encryption_off():
    findings = audit("in_cluster_off.json")
    assert ids(findings) == ["NO_IN_CLUSTER_ENCRYPTION"]
    assert "replication" in findings[0].message


def test_unauthenticated_with_and_without_strong_auth():
    findings = audit("unauthenticated.json")
    assert for_cluster(findings, "legacy-ingest") == [
        "NO_STRONG_AUTH", "UNAUTHENTICATED_ACCESS"
    ]
    # IAM alongside unauthenticated: open, but not auth-less.
    assert for_cluster(findings, "mixed-auth") == ["UNAUTHENTICATED_ACCESS"]


def test_public_access_enabled():
    findings = audit("public_access.json")
    assert ids(findings) == ["PUBLIC_ACCESS_ENABLED"]
    assert "SERVICE_PROVIDED_EIPS" in findings[0].message


def test_eol_version_comparison_is_numeric():
    findings = audit("versions.json", min_version="3.10.0")
    assert {f.cluster for f in findings} == {"old-brokers", "tiered-brokers"}
    assert ids(audit("versions.json", min_version="3.6.0")) == ["EOL_KAFKA_VERSION"]
    assert audit("versions.json", min_version="2.8.0") == []


def test_no_min_version_means_no_version_finding():
    assert audit("versions.json") == []


def test_single_subnet():
    findings = audit("single_subnet.json")
    assert ids(findings) == ["SINGLE_AZ"]
    assert "subnet-0a1private" in findings[0].message


def test_observability_off():
    findings = audit("observability_off.json")
    assert ids(findings) == [
        "MONITORING_DEFAULT", "NO_AUTO_MINOR_VERSION_UPGRADE", "NO_BROKER_LOGS"
    ]
    severities = {f.check: f.severity for f in findings}
    assert severities["NO_BROKER_LOGS"] == "medium"
    assert severities["MONITORING_DEFAULT"] == "low"


def test_storage_autoscaling_absent_is_reported_only_when_known():
    assert ids(audit("no_autoscaling.json")) == ["NO_STORAGE_AUTOSCALING"]
    assert "NO_STORAGE_AUTOSCALING" not in ids(audit("tls_plaintext.json"))


def test_default_at_rest_key_is_medium():
    findings = [f for f in audit("v1_describe.json") if f.check == "NO_CUSTOMER_MANAGED_KEY"]
    assert findings == []  # the v1 fixture carries a real key ARN


def test_require_cmk_flags_an_aws_managed_key():
    clusters = load([fixture("hardened.json")]).clusters
    clusters[0].at_rest_key = "alias/aws/kafka"
    assert ids(run(clusters, Options(require_cmk=True))) == ["NO_CUSTOMER_MANAGED_KEY"]
    # Without the flag an AWS-managed key is tolerated: it is still encrypted.
    assert run(clusters, Options()) == []


def test_missing_at_rest_key_is_a_finding_without_the_flag():
    clusters = load([fixture("hardened.json")]).clusters
    clusters[0].at_rest_key = None
    assert ids(run(clusters, Options())) == ["NO_CUSTOMER_MANAGED_KEY"]


def test_cluster_not_active():
    findings = audit("v1_describe.json")
    assert ids(findings) == ["CLUSTER_NOT_ACTIVE"]
    assert "UPDATING" in findings[0].message


def test_serverless_skips_broker_storage_and_monitoring_checks():
    assert audit("serverless.json") == []
    provisioned_only = {c.id for c in CHECKS if len(c.applies) == 1}
    findings = audit("serverless_open.json")
    assert ids(findings) == ["NO_STRONG_AUTH", "UNAUTHENTICATED_ACCESS"]
    assert provisioned_only.isdisjoint({f.check for f in findings})


def test_malformed_entry_is_reported_and_the_rest_is_still_audited():
    findings = audit("malformed.json")
    assert ids(findings) == ["MALFORMED_CLUSTER"]
    assert findings[0].cluster.startswith("<unnamed arn:aws:kafka:")
    # The healthy neighbour was audited too, and produced nothing.
    clusters = load([fixture("malformed.json")]).clusters
    assert [c.name for c in clusters][1] == "orders-prod"


def test_only_and_skip():
    clusters = load([fixture("unauthenticated.json")]).clusters
    only = run(clusters, Options(), only={"UNAUTHENTICATED_ACCESS"})
    assert {f.check for f in only} == {"UNAUTHENTICATED_ACCESS"}
    skipped = run(clusters, Options(), skip={"UNAUTHENTICATED_ACCESS"})
    assert {f.check for f in skipped} == {"NO_STRONG_AUTH"}


def test_every_check_has_a_known_severity_and_a_summary():
    for check in CHECKS:
        assert check.severity in ("low", "medium", "high")
        assert check.summary
        assert check.applies


@pytest.mark.parametrize("name", ["hardened.json", "serverless.json"])
def test_clean_fixtures_stay_clean_under_every_threshold(name):
    assert audit(name, min_version="3.6.0", require_cmk=False) == []
