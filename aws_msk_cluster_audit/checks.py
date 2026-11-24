"""One pure function per check, over the normalised cluster model.

Every check returns a message or ``None``.  ``None`` means *skipped*, and a skip
is never rendered as a pass: a serverless cluster has no broker storage, and a
dump that never carried autoscaling data cannot be used to claim autoscaling is
missing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from .model import PROVISIONED, SERVERLESS, Cluster
from .version import is_older

SEVERITIES = ("low", "medium", "high")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}

#: An AWS-managed key, as opposed to one you can set a policy on.
_AWS_MANAGED_KEY = re.compile(r"alias/aws/|:alias/aws/")

PLAINTEXT_BROKER = {"PLAINTEXT", "TLS_PLAINTEXT"}


@dataclass(frozen=True)
class Options:
    min_version: str | None = None
    require_cmk: bool = False


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    region: str
    cluster: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "check": self.check,
            "severity": self.severity,
            "region": self.region,
            "cluster": self.cluster,
            "message": self.message,
        }


@dataclass(frozen=True)
class Check:
    id: str
    severity: str
    applies: tuple[str, ...]
    fn: Callable[[Cluster, Options], str | None]
    summary: str


# --------------------------------------------------------------------------
# checks
# --------------------------------------------------------------------------

def _malformed(cluster: Cluster, _opts: Options) -> str | None:
    if not cluster.malformed:
        return None
    arn = cluster.arn or "no ClusterArn either"
    return f"cluster entry has no ClusterName ({arn}) — audited from {cluster.source}"


def _not_active(cluster: Cluster, _opts: Options) -> str | None:
    if cluster.state is None or cluster.state.upper() == "ACTIVE":
        return None
    return (
        f"state is {cluster.state}, not ACTIVE — the settings below were read "
        "from a cluster mid-change and may not be what it lands on"
    )


def _no_encryption_in_transit(cluster: Cluster, _opts: Options) -> str | None:
    if cluster.client_broker is None:
        return None
    if cluster.client_broker not in PLAINTEXT_BROKER:
        return None
    detail = (
        "clients may connect without TLS"
        if cluster.client_broker == "TLS_PLAINTEXT"
        else "clients must connect without TLS"
    )
    return f"encryptionInTransit.clientBroker is {cluster.client_broker} — {detail}"


def _no_in_cluster_encryption(cluster: Cluster, _opts: Options) -> str | None:
    if cluster.in_cluster_encryption is not False:
        return None
    return "encryptionInTransit.inCluster is false — broker-to-broker replication is plaintext"


def _no_customer_managed_key(cluster: Cluster, opts: Options) -> str | None:
    if cluster.at_rest_key is None:
        return "no encryptionAtRest.dataVolumeKMSKeyId — data volumes use the default MSK key"
    if opts.require_cmk and _AWS_MANAGED_KEY.search(cluster.at_rest_key):
        return (
            f"encryptionAtRest key {cluster.at_rest_key} is AWS-managed — "
            "--require-cmk asked for a customer-managed key"
        )
    return None


def _unauthenticated_access(cluster: Cluster, _opts: Options) -> str | None:
    if cluster.auth.unauthenticated is not True:
        return None
    return (
        "clientAuthentication.unauthenticated is enabled — anything that can reach "
        "the brokers can produce and consume"
    )


def _no_strong_auth(cluster: Cluster, _opts: Options) -> str | None:
    if cluster.auth.has_strong:
        return None
    if (cluster.auth.unauthenticated, cluster.auth.iam,
            cluster.auth.scram, cluster.auth.mtls) == (None, None, None, None):
        return None  # no ClientAuthentication block at all: nothing to judge
    return "no IAM, SASL/SCRAM or mTLS authentication configured"


def _public_access(cluster: Cluster, _opts: Options) -> str | None:
    if cluster.public_access is None or cluster.public_access == "DISABLED":
        return None
    return (
        f"connectivityInfo.publicAccess.type is {cluster.public_access} — "
        "brokers have public endpoints"
    )


def _eol_kafka_version(cluster: Cluster, opts: Options) -> str | None:
    if not opts.min_version:
        return None
    older = is_older(cluster.kafka_version, opts.min_version)
    if older is not True:
        return None
    return (
        f"Kafka {cluster.kafka_version} is older than the required "
        f"{opts.min_version}"
    )


def _single_az(cluster: Cluster, _opts: Options) -> str | None:
    if not cluster.client_subnets:
        return None
    unique = sorted(set(cluster.client_subnets))
    if len(unique) >= 2:
        return None
    return (
        f"brokers are placed in a single client subnet ({unique[0]}) — "
        "one AZ failure takes the cluster"
    )


def _no_broker_logs(cluster: Cluster, _opts: Options) -> str | None:
    logs = cluster.broker_logs
    if not logs.known:
        return None
    if logs.any_enabled:
        return None
    return (
        "every loggingInfo.brokerLogs destination is disabled — a broker crash "
        "loop leaves nothing to read afterwards"
    )


def _monitoring_default(cluster: Cluster, _opts: Options) -> str | None:
    if cluster.enhanced_monitoring != "DEFAULT":
        return None
    return (
        "enhancedMonitoring is DEFAULT — no per-partition metrics, so partition "
        "skew is invisible until a broker fills its disk"
    )


def _no_storage_autoscaling(cluster: Cluster, _opts: Options) -> str | None:
    if cluster.storage_autoscaling is not False:
        return None
    return "no storage autoscaling target for the cluster — broker volumes are fixed size"


def _no_auto_minor_upgrade(cluster: Cluster, _opts: Options) -> str | None:
    if cluster.auto_minor_version_upgrade is not False:
        return None
    return "autoMinorVersionUpgrade is false — broker patches need a manual rolling update"


PROV_ONLY = (PROVISIONED,)
BOTH = (PROVISIONED, SERVERLESS)

CHECKS: tuple[Check, ...] = (
    Check("MALFORMED_CLUSTER", "medium", BOTH, _malformed,
          "cluster entry with no ClusterName"),
    Check("CLUSTER_NOT_ACTIVE", "medium", BOTH, _not_active,
          "cluster state is not ACTIVE"),
    Check("NO_ENCRYPTION_IN_TRANSIT", "high", BOTH, _no_encryption_in_transit,
          "clientBroker allows PLAINTEXT"),
    Check("NO_IN_CLUSTER_ENCRYPTION", "high", BOTH, _no_in_cluster_encryption,
          "broker-to-broker traffic is plaintext"),
    Check("UNAUTHENTICATED_ACCESS", "high", BOTH, _unauthenticated_access,
          "unauthenticated client access is enabled"),
    Check("NO_STRONG_AUTH", "high", BOTH, _no_strong_auth,
          "no IAM, SCRAM or mTLS auth configured"),
    Check("PUBLIC_ACCESS_ENABLED", "high", PROV_ONLY, _public_access,
          "brokers have public endpoints"),
    Check("NO_CUSTOMER_MANAGED_KEY", "medium", PROV_ONLY, _no_customer_managed_key,
          "at-rest encryption uses the default key"),
    Check("EOL_KAFKA_VERSION", "medium", PROV_ONLY, _eol_kafka_version,
          "Kafka version below --min-version"),
    Check("SINGLE_AZ", "high", PROV_ONLY, _single_az,
          "brokers in a single client subnet"),
    Check("NO_BROKER_LOGS", "medium", PROV_ONLY, _no_broker_logs,
          "no broker log destination enabled"),
    Check("MONITORING_DEFAULT", "low", PROV_ONLY, _monitoring_default,
          "enhancedMonitoring left at DEFAULT"),
    Check("NO_STORAGE_AUTOSCALING", "low", PROV_ONLY, _no_storage_autoscaling,
          "no storage autoscaling target"),
    Check("NO_AUTO_MINOR_VERSION_UPGRADE", "low", PROV_ONLY, _no_auto_minor_upgrade,
          "autoMinorVersionUpgrade is false"),
)

CHECK_IDS = tuple(c.id for c in CHECKS)
CHECKS_BY_ID = {c.id: c for c in CHECKS}


def run(clusters: list[Cluster], options: Options | None = None,
        only: set[str] | None = None, skip: set[str] | None = None) -> list[Finding]:
    """Run the enabled checks over every cluster, in check order."""
    opts = options or Options()
    findings: list[Finding] = []
    for cluster in clusters:
        for check in CHECKS:
            if only and check.id not in only:
                continue
            if skip and check.id in skip:
                continue
            if cluster.cluster_type not in check.applies:
                continue
            message = check.fn(cluster, opts)
            if message is None:
                continue
            findings.append(Finding(check.id, check.severity, cluster.region,
                                    cluster.label, message))
    return findings


def at_or_above(findings: list[Finding], floor: str) -> list[Finding]:
    rank = SEVERITY_RANK[floor]
    return [f for f in findings if SEVERITY_RANK[f.severity] >= rank]
