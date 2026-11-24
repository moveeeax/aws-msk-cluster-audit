"""The one cluster shape every check reads.

The MSK API hands back three different envelopes (``ClusterInfoList`` from
``list-clusters-v2``, ``ClusterInfo`` from ``describe-cluster-v2``, and the flat
v1 variant of both) and two different cluster bodies (``Provisioned`` and
``Serverless``).  The loader flattens all of that into :class:`Cluster` so the
checks never branch on envelope shape -- only on ``cluster_type`` and on whether
a field was actually present.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PROVISIONED = "PROVISIONED"
SERVERLESS = "SERVERLESS"

#: Fields that are absent on a serverless cluster are ``None``, never ``False``.
#: A check that cannot tell the difference would report a skip as a pass.


@dataclass
class Auth:
    """Client authentication, normalised across the two cluster bodies."""

    unauthenticated: bool | None = None
    iam: bool | None = None
    scram: bool | None = None
    mtls: bool | None = None

    @property
    def has_strong(self) -> bool:
        return bool(self.iam or self.scram or self.mtls)


@dataclass
class BrokerLogs:
    cloudwatch: bool | None = None
    firehose: bool | None = None
    s3: bool | None = None

    @property
    def known(self) -> bool:
        return any(v is not None for v in (self.cloudwatch, self.firehose, self.s3))

    @property
    def any_enabled(self) -> bool:
        return bool(self.cloudwatch or self.firehose or self.s3)


@dataclass
class Cluster:
    """A single MSK cluster as the checks see it."""

    name: str | None
    arn: str | None
    region: str
    source: str
    cluster_type: str = PROVISIONED
    state: str | None = None

    kafka_version: str | None = None
    client_broker: str | None = None
    in_cluster_encryption: bool | None = None
    at_rest_key: str | None = None

    auth: Auth = field(default_factory=Auth)
    public_access: str | None = None

    client_subnets: list[str] = field(default_factory=list)
    broker_count: int | None = None
    broker_logs: BrokerLogs = field(default_factory=BrokerLogs)
    enhanced_monitoring: str | None = None
    auto_minor_version_upgrade: bool | None = None

    storage_autoscaling: bool | None = None
    """``None`` when the dump carried no autoscaling information at all."""

    malformed: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        if self.name:
            return self.name
        if self.arn:
            return f"<unnamed {self.arn}>"
        return "<unnamed>"

    @property
    def is_serverless(self) -> bool:
        return self.cluster_type == SERVERLESS


@dataclass
class Bundle:
    """Everything one invocation loaded."""

    clusters: list[Cluster] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    autoscaling_known: bool = False
    """True once any file carried ``ScalableTargets``/``ScalingPolicies``."""
