"""Read MSK JSON dumps off disk (or stdin) and flatten them into a Bundle."""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Iterable

from .model import PROVISIONED, SERVERLESS, Auth, BrokerLogs, Bundle, Cluster

#: ``arn:aws:kafka:eu-west-1:111122223333:cluster/prod/4b1b...``
_ARN_REGION = re.compile(r"^arn:[^:]*:kafka:([a-z0-9-]+):")
#: ``dump/eu-west-1-clusters.json`` -> ``eu-west-1``
_FILE_REGION = re.compile(r"\b((?:af|ap|ca|cn|eu|il|me|sa|us)-[a-z]+-\d)\b")

_CLUSTER_KEYS = ("ClusterInfoList", "ClusterInfo", "Clusters", "Cluster")
_AUTOSCALING_KEYS = ("ScalableTargets", "ScalingPolicies")
UNKNOWN_REGION = "unknown"


class InputError(Exception):
    """Raised when the input cannot be read or holds no MSK clusters."""


def _read_json(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: not valid JSON ({exc.msg} at line {exc.lineno})") from exc
    except OSError as exc:
        raise InputError(f"{path}: {exc.strerror or exc}") from exc


def _walk_inputs(inputs: Iterable[str]) -> list[tuple[str, Any]]:
    """Expand files, directories and ``-`` into ``(label, payload)`` pairs."""
    out: list[tuple[str, Any]] = []
    for item in inputs:
        if item == "-":
            raw = sys.stdin.read()
            try:
                out.append(("<stdin>", json.loads(raw)))
            except json.JSONDecodeError as exc:
                raise InputError(f"<stdin>: not valid JSON ({exc.msg})") from exc
            continue
        if os.path.isdir(item):
            found = sorted(
                os.path.join(root, name)
                for root, _dirs, files in os.walk(item)
                for name in files
                if name.endswith(".json")
            )
            if not found:
                raise InputError(f"{item}: no .json files in directory")
            out.extend((p, _read_json(p)) for p in found)
            continue
        if not os.path.exists(item):
            raise InputError(f"{item}: no such file or directory")
        out.append((item, _read_json(item)))
    if not out:
        raise InputError("no input given")
    return out


def _region_from(arn: str | None, source: str, hint: str | None) -> str:
    if hint:
        return hint
    if arn:
        m = _ARN_REGION.match(arn)
        if m:
            return m.group(1)
    m = _FILE_REGION.search(os.path.basename(source))
    if m:
        return m.group(1)
    return UNKNOWN_REGION


def _looks_like_cluster(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    return any(
        k in entry
        for k in ("ClusterArn", "ClusterName", "ClusterType", "Provisioned", "Serverless",
                  "CurrentBrokerSoftwareInfo", "BrokerNodeGroupInfo")
    )


def _collect_entries(payload: Any, source: str, hint: str | None,
                     out: list[tuple[Any, str, str | None]], state: dict) -> None:
    """Depth-first sweep for cluster entries, region keys and autoscaling data."""
    if isinstance(payload, list):
        for item in payload:
            _collect_entries(item, source, hint, out, state)
        return
    if not isinstance(payload, dict):
        return

    for key in _AUTOSCALING_KEYS:
        if key in payload:
            state["autoscaling_known"] = True
            for target in payload[key] or []:
                if isinstance(target, dict) and target.get("ResourceId"):
                    state["autoscaling_arns"].add(target["ResourceId"])

    matched = False
    for key in _CLUSTER_KEYS:
        if key in payload:
            matched = True
            value = payload[key]
            entries = value if isinstance(value, list) else [value]
            for entry in entries:
                if _looks_like_cluster(entry):
                    out.append((entry, source, hint))
    if matched:
        return

    if _looks_like_cluster(payload):
        out.append((payload, source, hint))
        return

    # A multi-region bundle: ``{"eu-west-1": {...}, "us-east-1": {...}}``.
    for key, value in payload.items():
        sub_hint = key if _FILE_REGION.fullmatch(key) else hint
        _collect_entries(value, source, sub_hint, out, state)


def _bool(node: Any, key: str = "Enabled") -> bool | None:
    if not isinstance(node, dict):
        return None
    value = node.get(key)
    return bool(value) if isinstance(value, bool) else None


def _auth_of(body: dict) -> Auth:
    node = body.get("ClientAuthentication")
    if not isinstance(node, dict):
        return Auth()
    sasl = node.get("Sasl") if isinstance(node.get("Sasl"), dict) else {}
    tls = node.get("Tls") if isinstance(node.get("Tls"), dict) else {}
    mtls = _bool(tls)
    if mtls is None and tls.get("CertificateAuthorityArnList"):
        # The v1 shape has no Enabled flag: a CA list is the switch.
        mtls = True
    return Auth(
        unauthenticated=_bool(node.get("Unauthenticated")),
        iam=_bool(sasl.get("Iam")),
        scram=_bool(sasl.get("Scram")),
        mtls=mtls,
    )


def _storage_autoscaling_of(body: dict, broker_group: dict) -> bool | None:
    """Inline autoscaling markers, when a dump carries them per cluster."""
    for holder in (body, broker_group):
        storage = holder.get("StorageInfo")
        if isinstance(storage, dict):
            ebs = storage.get("EbsStorageInfo")
            if isinstance(ebs, dict):
                for key in ("AutoScaling", "AutoScalingPolicy", "StorageAutoScaling"):
                    if key in ebs:
                        return bool(ebs[key])
        for key in ("StorageAutoScaling", "AutoScalingPolicy"):
            if key in holder:
                return bool(holder[key])
    return None


def _cluster_from(entry: dict, source: str, hint: str | None) -> Cluster:
    arn = entry.get("ClusterArn")
    name = entry.get("ClusterName")
    region = _region_from(arn, source, hint)

    declared = (entry.get("ClusterType") or "").upper()
    if declared == SERVERLESS or isinstance(entry.get("Serverless"), dict):
        cluster_type = SERVERLESS
    else:
        cluster_type = PROVISIONED

    # v2 nests the body; v1 keeps the same fields on the entry itself.
    body = entry.get("Serverless") if cluster_type == SERVERLESS else entry.get("Provisioned")
    if not isinstance(body, dict):
        body = entry

    cluster = Cluster(
        name=name if isinstance(name, str) and name.strip() else None,
        arn=arn if isinstance(arn, str) else None,
        region=region,
        source=source,
        cluster_type=cluster_type,
        state=entry.get("State") or body.get("State"),
        raw=entry,
    )
    cluster.malformed = cluster.name is None

    software = body.get("CurrentBrokerSoftwareInfo")
    if isinstance(software, dict):
        version = software.get("KafkaVersion")
        cluster.kafka_version = version if isinstance(version, str) else None

    encryption = body.get("EncryptionInfo")
    if isinstance(encryption, dict):
        transit = encryption.get("EncryptionInTransit")
        if isinstance(transit, dict):
            broker = transit.get("ClientBroker")
            cluster.client_broker = broker.upper() if isinstance(broker, str) else None
            if isinstance(transit.get("InCluster"), bool):
                cluster.in_cluster_encryption = transit["InCluster"]
        at_rest = encryption.get("EncryptionAtRest")
        if isinstance(at_rest, dict):
            key = at_rest.get("DataVolumeKMSKeyId")
            cluster.at_rest_key = key if isinstance(key, str) and key.strip() else None

    cluster.auth = _auth_of(body)

    broker_group = body.get("BrokerNodeGroupInfo")
    broker_group = broker_group if isinstance(broker_group, dict) else {}
    subnets = broker_group.get("ClientSubnets")
    if isinstance(subnets, list):
        cluster.client_subnets = [s for s in subnets if isinstance(s, str)]
    connectivity = broker_group.get("ConnectivityInfo")
    if isinstance(connectivity, dict):
        public = connectivity.get("PublicAccess")
        if isinstance(public, dict):
            kind = public.get("Type")
            cluster.public_access = kind.upper() if isinstance(kind, str) else None

    if cluster_type == PROVISIONED:
        count = body.get("NumberOfBrokerNodes")
        cluster.broker_count = count if isinstance(count, int) else None
        monitoring = body.get("EnhancedMonitoring")
        cluster.enhanced_monitoring = monitoring.upper() if isinstance(monitoring, str) else None
        logging = body.get("LoggingInfo")
        if isinstance(logging, dict):
            broker_logs = logging.get("BrokerLogs")
            if isinstance(broker_logs, dict):
                cluster.broker_logs = BrokerLogs(
                    cloudwatch=_bool(broker_logs.get("CloudWatchLogs")),
                    firehose=_bool(broker_logs.get("Firehose")),
                    s3=_bool(broker_logs.get("S3")),
                )
        if isinstance(body.get("AutoMinorVersionUpgrade"), bool):
            cluster.auto_minor_version_upgrade = body["AutoMinorVersionUpgrade"]
        cluster.storage_autoscaling = _storage_autoscaling_of(body, broker_group)
    elif isinstance(body.get("VpcConfigs"), list):
        subnet_ids: list[str] = []
        for vpc in body["VpcConfigs"]:
            if isinstance(vpc, dict) and isinstance(vpc.get("SubnetIds"), list):
                subnet_ids.extend(s for s in vpc["SubnetIds"] if isinstance(s, str))
        cluster.client_subnets = subnet_ids

    return cluster


def load(inputs: Iterable[str]) -> Bundle:
    """Load every input into one :class:`Bundle`.

    Raises :class:`InputError` when nothing readable or nothing MSK-shaped was
    found; the CLI turns that into exit code 2.
    """
    state: dict[str, Any] = {"autoscaling_known": False, "autoscaling_arns": set()}
    entries: list[tuple[Any, str, str | None]] = []
    sources: list[str] = []

    for source, payload in _walk_inputs(inputs):
        sources.append(source)
        _collect_entries(payload, source, None, entries, state)

    if not entries:
        raise InputError(
            "no MSK clusters found: expected list-clusters-v2 / describe-cluster-v2 output"
        )

    bundle = Bundle(sources=sources, autoscaling_known=bool(state["autoscaling_known"]))
    seen: set[str] = set()
    for entry, source, hint in entries:
        cluster = _cluster_from(entry, source, hint)
        key = cluster.arn or f"{cluster.region}/{cluster.name}/{source}"
        if cluster.arn and key in seen:
            # list-clusters-v2 and describe-cluster-v2 of the same cluster in
            # one dump is normal; audit it once.
            continue
        seen.add(key)
        if cluster.storage_autoscaling is None and bundle.autoscaling_known and cluster.arn:
            cluster.storage_autoscaling = cluster.arn in state["autoscaling_arns"]
        bundle.clusters.append(cluster)

    return bundle
