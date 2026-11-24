# aws-msk-cluster-audit

[![ci](https://github.com/moveeeax/aws-msk-cluster-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-msk-cluster-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Audit Amazon MSK clusters from `describe-cluster-v2` / `list-clusters-v2` JSON. No AWS calls, no
credentials, no SDK — it reads a dump, so it runs in CI next to the Terraform that created the
cluster.

MSK settings are chosen once, on launch day, and most of them cannot be changed later without a
rolling update nobody schedules. That makes the launch-day compromises permanent by default:
`clientBroker` left at `TLS_PLAINTEXT` for one client that could not do TLS in week one,
`unauthenticated` access enabled for a laptop test, `enhancedMonitoring` at `DEFAULT` so partition
skew is invisible until a broker fills its disk, `loggingInfo` with all three destinations off so a
crash loop leaves nothing to read. None of it fails a health check. All of it is a field in two
describe calls.

## Usage

```console
$ aws kafka list-clusters-v2 --region eu-west-1 > dump/eu-west-1-clusters.json
$ aws-msk-cluster-audit --input dump/ --min-version 3.6.0 --severity medium
SEVERITY  REGION     CLUSTER           CHECK                     DETAIL
--------  ---------  ----------------  ------------------------  ------
HIGH      eu-west-1  events-migrating  NO_ENCRYPTION_IN_TRANSIT  encryptionInTransit.clientBroker is TLS_PLAINTEXT — clients may connect without TLS
HIGH      eu-west-1  legacy-ingest     NO_ENCRYPTION_IN_TRANSIT  encryptionInTransit.clientBroker is TLS_PLAINTEXT — clients may connect without TLS
HIGH      eu-west-1  legacy-ingest     NO_IN_CLUSTER_ENCRYPTION  encryptionInTransit.inCluster is false — broker-to-broker replication is plaintext
HIGH      eu-west-1  legacy-ingest     NO_STRONG_AUTH            no IAM, SASL/SCRAM or mTLS authentication configured
HIGH      eu-west-1  legacy-ingest     PUBLIC_ACCESS_ENABLED     connectivityInfo.publicAccess.type is SERVICE_PROVIDED_EIPS — brokers have public endpoints
HIGH      eu-west-1  legacy-ingest     SINGLE_AZ                 brokers are placed in a single client subnet (subnet-0a1private) — one AZ failure takes the cluster
HIGH      eu-west-1  legacy-ingest     UNAUTHENTICATED_ACCESS    clientAuthentication.unauthenticated is enabled — anything that can reach the brokers can produce and consume
MEDIUM    eu-west-1  legacy-ingest     EOL_KAFKA_VERSION         Kafka 2.8.1 is older than the required 3.6.0
MEDIUM    eu-west-1  legacy-ingest     NO_BROKER_LOGS            every loggingInfo.brokerLogs destination is disabled — a broker crash loop leaves nothing to read afterwards
MEDIUM    us-east-1  us-orders         EOL_KAFKA_VERSION         Kafka 3.4.0 is older than the required 3.6.0

10 finding(s) across 5 cluster(s): 7 high, 3 medium, 0 low.
```

That output is the dump committed under `examples/dump`, so the commands below work out of the box:

```console
$ aws-msk-cluster-audit --input examples/dump --min-version 3.6.0
$ aws-msk-cluster-audit --input examples/dump --format json --fail-on high --min-version 3.6.0
$ aws-msk-cluster-audit --input examples/dump --only NO_ENCRYPTION_IN_TRANSIT,UNAUTHENTICATED_ACCESS --region eu-west-1
$ aws kafka describe-cluster-v2 --cluster-arn "$ARN" | aws-msk-cluster-audit --format csv
```

## Install

```console
$ pip install git+https://github.com/moveeeax/aws-msk-cluster-audit
```

Python 3.11 or newer, standard library only. Or run it straight out of a checkout with
`python -m aws_msk_cluster_audit`.

## Checks

| Check | Severity | Applies to | What it means |
| --- | --- | --- | --- |
| `NO_ENCRYPTION_IN_TRANSIT` | high | both | `clientBroker` is `PLAINTEXT` or `TLS_PLAINTEXT` |
| `NO_IN_CLUSTER_ENCRYPTION` | high | both | `inCluster` is false — replication traffic is plaintext |
| `UNAUTHENTICATED_ACCESS` | high | both | `clientAuthentication.unauthenticated` is enabled |
| `NO_STRONG_AUTH` | high | both | no IAM, SASL/SCRAM or mTLS configured |
| `PUBLIC_ACCESS_ENABLED` | high | provisioned | `connectivityInfo.publicAccess.type` is not `DISABLED` |
| `SINGLE_AZ` | high | provisioned | brokers placed in fewer than two client subnets |
| `NO_CUSTOMER_MANAGED_KEY` | medium | provisioned | no `dataVolumeKMSKeyId`, or an AWS-managed key under `--require-cmk` |
| `EOL_KAFKA_VERSION` | medium | provisioned | broker version below `--min-version` |
| `NO_BROKER_LOGS` | medium | provisioned | every `loggingInfo.brokerLogs` destination is disabled |
| `CLUSTER_NOT_ACTIVE` | medium | both | `state` is not `ACTIVE`, so the audit read a cluster mid-change |
| `MALFORMED_CLUSTER` | medium | both | cluster entry with no `ClusterName` |
| `MONITORING_DEFAULT` | low | provisioned | `enhancedMonitoring` is `DEFAULT` |
| `NO_STORAGE_AUTOSCALING` | low | provisioned | no `kafka:broker-storage` scalable target for the cluster |
| `NO_AUTO_MINOR_VERSION_UPGRADE` | low | provisioned | `autoMinorVersionUpgrade` is false |

`aws-msk-cluster-audit --list-checks` prints the same table.

## How it works

Three envelopes come out of the MSK API — `ClusterInfoList` from `list-clusters-v2`, `ClusterInfo`
from `describe-cluster-v2`, and the flat v1 variant of both — wrapping two different cluster bodies,
`Provisioned` and `Serverless`. The loader flattens all of that into one model, so every check is a
pure function of a `Cluster` and a threshold, and nothing branches on envelope shape.

Two decisions that matter more than they look:

**A skipped check is never a pass.** Every optional field is `None` when it was absent and `False`
only when the dump actually said `false`. A serverless cluster has no broker count, no storage and
no monitoring level, so broker, storage and monitoring checks are skipped for it rather than
reported as clean — and its auth and encryption are still audited.

**Kafka versions are compared as tuples.** `3.10.0` sorts below `3.6.0` as a string, which is how an
audit tool ends up calling a current cluster end-of-life. `parse()` turns `2.8.2.tiered` into
`(2, 8, 2)` and the comparison is numeric; an unparseable version skips the check instead of
guessing.

Storage autoscaling is not in `describe-cluster-v2` at all — it is an Application Auto Scaling
target. Feed the dump
`aws application-autoscaling describe-scalable-targets --service-namespace kafka` alongside the
cluster JSON and `NO_STORAGE_AUTOSCALING` matches targets to cluster ARNs. Without that file the
check stays silent instead of flagging every cluster.

## Inputs

A file, a directory of `.json` dumps, `-` for stdin, or `--input` repeated. Regions are resolved
from the cluster ARN, then from a `eu-west-1` in the filename, and an explicitly region-keyed bundle
wins over both:

```json
{
  "eu-west-1": { "ClusterInfoList": [ ... ] },
  "us-east-1": { "ClusterInfoList": [ ... ] }
}
```

The same cluster appearing in both `list-clusters-v2` and `describe-cluster-v2` output is audited
once, by ARN.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | nothing at or above `--fail-on` (default `medium`) |
| 1 | at least one reported finding at or above `--fail-on` |
| 2 | input unreadable, or no MSK clusters in it |

`--severity` is the display floor, `--fail-on` is the exit-code threshold; `--fail-on none` reports
without ever failing a build.

## In CI

```yaml
- name: Audit MSK
  run: |
    mkdir -p dump
    for region in eu-west-1 us-east-1; do
      aws kafka list-clusters-v2 --region "$region" > "dump/$region-clusters.json"
      aws application-autoscaling describe-scalable-targets \
        --service-namespace kafka --region "$region" > "dump/$region-autoscaling.json"
    done
    aws-msk-cluster-audit --input dump --min-version 3.6.0 --fail-on high
```

Read-only AWS calls produce the dump; the audit itself needs no credentials, which means a pull
request from a fork can run it against a committed fixture.

## Development

```console
$ python -m venv .venv && . .venv/bin/activate
$ pip install -e '.[dev]'
$ pytest -q
```

Fixtures under `tests/fixtures/` are real API shapes: a hardened cluster, a `TLS_PLAINTEXT` one, an
unauthenticated one, one with IAM alongside unauthenticated, a public-access one, three Kafka
versions, a single-subnet one, a serverless pair, a flat v1 dump, a region-keyed bundle, an entry
with no `ClusterName` and a truncated file.

## License

MIT
