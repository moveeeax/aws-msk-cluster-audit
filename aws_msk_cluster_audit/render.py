"""Table, JSON and CSV output."""

from __future__ import annotations

import csv
import io
import json

from .checks import SEVERITIES, Finding
from .model import Cluster

COLUMNS = ("SEVERITY", "REGION", "CLUSTER", "CHECK", "DETAIL")


def _summary(findings: list[Finding], clusters: list[Cluster]) -> dict:
    by_severity = {name: 0 for name in SEVERITIES}
    for finding in findings:
        by_severity[finding.severity] += 1
    return {
        "clusters_audited": len(clusters),
        "provisioned": sum(1 for c in clusters if not c.is_serverless),
        "serverless": sum(1 for c in clusters if c.is_serverless),
        "regions": sorted({c.region for c in clusters}),
        "findings": len(findings),
        "by_severity": by_severity,
    }


def as_table(findings: list[Finding], clusters: list[Cluster]) -> str:
    counts = _summary(findings, clusters)
    if not findings:
        return (
            f"No findings. Audited {counts['clusters_audited']} cluster(s) in "
            f"{len(counts['regions'])} region(s): {', '.join(counts['regions'])}."
        )

    rows = [(f.severity.upper(), f.region, f.cluster, f.check, f.message) for f in findings]
    widths = [max(len(COLUMNS[i]), max(len(r[i]) for r in rows)) for i in range(len(COLUMNS) - 1)]

    lines = []
    header = "  ".join(COLUMNS[i].ljust(widths[i]) for i in range(len(widths))) + "  " + COLUMNS[-1]
    lines.append(header)
    lines.append("  ".join("-" * w for w in widths) + "  " + "-" * len(COLUMNS[-1]))
    for row in rows:
        prefix = "  ".join(row[i].ljust(widths[i]) for i in range(len(widths)))
        lines.append(f"{prefix}  {row[-1]}")

    tally = ", ".join(
        f"{counts['by_severity'][name]} {name}" for name in reversed(SEVERITIES)
    )
    lines.append("")
    lines.append(
        f"{counts['findings']} finding(s) across {counts['clusters_audited']} "
        f"cluster(s): {tally}."
    )
    return "\n".join(lines)


def as_json(findings: list[Finding], clusters: list[Cluster]) -> str:
    return json.dumps(
        {
            "summary": _summary(findings, clusters),
            "findings": [f.as_dict() for f in findings],
        },
        indent=2,
        sort_keys=False,
    )


def as_csv(findings: list[Finding], _clusters: list[Cluster]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow([c.lower() for c in COLUMNS])
    for f in findings:
        writer.writerow([f.severity, f.region, f.cluster, f.check, f.message])
    return buf.getvalue().rstrip("\n")


RENDERERS = {"table": as_table, "json": as_json, "csv": as_csv}


def render(fmt: str, findings: list[Finding], clusters: list[Cluster]) -> str:
    return RENDERERS[fmt](findings, clusters)
