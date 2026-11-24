import csv
import io
import json

from conftest import EXAMPLES, fixture

from aws_msk_cluster_audit.cli import EXIT_FINDINGS, EXIT_INPUT, EXIT_OK, main


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_hardened_exits_zero_with_a_no_findings_line():
    code, out, _ = run_cli("--input", fixture("hardened.json"), "--min-version", "3.6.0")
    assert code == EXIT_OK
    assert "No findings" in out
    assert "orders-prod" not in out


def test_high_finding_exits_one_under_the_default_fail_on():
    code, out, _ = run_cli("--input", fixture("tls_plaintext.json"))
    assert code == EXIT_FINDINGS
    assert "NO_ENCRYPTION_IN_TRANSIT" in out
    assert "events-migrating" in out
    assert "eu-west-1" in out


def test_fail_on_none_still_prints_but_exits_zero():
    code, out, _ = run_cli("--input", fixture("tls_plaintext.json"), "--fail-on", "none")
    assert code == EXIT_OK
    assert "NO_ENCRYPTION_IN_TRANSIT" in out


def test_fail_on_high_ignores_low_findings():
    code, out, _ = run_cli("--input", fixture("observability_off.json"), "--fail-on", "high")
    assert code == EXIT_OK
    assert "MONITORING_DEFAULT" in out


def test_severity_floor_filters_output():
    code, out, _ = run_cli("--input", fixture("observability_off.json"), "--severity", "medium")
    assert "MONITORING_DEFAULT" not in out
    assert "NO_BROKER_LOGS" in out
    assert code == EXIT_FINDINGS


def test_json_output_is_parseable_and_summarises():
    code, out, _ = run_cli("--input", str(EXAMPLES), "--format", "json",
                           "--min-version", "3.6.0")
    payload = json.loads(out)
    assert code == EXIT_FINDINGS
    assert payload["summary"]["clusters_audited"] == 5
    assert payload["summary"]["serverless"] == 1
    assert payload["summary"]["regions"] == ["eu-west-1", "us-east-1"]
    assert payload["summary"]["findings"] == len(payload["findings"])
    checks = {f["check"] for f in payload["findings"]}
    assert {"NO_ENCRYPTION_IN_TRANSIT", "UNAUTHENTICATED_ACCESS", "EOL_KAFKA_VERSION"} <= checks


def test_findings_are_sorted_high_severity_first():
    _, out, _ = run_cli("--input", str(EXAMPLES), "--format", "json", "--min-version", "3.6.0")
    severities = [f["severity"] for f in json.loads(out)["findings"]]
    rank = {"high": 0, "medium": 1, "low": 2}
    assert severities == sorted(severities, key=lambda s: rank[s])


def test_csv_output_has_a_header_and_one_row_per_finding():
    _, out, _ = run_cli("--input", fixture("observability_off.json"), "--format", "csv")
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0] == ["severity", "region", "cluster", "check", "detail"]
    assert len(rows) == 4
    assert {r[3] for r in rows[1:]} == {
        "NO_BROKER_LOGS", "MONITORING_DEFAULT", "NO_AUTO_MINOR_VERSION_UPGRADE"
    }


def test_only_scopes_the_checks():
    _, out, _ = run_cli("--input", str(EXAMPLES), "--format", "json",
                        "--only", "NO_ENCRYPTION_IN_TRANSIT,UNAUTHENTICATED_ACCESS")
    checks = {f["check"] for f in json.loads(out)["findings"]}
    assert checks == {"NO_ENCRYPTION_IN_TRANSIT", "UNAUTHENTICATED_ACCESS"}


def test_region_scopes_the_clusters():
    _, out, _ = run_cli("--input", str(EXAMPLES), "--format", "json",
                        "--region", "us-east-1", "--min-version", "3.6.0")
    payload = json.loads(out)
    assert payload["summary"]["clusters_audited"] == 1
    assert {f["region"] for f in payload["findings"]} == {"us-east-1"}


def test_cluster_scopes_by_name():
    _, out, _ = run_cli("--input", str(EXAMPLES), "--format", "json",
                        "--cluster", "legacy-ingest")
    payload = json.loads(out)
    assert payload["summary"]["clusters_audited"] == 1
    assert {f["cluster"] for f in payload["findings"]} == {"legacy-ingest"}


def test_unknown_check_id_is_rejected_by_the_parser():
    out, err = io.StringIO(), io.StringIO()
    try:
        main(["--input", fixture("hardened.json"), "--only", "NOPE"], stdout=out, stderr=err)
    except SystemExit as exc:
        assert exc.code == 2
    else:  # pragma: no cover
        raise AssertionError("expected argparse to exit")


def test_overlapping_only_and_skip_is_an_input_error():
    code, _, err = run_cli("--input", fixture("hardened.json"),
                           "--only", "SINGLE_AZ", "--skip", "SINGLE_AZ")
    assert code == EXIT_INPUT
    assert "SINGLE_AZ" in err


def test_non_msk_input_exits_two_with_one_line():
    code, _, err = run_cli("--input", fixture("not_msk.json"))
    assert code == EXIT_INPUT
    assert err.count("\n") == 1
    assert err.startswith("error: ")


def test_unreadable_input_exits_two_without_a_traceback():
    code, _, err = run_cli("--input", fixture("broken.json.txt"))
    assert code == EXIT_INPUT
    assert "not valid JSON" in err
    assert "Traceback" not in err


def test_list_checks():
    code, out, _ = run_cli("--list-checks")
    assert code == EXIT_OK
    assert "NO_ENCRYPTION_IN_TRANSIT" in out
    assert out.splitlines()[0].startswith("CHECK")


def test_module_entrypoint_is_wired():
    from aws_msk_cluster_audit import __main__

    assert __main__.main is main
