import pytest

from aws_msk_cluster_audit.version import is_older, parse


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("3.6.0", (3, 6, 0)),
        ("2.8.1", (2, 8, 1)),
        ("3.10.0", (3, 10, 0)),
        ("3.6.0.tiered", (3, 6, 0)),
        ("2.8.2.tiered", (2, 8, 2)),
        ("3.6", (3, 6)),
        ("", None),
        ("latest", None),
        (None, None),
    ],
)
def test_parse(raw, expected):
    assert parse(raw) == expected


@pytest.mark.parametrize(
    "version,minimum,expected",
    [
        # The acceptance criterion: numeric, not lexical.
        ("2.8.1", "3.10.0", True),
        ("3.10.0", "3.6.0", False),
        ("3.6.0", "3.6.0", False),
        ("3.6", "3.6.0", False),
        ("3.5.1", "3.6.0", True),
        ("3.6.0.tiered", "3.6.0", False),
        ("3.6.0.tiered", "3.7.0", True),
    ],
)
def test_is_older(version, minimum, expected):
    assert is_older(version, minimum) is expected


def test_is_older_is_none_when_unparseable():
    assert is_older("latest", "3.6.0") is None
    assert is_older("3.6.0", None) is None
