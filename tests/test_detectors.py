import pytest

from piiscrub.detectors import BUILTIN_DETECTORS, build_active
from piiscrub.engine import AliasMap, tokenize


def cats(text, **kw):
    dets = build_active(**kw)
    amap = AliasMap()
    _, reps = tokenize(text, dets, amap)
    return {r.category for r in reps}


@pytest.mark.parametrize("text,category", [
    ("contact a.b+x@mail.example.com now", "email"),
    ("from 10.0.0.5 ok", "ipv4"),
    ("addr fe80::1ff:fe23:4567:890a here", "ipv6"),
    ("mac de:ad:be:ef:00:11 seen", "mac"),
    ("go to https://example.com/path?q=1 done", "url"),
    ("id 550e8400-e29b-41d4-a716-446655440000 x", "uuid"),
    ("key AKIAIOSFODNN7EXAMPLE end", "aws_key"),
    ("sid S-1-5-21-1004336348-1177238915-682003330-512 x", "windows_sid"),
    ("host db01.internal.corp ok", "fqdn"),
])
def test_positive_detections(text, category):
    assert category in cats(text)


@pytest.mark.parametrize("text", [
    "firmware version 2.0.0.0 shipped",   # version, not an IP
    "running v1.2.3.4 build",             # v-prefixed version
])
def test_version_strings_not_ipv4(text):
    assert "ipv4" not in cats(text)


@pytest.mark.parametrize("text", [
    "see report.json and data.csv files",   # file names, not hostnames
    "open index.html now",
])
def test_filenames_not_fqdn(text):
    assert "fqdn" not in cats(text)


def test_phone_is_opt_in():
    assert "phone" not in cats("call 415-555-1234 today")
    assert "phone" in cats("call 415-555-1234 today", enable={"phone"})


def test_disable_turns_off_builtin():
    assert "email" not in cats("mail a@b.com", disable={"email"})


def test_custom_pattern_high_priority():
    out_cats = cats("asset ASSET-123456 here",
                    custom=[{"name": "asset_tag", "type": "regex", "value": "ASSET-[0-9]{6}"}])
    assert "asset_tag" in out_cats


def test_jwt_detected():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"  # gitleaks:allow (synthetic jwt.io example token, not a real secret)
    assert "jwt" in cats(f"token {jwt} end")


# --------------------------------------------------------------------------
# README "Features" section claims "16+ built-in detectors".
# --------------------------------------------------------------------------

def test_builtin_detector_count_at_least_16():
    """README Features section states '16+ built-in detectors'.
    Verify the actual count in BUILTIN_DETECTORS matches that claim."""
    assert len(BUILTIN_DETECTORS) >= 16, (
        f"README documents 16+ built-in detectors, but only {len(BUILTIN_DETECTORS)} "
        "are defined in BUILTIN_DETECTORS"
    )
