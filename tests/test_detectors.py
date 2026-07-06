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


# --------------------------------------------------------------------------
# Audit blind spots: forms that previously survived BOTH strip and verify
# (verify runs the same tokenizer, so these were true blind leaks). Each must
# now be aliased end-to-end; the neighbouring negatives pin the accept
# filters that keep look-alikes untouched.
# --------------------------------------------------------------------------

def scrub(text, **kw):
    dets = build_active(**kw)
    amap = AliasMap()
    return tokenize(text, dets, amap)


def test_leading_zero_ipv4_aliased():
    # inet_aton parses leading-zero octets (octal), so this is a real address.
    out, reps = scrub("host 010.010.010.010 seen")
    assert out == "host <IP_1> seen"
    assert [r.category for r in reps] == ["ipv4"]


def test_leading_zero_single_octet_aliased():
    out, reps = scrub("host 192.168.001.100 seen")
    assert out == "host <IP_1> seen"


def test_all_decimal_full_form_ipv6_aliased():
    out, reps = scrub("addr 1234:5678:9012:3456:7890:1234:5678:9012 x")
    assert out == "addr <IPV6_1> x"
    assert [r.category for r in reps] == ["ipv6"]


def test_all_short_decimal_groups_still_untouched():
    # Colon-separated byte/time-style fields: pure decimal, every group <3
    # chars -> not IPv6. (A uniform 8x2-hex-digit run is claimed by
    # ptp_clockid instead, so mixed widths pin the ipv6 accept filter.)
    text = "fields 1:22:3:44:5:66:7:88 x"
    out, reps = scrub(text)
    assert out == text
    assert reps == []


def test_cisco_dotted_mac_aliased():
    out, reps = scrub("mac aabb.ccdd.eeff x")
    assert out == "mac <MAC_1> x"
    assert [r.category for r in reps] == ["mac"]


def test_dotted_numeric_triplet_untouched():
    # Serial/part-number shaped: no hex letter -> not a Cisco MAC.
    text = "serial 1234.5678.9012 x"
    out, reps = scrub(text)
    assert out == text
    assert reps == []


def test_v_prefixed_hostname_ip_aliased():
    # 'dev'/'srv' + IP: the v is part of a word, not a version marker.
    out, _ = scrub("box dev10.0.0.1 x")
    assert out == "box dev<IP_1> x"
    out, _ = scrub("box srv10.0.0.2 x")
    assert out == "box srv<IP_1> x"


def test_version_v_prefix_still_untouched():
    text = "running v1.2.3.4 build"
    out, reps = scrub(text)
    assert out == text
    assert reps == []


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
