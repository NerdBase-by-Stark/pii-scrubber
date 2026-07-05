import pytest

from piiscrub.detectors import (
    _is_wellknown_ipv4,
    _is_wellknown_ipv6,
    _is_wellknown_mac,
    build_active,
)
from piiscrub.engine import AliasMap, tokenize


def scrub(text, **kw):
    dets = build_active(**kw)
    amap = AliasMap()
    return tokenize(text, dets, amap)


# ----------------------------------------------------------------------
# Well-known values survive strip verbatim (design decision #1)
# ----------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "224.0.1.129",         # PTP primary multicast group
    "224.0.0.251",         # mDNS (inside 224.0.0.0/24 local control)
    "255.255.255.255",     # limited broadcast
    "127.0.0.1",           # loopback
    "ff02::fb",            # mDNS v6
    "ff05::181",           # PTP v6 — non-link-local scope nibble still kept
    "01:1b:19:00:00:00",   # PTP multicast MAC
    "ff:ff:ff:ff:ff:ff",   # broadcast MAC
])
def test_wellknown_survives_verbatim(value):
    out, reps = scrub(f"pkt to {value} seen")
    assert value in out
    assert reps == []


def test_normal_unicast_ipv4_still_tokenised():
    out, reps = scrub("from 192.0.2.10 ok")
    assert "192.0.2.10" not in out
    assert "<IP_1>" in out


def test_normal_mac_still_tokenised():
    out, reps = scrub("mac aa:bb:cc:dd:ee:01 up")
    assert "aa:bb:cc:dd:ee:01" not in out
    assert "<MAC_1>" in out


def test_keep_wellknown_false_restores_tokenisation():
    out, reps = scrub("pkt to 224.0.1.129 seen", keep_wellknown=False)
    assert "224.0.1.129" not in out
    assert "<IP_1>" in out


def test_denylist_overrides_keep():
    # Operator denylist force-tokenises even a well-known value.
    out, reps = scrub("pkt to 224.0.1.129 seen", denylist=["224.0.1.129"])
    assert "224.0.1.129" not in out
    assert "<DENY_1>" in out


# ----------------------------------------------------------------------
# ptp_clockid detector (design decision #9)
# ----------------------------------------------------------------------

def test_clockid_beats_ipv6():
    out, reps = scrub("id aa:bb:cc:ff:fe:dd:ee:ff end")
    assert "<CLOCKID_1>" in out
    assert {r.category for r in reps} == {"ptp_clockid"}


def test_compressed_ipv6_still_ipv6():
    out, reps = scrub("addr 2001:db8::1 here")
    assert "<IPV6_1>" in out
    assert {r.category for r in reps} == {"ipv6"}


# ----------------------------------------------------------------------
# IPv4-mapped / IPv4-compatible tails (RFC 4291): the whole literal must be
# claimed, or the overlapping ipv4 candidate is dropped and ".0.2.1" leaks.
# ----------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "::ffff:192.0.2.1",       # IPv4-mapped
    "::ffff:192.0.2.10",      # two-digit final octet at the boundary
    "::192.0.2.1",            # IPv4-compatible (deprecated but seen)
    "64:ff9b::1:192.0.2.33",  # hex groups after :: before the v4 tail
])
def test_v4_tail_fully_aliased(value):
    out, reps = scrub(f"v4map {value} x")
    assert out == "v4map <IPV6_1> x"
    assert {r.category for r in reps} == {"ipv6"}


def test_v4mapped_loopback_not_exempted():
    # ::ffff:127.0.0.1 is not on the well-known list — conservative: alias it.
    out, reps = scrub("lo ::ffff:127.0.0.1 x")
    assert out == "lo <IPV6_1> x"


def test_ratio_text_not_ipv6():
    # 1::2.5 is not a valid IPv6 literal; nothing should match at all.
    out, reps = scrub("ratio 1::2.5 here")
    assert out == "ratio 1::2.5 here"
    assert reps == []


# ----------------------------------------------------------------------
# Trailing-dot contexts: a sentence period or PTR label must not block the
# match (the IP would leak whole) — version runs and larger FQDNs still do.
# ----------------------------------------------------------------------

def test_ipv4_sentence_period_aliased():
    out, reps = scrub("peer 192.0.2.10.")
    assert out == "peer <IP_1>."


def test_ipv4_ellipsis_aliased():
    out, reps = scrub("wait 192.0.2.10... done")
    assert out == "wait <IP_1>... done"


def test_ptr_notation_ip_aliased():
    # "arpa" is not a recognised TLD, so the fqdn detector cannot claim the
    # whole PTR name — the IP head must be aliased, labels stay.
    out, reps = scrub("ptr 10.0.0.1.in-addr.arpa q")
    assert out == "ptr <IP_1>.in-addr.arpa q"


def test_v4mapped_sentence_period_whole():
    out, reps = scrub("v4map ::ffff:192.0.2.1. end")
    assert out == "v4map <IPV6_1>. end"


@pytest.mark.parametrize("text", [
    "fw 1.2.3.4.5 ok",        # version-style dotted run
    "run 10.20.30.40.50 ok",  # five octets
])
def test_version_style_dotted_runs_untouched(text):
    out, reps = scrub(text)
    assert out == text
    assert reps == []


def test_wellknown_with_sentence_period_kept():
    out, reps = scrub("pkt 224.0.1.129. end")
    assert out == "pkt 224.0.1.129. end"
    assert reps == []


def test_leading_dot_context_unchanged():
    # Lookbehind side untouched: a dotted-run head still blocks the match.
    out, reps = scrub("odd .192.0.2.10 here")
    assert out == "odd .192.0.2.10 here"
    assert reps == []


def test_ip_headed_fqdn_still_host():
    # "IP.domain.tld" is a hostname: fqdn must keep claiming the whole name —
    # letting ipv4 take the head would leak ".example.com" (span-claiming
    # drops the overlapping fqdn candidate without re-scanning the tail).
    out, reps = scrub("rdns 192.0.2.10.example.com up")
    assert out == "rdns <HOST_1> up"
    assert {r.category for r in reps} == {"fqdn"}


# ----------------------------------------------------------------------
# Predicate edges: PTP v6 scope nibbles and defensive parsing
# ----------------------------------------------------------------------

def test_ptp_v6_group_any_scope_nibble():
    for x in "0123456789abcdef":
        assert _is_wellknown_ipv6(f"ff0{x}::181")
    assert not _is_wellknown_ipv6("ff15::181")   # flags nibble set → not ff0X
    assert not _is_wellknown_ipv6("ff02::182")   # wrong group


def test_predicates_reject_unparseable():
    assert not _is_wellknown_ipv4("not-an-ip")
    assert not _is_wellknown_ipv6("not-an-ip")
    assert not _is_wellknown_mac("aa:bb:cc:dd:ee:01")


def test_mac_predicate_casefold_and_hyphens():
    assert _is_wellknown_mac("FF-FF-FF-FF-FF-FF")
    assert _is_wellknown_mac("01-00-5E-00-00-FB")
