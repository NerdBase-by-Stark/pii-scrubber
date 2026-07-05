"""Tests for the structured alias-style plumbing (LLM-prep mode, design #2/#3).

The structured style only varies the alias *prefix*; composed keys stay
category-based, so a value never gets two aliases across styles/runs within one
vault. NET labels (subnet grouping) are minted on the AliasMap and share one
first-seen sequence across IPv4 and IPv6.

Well-known-address filtering is being added to ``detectors.py`` by another
agent. Where a test value would be kept verbatim by that filter (the multicast
MAC ``01:00:5e`` prefix), we build detectors with ``keep_wellknown=False`` so
the value is tokenised. ``_dets`` degrades gracefully to plain ``build_active``
while that parameter does not yet exist, so the suite passes with either state
of ``detectors.py``.
"""

import json

from piiscrub.detectors import build_active
from piiscrub.engine import (
    AliasMap,
    make_structured_style,
    tokenize,
    tokenize_segment,
)


def _dets(**kw):
    """Active detector set, forcing well-known addresses to be tokenised when
    the (concurrently-added) ``keep_wellknown`` filter exists; falls back to the
    current signature when it does not."""
    try:
        return build_active(keep_wellknown=False, **kw)
    except TypeError:
        return build_active(**kw)


def _alias_of(reps, category):
    for r in reps:
        if r.category == category:
            return r.alias
    return None


def test_same_subnet_shares_net_label_other_subnet_differs():
    """Two IPv4 hosts in one /24 share a NET label (distinct per-host indices);
    a host in a different /24 gets NET2. Fully-expanded, first-seen order."""
    dets = _dets()
    amap = AliasMap()
    style = make_structured_style(amap)
    # RFC-5737 documentation ranges: 192.0.2.0/24 (TEST-NET-1) then
    # 198.51.100.0/24 (TEST-NET-2).
    out, _ = tokenize("a 192.0.2.10 b 192.0.2.20 c 198.51.100.5", dets, amap,
                      style=style)
    assert out == "a <IP_NET1_1> b <IP_NET1_2> c <IP_NET2_1>"
    assert amap._nets == {"v4:192.0.2.0": "NET1", "v4:198.51.100.0": "NET2"}


def test_multicast_ipv4_prefix():
    dets = _dets()
    amap = AliasMap()
    style = make_structured_style(amap)
    out, reps = tokenize("group 239.69.1.2 here", dets, amap, style=style)
    assert _alias_of(reps, "ipv4") == "<MCAST_1>"
    assert "<MCAST_1>" in out


def test_link_local_ipv4_prefix():
    dets = _dets()
    amap = AliasMap()
    style = make_structured_style(amap)
    out, reps = tokenize("apipa 169.254.1.5 seen", dets, amap, style=style)
    assert _alias_of(reps, "ipv4") == "<IP_LL_1>"
    assert "<IP_LL_1>" in out


def test_ipv6_64_grouping():
    """Two IPv6 hosts in one /64 share a NET label; a different /64 differs.

    The IPv6 detector's compressed-form regex only captures the ``::tail`` of a
    ``2001:db8:0:1::5`` literal, so structured grouping is exercised with the
    fully-expanded form (caught whole by the 8-group detector)."""
    dets = _dets()
    amap = AliasMap()
    style = make_structured_style(amap)
    out, _ = tokenize(
        "x 2001:db8:0:1:0:0:0:5 y 2001:db8:0:1:0:0:0:6 z 2001:db8:0:2:0:0:0:5",
        dets, amap, style=style,
    )
    assert out == "x <IPV6_NET1_1> y <IPV6_NET1_2> z <IPV6_NET2_1>"
    assert amap._nets == {
        "v6:2001:db8:0:1::": "NET1",
        "v6:2001:db8:0:2::": "NET2",
    }


def test_multicast_mac_prefix():
    """A multicast MAC (group bit of first octet set) gets the ``MACMC`` prefix.

    ``01:00:5e`` is a well-known multicast prefix; ``_dets`` sets
    ``keep_wellknown=False`` so it is tokenised regardless of detectors.py
    state. A plain unicast MAC keeps its opaque ``MAC`` prefix. Both ':' and
    '-' separators are handled."""
    dets = _dets()
    amap = AliasMap()
    style = make_structured_style(amap)
    out, reps = tokenize(
        "mc 01:00:5e:00:00:fb uni de:ad:be:ef:00:11 dash 01-00-5e-00-00-fb",
        dets, amap, style=style,
    )
    mac_reps = [r for r in reps if r.category == "mac"]
    aliases = [r.alias for r in mac_reps]
    assert "<MACMC_1>" in aliases          # 01:00:5e (colon form)
    assert "<MACMC_2>" in aliases          # 01-00-5e (dash form, distinct value)
    assert "<MAC_1>" in aliases            # unicast keeps opaque prefix
    assert "<MACMC_1>" in out


def test_shared_net_sequence_across_v4_and_v6():
    """NET labels are one first-seen sequence shared across families: v4 subnets
    take NET1/NET2, then a v6 /64 takes NET3 (net_key disambiguates)."""
    dets = _dets()
    amap = AliasMap()
    style = make_structured_style(amap)
    out, _ = tokenize(
        "a 192.0.2.10 b 198.51.100.5 c 2001:db8:0:9:0:0:0:1",
        dets, amap, style=style,
    )
    assert out == "a <IP_NET1_1> b <IP_NET2_1> c <IPV6_NET3_1>"
    assert amap._nets == {
        "v4:192.0.2.0": "NET1",
        "v4:198.51.100.0": "NET2",
        "v6:2001:db8:0:9::": "NET3",
    }


def test_vault_roundtrip_preserves_nets_and_continues_sequence():
    """to_dict/from_dict preserves the NET registry and continues the label
    sequence (a new /24 after restore mints NET3, not NET1)."""
    dets = _dets()
    amap = AliasMap()
    style = make_structured_style(amap)
    tokenize("a 192.0.2.10 b 198.51.100.5", dets, amap, style=style)
    assert amap._nets == {"v4:192.0.2.0": "NET1", "v4:198.51.100.0": "NET2"}

    # Serialise through JSON (vault round-trip) and restore.
    restored = AliasMap.from_dict(json.loads(json.dumps(amap.to_dict())))
    assert restored._nets == {"v4:192.0.2.0": "NET1", "v4:198.51.100.0": "NET2"}

    # A brand-new /24 continues the sequence at NET3.
    style2 = make_structured_style(restored)
    out, _ = tokenize("d 203.0.113.7", dets, restored, style=style2)
    assert out == "d <IP_NET3_1>"
    assert restored._nets["v4:203.0.113.0"] == "NET3"


def test_opaque_first_then_structured_returns_original_alias():
    """DOCUMENTED: consistency beats style. A value tokenised opaque first keeps
    that alias when later tokenised with the structured style — the composed key
    is category-based, so ``_ensure_alias`` hits the existing ``key_index``
    entry and the structured prefix is never applied (design decision #2)."""
    dets = _dets()
    amap = AliasMap()
    out_opaque, _ = tokenize("z 192.0.2.99", dets, amap)          # opaque first
    assert out_opaque == "z <IP_1>"

    style = make_structured_style(amap)
    out_structured, reps = tokenize("z 192.0.2.99 again", dets, amap, style=style)
    # Same value -> the ORIGINAL opaque alias, not <IP_NET1_1>.
    assert out_structured == "z <IP_1> again"
    assert _alias_of(reps, "ipv4") == "<IP_1>"


def test_no_style_is_byte_identical():
    """Passing ``style=None`` (or omitting it) must be byte-identical to the
    pre-existing behaviour — the plumbing adds nothing to the no-style path."""
    dets = build_active()
    text = "mail a@b.com from 10.1.2.3 mac de:ad:be:ef:00:11 ip 192.0.2.5"
    a_omit = AliasMap()
    out_omit, reps_omit = tokenize(text, dets, a_omit)
    a_none = AliasMap()
    out_none, reps_none = tokenize(text, dets, a_none, style=None)
    assert out_omit == out_none
    assert len(reps_omit) == len(reps_none)
    assert a_omit.reverse_pairs() == a_none.reverse_pairs()
    # And no NET labels are ever minted on the opaque path.
    assert a_omit._nets == {} and a_none._nets == {}


def _stream(text, dets, chunk, overlap):
    """Drive tokenize_segment as a streaming caller would: accumulate fixed-size
    reads, commit up to ``len(buf) - overlap`` each round, carry ``buf[consumed:]``
    forward, flush the tail with ``safe_end=None``. Returns (output, amap)."""
    amap = AliasMap()
    style = make_structured_style(amap)
    buf = ""
    out = []
    pos = 0
    while pos < len(text):
        buf += text[pos:pos + chunk]
        pos += chunk
        safe = max(0, len(buf) - overlap)
        emitted, _reps, consumed = tokenize_segment(
            buf, dets, amap, safe_end=safe, style=style)
        out.append(emitted)
        buf = buf[consumed:]
    emitted, _reps, _consumed = tokenize_segment(
        buf, dets, amap, safe_end=None, style=style)
    out.append(emitted)
    return "".join(out), amap


def test_streaming_with_style_equals_whole_file():
    """Streamed chunks (tokenize_segment + style) reproduce the whole-file
    tokenize result byte-for-byte, with identical aliases and NET labels — the
    structured style is only invoked for committed spans, in left-to-right
    order, so subnet-label minting order is preserved across the boundary."""
    dets = _dets()
    text = ("row 192.0.2.10 and 192.0.2.20 then 198.51.100.5 mc 239.69.1.2 "
            "ll 169.254.1.5 mac 01:00:5e:00:00:fb uni de:ad:be:ef:00:11 "
            "v6 2001:db8:0:1:0:0:0:5 v6b 2001:db8:0:2:0:0:0:6 end 192.0.2.10")

    amap_whole = AliasMap()
    style_whole = make_structured_style(amap_whole)
    whole, _ = tokenize(text, dets, amap_whole, style=style_whole)

    for chunk, overlap in [(7, 20), (13, 20), (5, 32), (50, 10)]:
        streamed, amap_s = _stream(text, dets, chunk, overlap)
        assert streamed == whole, f"chunk={chunk} overlap={overlap}"
        assert amap_s.reverse_pairs() == amap_whole.reverse_pairs()
        assert amap_s._nets == amap_whole._nets
