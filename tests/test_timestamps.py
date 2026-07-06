"""Timestamps are sacred: they are the cross-source correlation key and must
never be scrubbed (design decision #10 in
docs/plans/2026-07-05-llm-prep-mode-design.md). Every test below embeds the
timestamp in a realistic log line next to a real detectable (an RFC-5737
TEST-NET-3 address) so the assertion proves *selective* scrubbing: the IP is
aliased, the timestamp survives byte-identical.

One test documents a known, non-guaranteed edge from decision #10: a bare
digit-run timestamp (epoch-millis/-micros with no separators) sits inside the
credit-card detector's 13-19 digit window, so a value that happens to be
Luhn-valid gets tokenised away. That behaviour is pinned, not asserted as
correct.
"""

from piiscrub.detectors import build_active
from piiscrub.engine import AliasMap, tokenize

_IP = "203.0.113.5"  # RFC 5737 TEST-NET-3 — not a real host


def _luhn(num: str) -> bool:
    """Local Luhn check (deliberately reimplemented, not imported from
    detectors.py) used to verify the Luhn validity of chosen digit-run
    timestamps *before* asserting on how they're handled."""
    total = 0
    alt = False
    for ch in reversed(num):
        if not ch.isdigit():
            return False
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _assert_ip_scrubbed_ts_kept(line: str, ts: str) -> None:
    dets = build_active()
    amap = AliasMap()
    out, reps = tokenize(line, dets, amap)
    assert ts in out, f"timestamp {ts!r} was altered: {out!r}"
    assert _IP not in out
    assert any(r.category == "ipv4" and r.value == _IP for r in reps)


def test_iso8601_zulu_survives():
    ts = "2026-07-05T10:38:00.123456Z"
    line = f"{ts} INFO src={_IP} heartbeat"
    _assert_ip_scrubbed_ts_kept(line, ts)


def test_iso8601_space_comma_millis_survives():
    ts = "2026-07-05 10:38:00,123"
    line = f"{ts} INFO src={_IP} heartbeat"
    _assert_ip_scrubbed_ts_kept(line, ts)


def test_iso8601_offset_variant_survives():
    ts = "2026-07-05T10:38:00.123456+02:00"
    line = f"{ts} INFO src={_IP} heartbeat"
    _assert_ip_scrubbed_ts_kept(line, ts)


def test_syslog_double_space_single_digit_day_survives():
    ts = "Jul  5 10:38:00"  # double space before single-digit day
    line = f"{ts} host sshd: connection from {_IP}"
    _assert_ip_scrubbed_ts_kept(line, ts)


def test_syslog_two_digit_day_survives():
    ts = "Jul 15 10:38:00"
    line = f"{ts} host sshd: connection from {_IP}"
    _assert_ip_scrubbed_ts_kept(line, ts)


def test_epoch_seconds_survives():
    ts = "1783247880"  # 2026-07-05T10:38:00Z, computed via datetime, 10 digits
    line = f"epoch={ts} src={_IP}"
    _assert_ip_scrubbed_ts_kept(line, ts)


def test_epoch_seconds_with_fraction_survives():
    ts = "1783247880.123456"
    line = f"epoch={ts} src={_IP}"
    _assert_ip_scrubbed_ts_kept(line, ts)


def test_pcap_dissection_header_ts_survives():
    ts = "2026-07-05T10:38:00.000001Z"
    line = f"# packet 3 ts={ts} caplen=60 origlen=60 src={_IP}"
    _assert_ip_scrubbed_ts_kept(line, ts)


def test_epoch_millis_13digit_nonluhn_survives():
    # 1783247880 (epoch secs for 2026-07-05T10:38:00Z) + .456 ms, no separators.
    ts = "1783247880456"
    assert len(ts) == 13
    assert not _luhn(ts), "test value must be non-Luhn to exercise the guarantee"
    line = f"ts_ms={ts} src={_IP}"
    _assert_ip_scrubbed_ts_kept(line, ts)


def test_epoch_micros_16digit_nonluhn_survives():
    ts = "1783247880123456"
    assert len(ts) == 16
    assert not _luhn(ts), "test value must be non-Luhn to exercise the guarantee"
    line = f"ts_us={ts} src={_IP}"
    _assert_ip_scrubbed_ts_kept(line, ts)


def test_epoch_micros_16digit_luhnvalid_documented_edge():
    """DOCUMENTED EDGE, NOT a guarantee (design decision #10): a bare
    16-digit epoch-micros integer has no separators, so it sits entirely
    inside the credit-card detector's 13-19-digit acceptance window. When
    that specific digit-run is also Luhn-valid (as this deliberately chosen
    value is), the credit-card detector wins the span and the timestamp gets
    tokenised away. Pinning today's actual behaviour, not asserting it is
    correct or desired."""
    ts = "1783247880000003"
    assert len(ts) == 16
    assert _luhn(ts), "value must be Luhn-valid to exercise this edge"
    line = f"ts_us={ts} src={_IP}"
    dets = build_active()
    amap = AliasMap()
    out, reps = tokenize(line, dets, amap)
    # Current behaviour: the credit-card detector eats the timestamp.
    assert ts not in out
    assert any(r.category == "credit_card" and r.value == ts for r in reps)
    # The neighbouring IP is aliased regardless, proving selective scrubbing
    # still ran (only the CC detector, not some catastrophic failure, ate it).
    assert _IP not in out
    assert any(r.category == "ipv4" and r.value == _IP for r in reps)
