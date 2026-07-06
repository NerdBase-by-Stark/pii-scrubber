"""Tests for the pcap / pcapng dissector (formats/pcap.py).

All capture fixtures are built byte-by-byte with ``struct`` here — no binary
blobs are committed. The core contract under test:

* every address / name / payload string recovered from a packet appears ALIASED
  in the ``.txt`` derivative and NO raw value survives;
* raw payload bytes are never emitted as hex;
* a structurally invalid file (bad magic) raises ExtractError (walker then
  copies through + flags), while a merely truncated capture yields a warning and
  keeps the dissected output;
* classic pcap in both byte orders and µs/ns resolution, plus pcapng
  (SHB/IDB/EPB/SPB, unknown blocks, multiple sections, if_tsresol) all parse;
* every supported link type (Ethernet + VLAN, SLL, SLL2, raw IP, Null/Loopback)
  reaches L3/L4;
* limits (max_out_bytes) trip ExtractError; scan (write=False) drives scrub but
  writes nothing
  a shared AliasMap gives the same alias across sources.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

import pytest

from piiscrub.detectors import build_active
from piiscrub.engine import AliasMap, tokenize
from piiscrub.formats import ExtractError, ExtractLimits, get_handler


# ---------------------------------------------------------------------------
# Packet / capture builders


def _mac_bytes(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def eth(dst: str, src: str, ethertype: int, payload: bytes) -> bytes:
    return _mac_bytes(dst) + _mac_bytes(src) + struct.pack(">H", ethertype) + payload


def vlan_eth(dst: str, src: str, vid: int, inner_et: int, payload: bytes) -> bytes:
    return (_mac_bytes(dst) + _mac_bytes(src) + struct.pack(">H", 0x8100)
            + struct.pack(">HH", vid, inner_et) + payload)


def ipv4(src: str, dst: str, proto: int, payload: bytes, *, ttl: int = 64,
         frag_off: int = 0, mf: bool = False) -> bytes:
    total = 20 + len(payload)
    flags_frag = (0x2000 if mf else 0) | (frag_off // 8)
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total, 0x1234, flags_frag, ttl, proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def ipv6(src: str, dst: str, nexthdr: int, payload: bytes, *, hop: int = 64) -> bytes:
    return (struct.pack(">IHBB", 0x60000000, len(payload), nexthdr, hop)
            + socket.inet_pton(socket.AF_INET6, src)
            + socket.inet_pton(socket.AF_INET6, dst) + payload)


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport: int, dport: int, payload: bytes, *, flags: int = 0x18) -> bytes:
    off_flags = (5 << 12) | flags
    return struct.pack(">HHIIHHHH", sport, dport, 0, 0, off_flags, 65535, 0, 0) + payload


def arp(oper: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    return (struct.pack(">HHBBH", 1, 0x0800, 6, 4, oper)
            + _mac_bytes(sha) + socket.inet_aton(spa)
            + _mac_bytes(tha) + socket.inet_aton(tpa))


def _dns_name(name: str) -> bytes:
    out = b"".join(bytes([len(lbl)]) + lbl.encode() for lbl in name.split("."))
    return out + b"\x00"


def dns_query(name: str, qtype: int = 1, qid: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + _dns_name(name) + struct.pack(">HH", qtype, 1)


def dns_response_a(name: str, ip: str, qid: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    q = _dns_name(name) + struct.pack(">HH", 1, 1)
    ans = (_dns_name(name) + struct.pack(">HHIH", 1, 1, 300, 4)
           + socket.inet_aton(ip))
    return header + q + ans


def sll(proto: int, payload: bytes, src_mac: str = "aa:bb:cc:dd:ee:ff") -> bytes:
    addr = _mac_bytes(src_mac) + b"\x00\x00"           # 8-byte address field
    return struct.pack(">HHH", 0, 1, 6) + addr + struct.pack(">H", proto) + payload


def sll2(proto: int, payload: bytes, src_mac: str = "aa:bb:cc:dd:ee:ff") -> bytes:
    addr = _mac_bytes(src_mac) + b"\x00\x00"
    return (struct.pack(">H", proto) + b"\x00\x00" + struct.pack(">I", 1)
            + struct.pack(">H", 1) + bytes([0, 6]) + addr + payload)


def null_lo(family: int, payload: bytes) -> bytes:
    return struct.pack("<I", family) + payload


def classic_pcap(packets, *, endian: str = "<", ns: bool = False,
                 linktype: int = 1, snaplen: int = 65535) -> bytes:
    if endian == "<":
        magic = b"\x4d\x3c\xb2\xa1" if ns else b"\xd4\xc3\xb2\xa1"
    else:
        magic = b"\xa1\xb2\x3c\x4d" if ns else b"\xa1\xb2\xc3\xd4"
    e = endian
    out = bytearray(magic)
    out += struct.pack(e + "HHiIII", 2, 4, 0, 0, snaplen, linktype)
    for ts_sec, ts_sub, pkt in packets:
        out += struct.pack(e + "IIII", ts_sec, ts_sub, len(pkt), len(pkt))
        out += pkt
    return bytes(out)


# --- pcapng block builders -------------------------------------------------

def _pad4(b: bytes) -> bytes:
    return b + b"\x00" * ((-len(b)) % 4)


def _block(btype: int, body: bytes, e: str) -> bytes:
    padded = _pad4(body)
    total = 12 + len(padded)
    return (struct.pack(e + "II", btype, total) + padded
            + struct.pack(e + "I", total))


def shb(e: str = "<") -> bytes:
    bom = b"\x4d\x3c\x2b\x1a" if e == "<" else b"\x1a\x2b\x3c\x4d"
    body = bom + struct.pack(e + "HH", 1, 0) + struct.pack(e + "q", -1)
    total = 12 + len(body)
    return (struct.pack(e + "I", 0x0A0D0D0A) + struct.pack(e + "I", total)
            + body + struct.pack(e + "I", total))


def idb(linktype: int, e: str = "<", tsresol: int | None = None) -> bytes:
    body = struct.pack(e + "HHI", linktype, 0, 65535)
    if tsresol is not None:
        body += struct.pack(e + "HH", 9, 1) + bytes([tsresol]) + b"\x00\x00\x00"
        body += struct.pack(e + "HH", 0, 0)          # opt_endofopt
    return _block(0x00000001, body, e)


def epb(iface: int, ts_sec: float, pkt: bytes, e: str = "<",
        tsresol_exp: int = 6) -> bytes:
    ts = int(ts_sec * (10 ** tsresol_exp))
    body = (struct.pack(e + "IIIII", iface, ts >> 32, ts & 0xFFFFFFFF,
                        len(pkt), len(pkt)) + pkt)
    return _block(0x00000006, body, e)


def spb(pkt: bytes, e: str = "<") -> bytes:
    body = struct.pack(e + "I", len(pkt)) + pkt
    return _block(0x00000003, body, e)


def unknown_block(e: str = "<") -> bytes:
    return _block(0x00000ABC, b"payloadless custom block", e)


# ---------------------------------------------------------------------------
# Driver


def _scrub_factory(amap: AliasMap):
    dets = build_active()

    def scrub(rel: str, text: str):
        new, reps = tokenize(text, dets, amap, frozenset(), file=rel)
        return new, len(reps)

    return scrub


def run(tmp_path: Path, raw: bytes, *, name: str = "cap.pcap", write: bool = True,
        limits: ExtractLimits | None = None, amap: AliasMap | None = None):
    """Dissect ``raw`` via the registered pcap handler; return
    ``(outcome, derivative_text, amap)``."""
    amap = amap or AliasMap()
    limits = limits or ExtractLimits()
    src = tmp_path / name
    src.write_bytes(raw)
    out_path = (tmp_path / "out" / name) if write else None
    handler = get_handler(".pcap")
    outcome = handler.process(src, name, out_path, _scrub_factory(amap),
                              write=write, limits=limits)
    text = ""
    if write and out_path is not None:
        deriv = out_path.parent / (out_path.name + ".txt")
        if deriv.exists():
            text = deriv.read_text()
    return outcome, text, amap


# ===========================================================================
# Basic dissection + aliasing


def test_ethernet_ipv4_udp_dns_query(tmp_path: Path):
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:01", 0x0800,
              ipv4("10.1.2.3", "10.1.2.9", 17, udp(40000, 53,
                   dns_query("mail.example.com"))))
    outcome, text, amap = run(tmp_path, classic_pcap([(1609556645, 6, pkt)]))
    assert outcome.kind == "derivative" and outcome.out_rel == "cap.pcap.txt"
    # raw values gone, aliases present
    for raw_val in ("10.1.2.3", "10.1.2.9", "mail.example.com",
                    "aa:bb:cc:dd:ee:01", "11:22:33:44:55:66"):
        assert raw_val not in text
    assert "<IP_" in text and "<HOST_" in text and "<MAC_" in text
    assert "dns query" in text and "udp 40000 -> 53" in text
    assert outcome.replacements >= 4


def test_dns_response_a_record_rdata_aliased(tmp_path: Path):
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:02", 0x0800,
              ipv4("192.0.2.1", "192.0.2.55", 17,
                   udp(53, 40000, dns_response_a("host.internal", "203.0.113.7"))))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert "203.0.113.7" not in text and "host.internal" not in text
    assert "dns answer" in text and "<IP_" in text and "<HOST_" in text


def test_tcp_http_payload_email_and_url_aliased(tmp_path: Path):
    body = (b"GET /login HTTP/1.1\r\nHost: portal.example.com\r\n"
            b"X-Contact: alice@example.com visit http://portal.example.com/x\r\n\r\n")
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:03", 0x0800,
              ipv4("198.51.100.4", "198.51.100.9", 6, tcp(51000, 80, body)))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert "alice@example.com" not in text
    assert "http://portal.example.com/x" not in text
    assert "portal.example.com" not in text
    assert "<EMAIL_" in text and "<URL_" in text
    assert 'payload "' in text and "tcp 51000 -> 80" in text


def test_ipv6_udp(tmp_path: Path):
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:04", 0x86DD,
              ipv6("2001:db8::1", "2001:db8::2", 17, udp(5000, 6000, b"hello there")))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert "2001:db8::1" not in text and "2001:db8::2" not in text
    assert "<IPV6_" in text and "ipv6 " in text


def test_vlan_tagged_ethernet(tmp_path: Path):
    pkt = vlan_eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:05", 42, 0x0800,
                   ipv4("172.16.0.5", "172.16.0.9", 17, udp(1, 2, b"data")))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert "[vlan 42]" in text
    assert "172.16.0.5" not in text and "<IP_" in text


def test_arp(tmp_path: Path):
    pkt = eth("ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:06", 0x0806,
              arp(1, "aa:bb:cc:dd:ee:06", "10.9.9.1", "00:00:00:00:00:00", "10.9.9.2"))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert "arp oper=1" in text
    assert "10.9.9.1" not in text and "10.9.9.2" not in text
    assert "aa:bb:cc:dd:ee:06" not in text
    assert "<IP_" in text and "<MAC_" in text


# ===========================================================================
# Link types


def test_linux_sll(tmp_path: Path):
    pkt = sll(0x0800, ipv4("10.5.5.5", "10.5.5.9", 17, udp(1, 2, b"payloadX")))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)], linktype=113))
    assert "sll " in text and "10.5.5.5" not in text and "<IP_" in text


def test_linux_sll2(tmp_path: Path):
    pkt = sll2(0x0800, ipv4("10.6.6.6", "10.6.6.9", 17, udp(1, 2, b"payloadY")))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)], linktype=276))
    assert "sll2 " in text and "10.6.6.6" not in text and "<IP_" in text


def test_raw_ip_linktype(tmp_path: Path):
    pkt = ipv4("10.7.7.7", "10.7.7.9", 17, udp(1, 2, b"rawip"))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)], linktype=101))
    assert "10.7.7.7" not in text and "<IP_" in text


def test_null_loopback_ipv4(tmp_path: Path):
    pkt = null_lo(2, ipv4("10.8.8.8", "10.8.8.9", 17, udp(1, 2, b"loop")))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)], linktype=0))
    assert "null family=2" in text and "10.8.8.8" not in text and "<IP_" in text


def test_null_loopback_ipv6(tmp_path: Path):
    pkt = null_lo(24, ipv6("2001:db8::9", "2001:db8::a", 17, udp(1, 2, b"x")))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)], linktype=0))
    assert "2001:db8::9" not in text and "<IPV6_" in text


def test_unknown_linktype_no_hex_only_strings(tmp_path: Path):
    # Unknown link type -> note + printable strings, never a hex dump.
    payload = b"\xde\xad\xbe\xef user bob@example.org here \x00\x01"
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, payload)], linktype=9999))
    assert "# link unknown type=9999" in text
    assert "deadbeef" not in text.lower()      # raw payload never hex-dumped
    assert "bob@example.org" not in text and "<EMAIL_" in text


# ===========================================================================
# Endianness + timestamp resolution


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("ns", [False, True])
def test_classic_endianness_and_resolution(tmp_path: Path, endian: str, ns: bool):
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:07", 0x0800,
              ipv4("10.4.4.4", "10.4.4.9", 17, udp(1, 2, b"resolutiontest")))
    sub = 123456789 if ns else 123456
    _, text, _ = run(tmp_path, classic_pcap([(1609556645, sub, pkt)],
                                            endian=endian, ns=ns))
    assert "10.4.4.4" not in text and "<IP_" in text
    assert "# packet 1 ts=2021-" in text        # decoded ISO8601 timestamp


# ===========================================================================
# pcapng


def test_pcapng_basic_epb(tmp_path: Path):
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:08", 0x0800,
              ipv4("10.10.10.1", "10.10.10.9", 17, udp(1, 53,
                   dns_query("srv.corp"))))
    raw = shb() + idb(1, tsresol=6) + epb(0, 1609556645.5, pkt)
    outcome, text, _ = run(tmp_path, raw, name="cap.pcapng")
    assert outcome.out_rel == "cap.pcapng.txt"
    assert "10.10.10.1" not in text and "srv.corp" not in text
    assert "<IP_" in text and "<HOST_" in text
    assert "# packet 1 ts=2021-" in text


def test_pcapng_big_endian(tmp_path: Path):
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:09", 0x0800,
              ipv4("10.11.11.1", "10.11.11.9", 17, udp(1, 2, b"beping")))
    raw = shb(">") + idb(1, ">", tsresol=6) + epb(0, 1000.0, pkt, ">")
    _, text, _ = run(tmp_path, raw, name="be.pcapng")
    assert "10.11.11.1" not in text and "<IP_" in text


def test_pcapng_tsresol_nanoseconds(tmp_path: Path):
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:0a", 0x0800,
              ipv4("10.12.12.1", "10.12.12.9", 17, udp(1, 2, b"nano")))
    # tsresol exp 9 => nanoseconds; timestamp value scaled accordingly.
    raw = shb() + idb(1, tsresol=9) + epb(0, 1609556645.25, pkt, tsresol_exp=9)
    _, text, _ = run(tmp_path, raw, name="ns.pcapng")
    assert "# packet 1 ts=2021-" in text and "<IP_" in text


def test_pcapng_spb_and_unknown_block(tmp_path: Path):
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:0b", 0x0800,
              ipv4("10.13.13.1", "10.13.13.9", 17, udp(1, 2, b"simple")))
    raw = (shb() + idb(1, tsresol=6) + unknown_block()
           + spb(pkt) + unknown_block())
    _, text, _ = run(tmp_path, raw, name="spb.pcapng")
    assert "10.13.13.1" not in text and "<IP_" in text
    assert "# packet 1 ts=n/a" in text          # SPB has no timestamp


def test_pcapng_multiple_sections(tmp_path: Path):
    p1 = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:0c", 0x0800,
             ipv4("10.14.0.1", "10.14.0.9", 17, udp(1, 2, b"s1")))
    p2 = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:0d", 0x0800,
             ipv4("10.15.0.1", "10.15.0.9", 17, udp(1, 2, b"s2")))
    raw = (shb() + idb(1, tsresol=6) + epb(0, 1.0, p1)
           + shb() + idb(1, tsresol=6) + epb(0, 2.0, p2))
    _, text, _ = run(tmp_path, raw, name="multi.pcapng")
    assert "10.14.0.1" not in text and "10.15.0.1" not in text
    assert text.count("# packet") == 2


# ===========================================================================
# Truncation, bad magic, guards


def test_truncated_final_packet_keeps_output(tmp_path: Path):
    good = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:0e", 0x0800,
               ipv4("10.16.0.1", "10.16.0.9", 17, udp(1, 2, b"ok")))
    raw = bytearray(classic_pcap([(1, 0, good)]))
    # append a second record header claiming 500 bytes but supply only 4
    raw += struct.pack("<IIII", 2, 0, 500, 500) + b"\x01\x02\x03\x04"
    outcome, text, _ = run(tmp_path, bytes(raw))
    assert "# WARNING: truncated capture" in text
    assert any("truncated" in w for w in outcome.warnings)
    # the good first packet still made it through, aliased
    assert "10.16.0.1" not in text and "<IP_" in text
    assert outcome.kind == "derivative"


def _classic_pcap_caplen(pkt_full: bytes, incl: int, *, endian: str = "<",
                         linktype: int = 1) -> bytes:
    """Classic pcap with a SINGLE record whose incl_len (caplen) is ``incl`` but
    orig_len is the full ``len(pkt_full)`` — i.e. the packet was TRUNCATED at
    capture time (snaplen), the routine tcpdump case. Only ``incl`` bytes are
    stored, so the file itself is complete (not a truncated-final-record)."""
    magic = b"\xd4\xc3\xb2\xa1" if endian == "<" else b"\xa1\xb2\xc3\xd4"
    out = bytearray(magic)
    out += struct.pack(endian + "HHiIII", 2, 4, 0, 0, 65535, linktype)
    out += struct.pack(endian + "IIII", 1, 0, incl, len(pkt_full))
    out += pkt_full[:incl]
    return bytes(out)


def test_caplen_truncated_packet_drops_cut_final_run(tmp_path: Path):
    # A snaplen-truncated packet (caplen < origlen) whose captured bytes end
    # mid-token must NOT emit that final printable run: cutting an email before
    # its TLD ('bob.smith@stark-r') yields a fragment no detector matches, so it
    # would be written RAW into the derivative and slip past verify (audit fix 2).
    body = b"From: bob.smith@stark-records.com\r\n"
    pkt_full = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:20", 0x0800,
                   ipv4("198.51.100.4", "198.51.100.9", 6, tcp(51000, 80, body)))
    # Chop the trailing 'ecords.com\r\n' (12 bytes) so the captured payload ends
    # exactly at '...stark-r'.
    incl = len(pkt_full) - 12
    _, text, _ = run(tmp_path, _classic_pcap_caplen(pkt_full, incl))
    assert "caplen=" in text and "# packet 1" in text
    # The cut fragment is gone entirely — neither the fragment nor a raw email.
    assert "stark-r" not in text
    assert "bob.smith" not in text


def test_full_packet_still_emits_final_run(tmp_path: Path):
    # Contrast with the truncation case: when caplen == origlen the final run is
    # a genuine token boundary and MUST still be emitted (and its email aliased),
    # so the fix does not over-drop complete payloads.
    body = b"From: bob.smith@stark-records.com\r\n"
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:21", 0x0800,
              ipv4("198.51.100.4", "198.51.100.9", 6, tcp(51000, 80, body)))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert "bob.smith@stark-records.com" not in text   # raw email scrubbed
    assert "<EMAIL_" in text                            # but it WAS captured/aliased


def test_bad_magic_raises_extracterror(tmp_path: Path):
    src = tmp_path / "bad.pcap"
    src.write_bytes(b"not-a-pcap-file at all, definitely bytes here")
    handler = get_handler(".pcap")
    with pytest.raises(ExtractError):
        handler.process(src, "bad.pcap", tmp_path / "out" / "bad.pcap",
                        _scrub_factory(AliasMap()), write=True,
                        limits=ExtractLimits())
    # no partial derivative left behind
    assert not (tmp_path / "out" / "bad.pcap.txt").exists()


def test_empty_file_raises(tmp_path: Path):
    src = tmp_path / "empty.pcap"
    src.write_bytes(b"")
    with pytest.raises(ExtractError):
        get_handler(".pcap").process(src, "empty.pcap", None,
                                     _scrub_factory(AliasMap()), write=False,
                                     limits=ExtractLimits())


def test_max_out_bytes_trips_extracterror(tmp_path: Path):
    pkts = []
    for i in range(50):
        pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:0f", 0x0800,
                  ipv4(f"10.20.0.{i % 200}", "10.20.0.250", 17, udp(1, 2, b"x")))
        pkts.append((i, 0, pkt))
    raw = classic_pcap(pkts)
    with pytest.raises(ExtractError):
        run(tmp_path, raw, limits=ExtractLimits(max_out_bytes=64))


def test_input_size_guard_trips_before_read(tmp_path: Path):
    # Regression: process() slurped the whole capture with path.read_bytes()
    # before any guard; a multi-GB pcap OOMed and MemoryError (not ExtractError)
    # aborted the run. The input-size guard now fails open to copy+flag when the
    # capture is larger than max_out_bytes, WITHOUT reading it into RAM.
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:20", 0x0800,
              ipv4("10.9.0.1", "10.9.0.9", 17, udp(1, 2, b"payload here")))
    raw = classic_pcap([(1, 0, pkt)])
    src = tmp_path / "big.pcap"
    src.write_bytes(raw)
    with pytest.raises(ExtractError) as ei:
        get_handler(".pcap").process(
            src, "big.pcap", None, _scrub_factory(AliasMap()), write=False,
            limits=ExtractLimits(max_out_bytes=len(raw) - 1))
    assert "max_out_bytes" in str(ei.value)


def test_dns_compression_pointer_loop_guard(tmp_path: Path):
    # DNS query whose name is a compression pointer that points at itself.
    header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    loop_name = struct.pack(">H", 0xC00C)         # pointer to offset 12 (itself)
    dns = header + loop_name + struct.pack(">HH", 1, 1)
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:10", 0x0800,
              ipv4("10.21.0.1", "10.21.0.9", 17, udp(40000, 53, dns)))
    # must terminate quickly and not raise
    outcome, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert outcome.kind == "derivative"
    assert "10.21.0.1" not in text and "<IP_" in text


def test_short_payload_runs_not_emitted(tmp_path: Path):
    # 3-char run "abc" is below the 4-char minimum -> not emitted.
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:11", 0x0800,
              ipv4("10.22.0.1", "10.22.0.9", 17,
                   udp(1, 2, b"\x00abc\x00LONGENOUGH\x00")))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert 'payload "abc"' not in text
    assert 'payload "LONGENOUGH"' in text


# ===========================================================================
# Scan (write=False) + shared AliasMap cross-source correlation


def test_scan_writes_nothing_but_drives_scrub(tmp_path: Path):
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:12", 0x0800,
              ipv4("10.30.0.1", "10.30.0.9", 17, udp(1, 2, b"user carol@example.net")))
    amap = AliasMap()
    outcome, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]),
                           write=False, amap=amap)
    assert text == ""                              # nothing written
    assert not (tmp_path / "out").exists()
    assert outcome.replacements >= 2               # ip + email aliased in memory
    assert any(m["category"] == "email" for m in amap.decode_table().values())


def test_shared_aliasmap_same_ip_same_alias(tmp_path: Path):
    amap = AliasMap()
    dets = build_active()
    # first: a plain log line through the shared amap
    _, reps = tokenize("connection from 10.40.0.7 established", dets, amap,
                       frozenset(), file="app.log")
    log_alias = reps[0].alias
    # then: same IP inside a pcap, same shared amap
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:13", 0x0800,
              ipv4("10.40.0.7", "10.40.0.9", 17, udp(1, 2, b"z")))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]), amap=amap)
    assert log_alias in text                       # cross-source correlation
    assert "10.40.0.7" not in text


def test_project_vault_pcap_cross_run_aliasing(tmp_path: Path):
    """A --project vault run over a pcap must keep cross-run aliasing: the same
    IP dissected out of a capture in two separate strip runs sharing one vault
    gets the SAME alias (the walker's scrub closure must correlate against the
    persisted-and-reloaded AliasMap, not a fresh one)."""
    import re

    from piiscrub.cli import main

    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:30", 0x0800,
              ipv4("10.55.0.7", "10.55.0.9", 17,
                   udp(1, 2, b"contact dave@example.org")))
    raw = classic_pcap([(1, 0, pkt)])
    proj = tmp_path / "vault"

    def one_run(n: int) -> str:
        src = tmp_path / f"src{n}"
        src.mkdir()
        (src / "cap.pcap").write_bytes(raw)
        dst = tmp_path / f"dst{n}"
        rc = main(["strip", str(src), str(dst), "--project", str(proj),
                   "--no-progress"])
        assert rc == 0
        return (dst / "cap.pcap.txt").read_text()

    body1 = one_run(1)
    body2 = one_run(2)
    ip_aliases_1 = set(re.findall(r"<IP_\d+>", body1))
    email_aliases_1 = set(re.findall(r"<EMAIL_\d+>", body1))
    assert ip_aliases_1 and ip_aliases_1 == set(re.findall(r"<IP_\d+>", body2))
    assert email_aliases_1 == set(re.findall(r"<EMAIL_\d+>", body2))
    for raw_val in ("10.55.0.7", "10.55.0.9", "dave@example.org"):
        assert raw_val not in body1 and raw_val not in body2


# ===========================================================================
# Payload-string cap must never cut a printable run MID-TOKEN (audit fix 1):
# slicing an overflowing run at ``_PAYLOAD_STR_CAP - emitted`` could leave a
# raw un-aliased PII fragment (email local-part / hostname) that no longer
# matches a detector shape and would leak into the DST derivative.

def test_payload_cap_drops_overflow_run_no_mid_token_leak(tmp_path: Path):
    # A first printable run fills the cap to 4080/4096; the SECOND run holds a
    # raw email whose emission would overflow. The old code sliced it to 16
    # chars ("contact bob.smit") — leaking "bob.smit" raw. The fix drops the
    # whole overflowing run, so no fragment of the email survives.
    filler = b"A" * 4080
    email_run = b"contact bob.smith@stark-records.com"
    body = filler + b"\x00" + email_run
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:20", 0x0800,
              ipv4("10.30.0.1", "10.30.0.9", 6, tcp(51000, 80, body)))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    # No raw fragment of the email — neither the full value nor a mid-token slice.
    assert "bob.smith@stark-records.com" not in text
    assert "bob.smit" not in text
    assert "bob.sm" not in text
    # The under-cap first run is still emitted; the truncation note is present.
    assert 'payload "' + "A" * 4080 + '"' in text
    assert "payload strings truncated" in text


def test_payload_cap_later_short_run_still_emitted(tmp_path: Path):
    # After a run is dropped for overflow, a subsequent run that still fits under
    # the cap must be emitted (dropping is per-run, not "stop for the packet").
    body = (b"A" * 4080 + b"\x00"
            + b"toolongrunthatwilloverflowthecap_" * 2 + b"\x00"
            + b"ok42")
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:21", 0x0800,
              ipv4("10.31.0.1", "10.31.0.9", 6, tcp(51000, 80, body)))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert 'payload "ok42"' in text
    assert "payload strings truncated" in text


# ===========================================================================
# DNS name decoding must cap TOTAL decoded length, not just jump count (audit
# fix 8): compression pointers re-walk labels from each target, so an unbounded
# name amplifies ~129x in memory before any sink budget applies.

def test_decode_name_total_length_capped_against_pointer_bomb():
    from piiscrub.formats.pcap import _decode_name

    # 200 one-char labels, then a compression pointer back to offset 0. Without a
    # length cap the 128-jump loop re-walks all 200 labels per jump -> ~25 600
    # labels (a multi-KB..MB string). The cap stops the name at ~255 bytes.
    body = (b"\x01a") * 200 + b"\xc0\x00"      # pointer to offset 0 (itself)
    name, _next = _decode_name(body, 0)
    # Bounded well under what an uncapped decode would produce (~25 600 labels).
    assert len(name) < 600
    assert name.count(".") < 300


# ===========================================================================
# PTP (Precision Time Protocol, IEEE 1588) dissection — decisions #8/#9.
# Packets are built byte-by-byte like every other fixture; offsets follow the
# IEEE 1588-2008 header (34 B) + message bodies.


def eui64_from_mac(mac: str) -> bytes:
    """A MAC-derived EUI-64 clockIdentity: OUI(3) + ff:fe + NIC(3)."""
    m = _mac_bytes(mac)
    return m[0:3] + b"\xff\xfe" + m[3:6]


def ptp_v2_header(msg_type: int, seq: int, clock_id: bytes, *, domain: int = 0,
                  port: int = 1, msg_len: int = 0) -> bytes:
    assert len(clock_id) == 8
    b = bytearray(34)
    b[0] = msg_type & 0x0F                 # transportSpecific=0 | messageType
    b[1] = 0x02                            # versionPTP = 2
    struct.pack_into(">H", b, 2, msg_len)  # messageLength
    b[4] = domain                          # domainNumber
    b[20:28] = clock_id                    # clockIdentity (sourcePortIdentity)
    struct.pack_into(">H", b, 28, port)    # portNumber
    struct.pack_into(">H", b, 30, seq)     # sequenceId
    return bytes(b)


def ptp_v2_sync(seq: int, clock_id: bytes, *, sec: int = 0, ns: int = 0,
                domain: int = 0, port: int = 1) -> bytes:
    hdr = ptp_v2_header(0x0, seq, clock_id, domain=domain, port=port)
    return hdr + sec.to_bytes(6, "big") + struct.pack(">I", ns)  # originTimestamp


def ptp_v2_announce(seq: int, clock_id: bytes, gm_id: bytes, *, domain: int = 0,
                    port: int = 1, prio1: int = 128, prio2: int = 128,
                    steps: int = 1, tsrc: int = 0xA0, utcoff: int = 37,
                    sec: int = 0, ns: int = 0) -> bytes:
    assert len(gm_id) == 8
    hdr = ptp_v2_header(0x0B, seq, clock_id, domain=domain, port=port)
    body = bytearray(30)                       # packet offsets 34..63
    body[0:6] = sec.to_bytes(6, "big")         # originTimestamp seconds  @34
    struct.pack_into(">I", body, 6, ns)        # originTimestamp nanos    @40
    struct.pack_into(">h", body, 10, utcoff)   # currentUtcOffset i16     @44
    body[13] = prio1                           # grandmasterPriority1     @47
    body[18] = prio2                           # grandmasterPriority2     @52
    body[19:27] = gm_id                        # grandmasterIdentity      @53
    struct.pack_into(">H", body, 27, steps)    # stepsRemoved             @61
    body[29] = tsrc                            # timeSource               @63
    return hdr + bytes(body)


def ptp_v1_sync(seq: int, uuid_mac: str, *, subdomain: str = "_DFLT",
                control: int = 0, source_port: int = 1) -> bytes:
    b = bytearray(40)
    struct.pack_into(">H", b, 0, 1)            # versionPTP = 1
    struct.pack_into(">H", b, 2, 1)            # versionNetwork
    sd = subdomain.encode("ascii")[:16]
    b[4:4 + len(sd)] = sd                      # subdomain @4 (null-padded ASCII)
    b[20] = 0x01                               # messageType (unused by dissector)
    b[21] = 0x01                               # sourceCommunicationTechnology
    b[22:28] = _mac_bytes(uuid_mac)            # sourceUuid @22 (a MAC)
    struct.pack_into(">H", b, 28, source_port)  # sourcePortId @28
    struct.pack_into(">H", b, 30, seq)         # sequenceId @30
    b[32] = control                            # control @32
    return bytes(b)


def test_ptp_v2_announce_udp_mac_identities(tmp_path: Path):
    # v2 Announce over IPv4/UDP 320 (PTP general) with MAC-derived identities:
    # scalar fields survive, identities become reconstructed MACs then aliases.
    clock_mac = "aa:bb:cc:dd:ee:41"
    gm_mac = "aa:bb:cc:dd:ee:42"
    ann = ptp_v2_announce(1234, eui64_from_mac(clock_mac), eui64_from_mac(gm_mac))
    pkt = eth("01:1b:19:00:00:00", "aa:bb:cc:dd:ee:40", 0x0800,
              ipv4("192.0.2.10", "224.0.1.129", 17, udp(320, 320, ann)))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert "ptp v2 announce dom=0 seq=1234" in text
    assert "prio1=128" in text and "prio2=128" in text
    assert "steps=1" in text and "tsrc=0xa0" in text and "utcoff=37" in text
    assert "clockid mac=<MAC" in text and "gm mac=<MAC" in text
    assert "eui64" in text
    for raw_val in (clock_mac, gm_mac):
        assert raw_val not in text


def test_ptp_v2_sync_l2_ethertype(tmp_path: Path):
    # v2 Sync over L2 ethertype 0x88F7 (no IP/UDP); origin timestamp survives.
    dev_mac = "aa:bb:cc:dd:ee:51"
    sync = ptp_v2_sync(7, eui64_from_mac(dev_mac), sec=1000, ns=500)
    pkt = eth("01:1b:19:00:00:00", dev_mac, 0x88F7, sync)
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert "type=0x88f7" in text
    assert "ptp v2 sync dom=0 seq=7" in text
    assert "clockid mac=<MAC" in text and "eui64" in text
    assert "origin_ts=1000.000000500" in text
    assert dev_mac not in text


def test_ptp_v2_sync_l2_vlan_tagged(tmp_path: Path):
    # Same as above but 802.1Q-tagged: VLAN recursion must still reach PTP.
    dev_mac = "aa:bb:cc:dd:ee:52"
    sync = ptp_v2_sync(8, eui64_from_mac(dev_mac), sec=2000, ns=0)
    pkt = vlan_eth("01:1b:19:00:00:00", dev_mac, 100, 0x88F7, sync)
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert "[vlan 100]" in text
    assert "ptp v2 sync dom=0 seq=8" in text
    assert "clockid mac=<MAC" in text
    assert dev_mac not in text


def test_ptp_v2_non_eui64_identity_emits_8group_hex(tmp_path: Path):
    # A clockIdentity whose middle bytes are NOT ff:fe/ff:ff is NOT a MAC-derived
    # EUI-64: it must be emitted as canonical 8-group colon-hex, with no false MAC
    # reconstruction. Asserted on the dissection TEXT directly (pre-scrub), since
    # the ptp_clockid detector would otherwise alias the 8-group form.
    from piiscrub.formats.pcap import _Sink, _dissect_ptp

    clock_id = b"\xaa\xbb\xcc\x11\x22\xdd\xee\xff"   # middle bytes 11:22, not ff:fe
    gm_id = b"\x00\x11\x22\x33\x44\x55\x66\x77"
    ann = ptp_v2_announce(99, clock_id, gm_id)
    sink = _Sink(1 << 20)
    _dissect_ptp(ann, sink)
    text = sink.text()
    assert "clockid aa:bb:cc:11:22:dd:ee:ff" in text
    assert "gm 00:11:22:33:44:55:66:77" in text
    # No false EUI-64 reconstruction: middle bytes not stripped, no mac=/eui64.
    assert "mac=" not in text
    assert "eui64" not in text
    assert "ff:fe" not in text


def test_ptp_v1_sync_udp_uuid_is_mac(tmp_path: Path):
    # PTPv1 (Dante) Sync over UDP 319: sourceUuid IS a MAC -> "uuid mac=" aliased.
    uuid_mac = "aa:bb:cc:dd:ee:61"
    v1 = ptp_v1_sync(4242, uuid_mac, subdomain="_DFLT", control=0)
    pkt = eth("01:1b:19:00:00:00", "aa:bb:cc:dd:ee:60", 0x0800,
              ipv4("192.0.2.20", "224.0.1.129", 17, udp(319, 319, v1)))
    _, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert "ptp v1 sync" in text
    assert "uuid mac=" in text
    assert "seq=4242" in text and "dom=_DFLT" in text
    assert uuid_mac not in text
    assert "<MAC_" in text


def test_ptp_truncated_payload_falls_back_to_strings(tmp_path: Path):
    # A PTPv2 version nibble but a payload far shorter than the 34-byte header:
    # must NOT raise and must degrade to printable-string extraction.
    short = bytes([0x00, 0x02]) + b"PTPSHORTSTRING01"       # 18 bytes, < 34
    pkt = eth("11:22:33:44:55:66", "aa:bb:cc:dd:ee:71", 0x0800,
              ipv4("192.0.2.30", "224.0.1.129", 17, udp(1, 320, short)))
    outcome, text, _ = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert outcome.kind == "derivative"            # no crash / no ExtractError
    assert "ptp v2" not in text                     # header too short to decode
    assert 'payload "PTPSHORTSTRING01"' in text     # strings fallback ran


def test_ptp_clockid_eui64_shares_l2_mac_alias(tmp_path: Path):
    # Full pipeline: the SAME device MAC appears as the eth SOURCE and, EUI-64-
    # encoded, inside the PTP clockIdentity. Both must alias to ONE <MAC_n> (leak
    # closed, correlation preserved); the origin timestamp survives verbatim.
    dev_mac = "aa:bb:cc:dd:ee:ff"
    sync = ptp_v2_sync(1234, eui64_from_mac(dev_mac),
                       sec=1609556645, ns=250000000)
    pkt = eth("01:1b:19:00:00:00", dev_mac, 0x88F7, sync)
    _, text, amap = run(tmp_path, classic_pcap([(1, 0, pkt)]))
    assert dev_mac not in text                       # raw MAC never leaks
    mac_aliases = [a for a, m in amap.decode_table().items()
                   if m["category"] == "mac" and m["original"] == dev_mac]
    assert len(mac_aliases) == 1                      # one alias for the device MAC
    alias = mac_aliases[0]
    assert text.count(alias) >= 2                     # eth line AND clockid line
    assert "origin_ts=1609556645.250000000" in text   # timestamp verbatim
