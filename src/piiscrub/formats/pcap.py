"""pcap / pcapng / cap dissector -> scrubbed text derivative.

Turns a packet capture into one text block per packet and pushes every
recovered field (MACs, IPv4/IPv6 addresses, ARP addresses, DNS names + A/AAAA
rdata, and printable-ASCII payload string runs) through the walker's ``scrub``
closure, so the emails / URLs / hostnames / addresses buried inside HTTP, SMTP,
DNS, etc. all get aliased. The result is a ``.txt`` derivative
(``capture.pcap`` -> ``capture.pcap.txt``); ``kind`` is always ``"derivative"``.

Design invariants (see docs/plans/2026-07-05-format-extractors-design.md):

* **Stdlib only** — ``struct``/``socket``/``datetime`` parsing, no scapy/dpkt.
* **NEVER emit raw hex of payload bytes.** Hex can encode PII invisibly to the
  text detectors, so the dissector only ever emits decoded fields and printable
  ASCII string runs (>= 4 chars, capped 4 KB per packet). An unknown link type
  or an undecodable body degrades to a note line + string extraction, never a
  hex dump.
* **Fail-open, structural only.** A structurally invalid file (bad/absent magic)
  raises :class:`ExtractError` so the walker copies the original through + flags
  it. A merely *truncated* capture (incomplete final packet / bad block length)
  is normal: the dissector stops, records a warning line in the text and an
  outcome warning, and still returns everything it did dissect.
* Nothing is written until the full dissection succeeds and is scrubbed, so the
  fallback path never has a partial derivative to clean up (belt-and-braces: the
  write step still deletes a half-written file before re-raising).
"""

from __future__ import annotations

import datetime
import socket
import struct
from pathlib import Path

from . import register
from .base import ExtractError, ExtractLimits, ExtractOutcome, ScrubFn

# ---------------------------------------------------------------------------
# Constants

# Classic pcap file magics: (endianness, nanosecond?) keyed by the 4 header
# bytes. Both byte orders, µs + ns timestamp variants.
_CLASSIC_MAGICS: dict[bytes, tuple[str, bool]] = {
    b"\xa1\xb2\xc3\xd4": (">", False),   # big-endian, microseconds
    b"\xd4\xc3\xb2\xa1": ("<", False),   # little-endian, microseconds
    b"\xa1\xb2\x3c\x4d": (">", True),    # big-endian, nanoseconds
    b"\x4d\x3c\xb2\xa1": ("<", True),    # little-endian, nanoseconds
}

# pcapng Section Header Block type; palindromic so it reads identically in both
# byte orders (the endianness is taken from the byte-order magic inside it).
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
_BOM_BE = b"\x1a\x2b\x3c\x4d"
_BOM_LE = b"\x4d\x3c\x2b\x1a"

_BT_SHB = 0x0A0D0D0A
_BT_IDB = 0x00000001
_BT_SPB = 0x00000003
_BT_EPB = 0x00000006

# DLT / LINKTYPE_* values we dissect.
_LT_NULL = 0        # BSD loopback (4-byte address family prefix)
_LT_ETHERNET = 1
_LT_RAW = 101       # raw IP, version sniffed from first nibble
_LT_LINUX_SLL = 113
_LT_IPV4 = 228
_LT_IPV6 = 229
_LT_LINUX_SLL2 = 276

# EtherTypes.
_ET_IPV4 = 0x0800
_ET_ARP = 0x0806
_ET_IPV6 = 0x86DD
_ET_VLAN = 0x8100    # 802.1Q
_ET_QINQ = 0x88A8    # 802.1ad

# IP protocol numbers.
_IP_ICMP = 1
_IP_TCP = 6
_IP_UDP = 17
_IP_ICMPV6 = 58
_IP_FRAG6 = 44       # IPv6 fragment extension header

_PAYLOAD_STR_CAP = 4096   # max printable-string chars emitted per packet
_MIN_RUN = 4              # shortest printable run worth emitting

_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
              16: "TXT", 28: "AAAA", 33: "SRV"}


# ---------------------------------------------------------------------------
# Output sink with the max_out_bytes budget guard


class _Sink:
    """Accumulates dissected text lines under the ``max_out_bytes`` budget.

    Every appended line grows a running byte estimate; overshooting the cap
    raises :class:`ExtractError` (a runaway-dissection guard) which the walker
    turns into copy-through + flag. Because lines are only ever buffered here and
    written by the caller AFTER a full successful dissection, tripping the guard
    never leaves a partial derivative behind.
    """

    def __init__(self, max_bytes: int) -> None:
        self._lines: list[str] = []
        self._n = 0
        self._max = max_bytes

    def add(self, line: str) -> None:
        self._n += len(line) + 1
        if self._n > self._max:
            raise ExtractError(
                f"dissected text exceeds max_out_bytes ({self._max})"
            )
        self._lines.append(line)

    def text(self) -> str:
        return "\n".join(self._lines) + ("\n" if self._lines else "")


# ---------------------------------------------------------------------------
# Field formatting helpers (all produce detector-friendly text forms)


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ipv4_str(b: bytes) -> str:
    return ".".join(str(x) for x in b[:4])


def _ipv6_str(b: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, bytes(b[:16]))
    except (OSError, ValueError):
        return "invalid-ipv6"


def _fmt_ts(seconds: float) -> str:
    try:
        return datetime.datetime.fromtimestamp(
            seconds, tz=datetime.timezone.utc
        ).isoformat()
    except (OverflowError, OSError, ValueError):
        return f"raw:{seconds}"


def _tcp_flags(flags: int) -> str:
    names = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
             (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]
    on = [name for bit, name in names if flags & bit]
    return ",".join(on) if on else "-"


def _emit_strings(data: bytes, sink: _Sink) -> None:
    """Emit printable-ASCII runs (>= 4 chars) from ``data`` as ``payload "…"``
    lines, capped at 4 KB of extracted characters per packet. This is what lets
    text PII inside HTTP/SMTP/etc. payloads reach the tokeniser. Raw hex is
    NEVER emitted — only these decoded printable runs."""
    emitted = 0
    truncated = False
    run = bytearray()

    def flush() -> None:
        nonlocal emitted, truncated
        if len(run) >= _MIN_RUN and emitted < _PAYLOAD_STR_CAP:
            s = run.decode("ascii")
            if emitted + len(s) > _PAYLOAD_STR_CAP:
                s = s[: _PAYLOAD_STR_CAP - emitted]
                truncated = True
            if s:
                sink.add(f'payload "{s}"')
                emitted += len(s)

    for byte in data:
        if 0x20 <= byte <= 0x7E:
            run.append(byte)
        else:
            flush()
            run = bytearray()
            if emitted >= _PAYLOAD_STR_CAP:
                truncated = True
                break
    flush()
    if truncated:
        sink.add(f"# note: payload strings truncated at {_PAYLOAD_STR_CAP} chars")


# ---------------------------------------------------------------------------
# DNS name decoding (compression-pointer safe)


def _decode_name(msg: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name starting at ``offset`` in ``msg``.

    Returns ``(name, next_offset)`` where ``next_offset`` is the position just
    after the name in the record stream (following the FIRST pointer, per the
    wire format). Compression pointers are followed with a hard cap of 128 jumps
    so a self-referential / cyclic pointer chain can never loop forever."""
    labels: list[str] = []
    pos = offset
    next_off: int | None = None
    jumps = 0
    n = len(msg)
    while True:
        if pos >= n:
            break
        length = msg[pos]
        if length == 0:
            pos += 1
            if next_off is None:
                next_off = pos
            break
        if (length & 0xC0) == 0xC0:            # compression pointer
            if pos + 1 >= n:
                break
            pointer = ((length & 0x3F) << 8) | msg[pos + 1]
            if next_off is None:
                next_off = pos + 2
            jumps += 1
            if jumps > 128:
                break
            pos = pointer
            continue
        pos += 1
        if pos + length > n:
            break
        labels.append(msg[pos:pos + length].decode("ascii", "replace"))
        pos += length
    if next_off is None:
        next_off = pos
    return ".".join(labels), next_off


def _dns_type(t: int) -> str:
    return _DNS_TYPES.get(t, str(t))


def _dissect_dns(payload: bytes, sink: _Sink, *, tcp: bool) -> None:
    """Decode DNS query/answer names and A/AAAA rdata from a port-53 payload.

    Any structural surprise degrades gracefully to printable-string extraction
    (best effort), never an error — a malformed DNS packet is not a corrupt
    file."""
    try:
        msg = payload
        if tcp:
            # DNS-over-TCP prefixes the message with a 2-byte length.
            if len(payload) >= 2:
                msg = payload[2:]
        if len(msg) < 12:
            _emit_strings(payload, sink)
            return
        qd = int.from_bytes(msg[4:6], "big")
        an = int.from_bytes(msg[6:8], "big")
        off = 12
        # Sanity-cap record counts so a bogus header can't spin us.
        for _ in range(min(qd, 64)):
            name, off = _decode_name(msg, off)
            if off + 4 > len(msg):
                return
            qtype = int.from_bytes(msg[off:off + 2], "big")
            off += 4
            sink.add(f"dns query {name or '.'} type={_dns_type(qtype)}")
        for _ in range(min(an, 256)):
            name, off = _decode_name(msg, off)
            if off + 10 > len(msg):
                return
            atype = int.from_bytes(msg[off:off + 2], "big")
            rdlen = int.from_bytes(msg[off + 8:off + 10], "big")
            rdoff = off + 10
            rdata = msg[rdoff:rdoff + rdlen]
            if atype == 1 and rdlen == 4:
                sink.add(f"dns answer {name or '.'} A {_ipv4_str(rdata)}")
            elif atype == 28 and rdlen == 16:
                sink.add(f"dns answer {name or '.'} AAAA {_ipv6_str(rdata)}")
            elif atype in (2, 5, 12):          # NS / CNAME / PTR -> a name
                target, _ = _decode_name(msg, rdoff)
                sink.add(f"dns answer {name or '.'} {_dns_type(atype)} "
                         f"{target or '.'}")
            else:
                sink.add(f"dns answer {name or '.'} type={_dns_type(atype)}")
            off = rdoff + rdlen
    except Exception:      # noqa: BLE001 - best-effort, fall back to strings
        _emit_strings(payload, sink)


# ---------------------------------------------------------------------------
# L4 dissection


def _dissect_l4(proto: int, data: bytes, sink: _Sink) -> None:
    if proto == _IP_TCP:
        _dissect_tcp(data, sink)
    elif proto == _IP_UDP:
        _dissect_udp(data, sink)
    elif proto == _IP_ICMP:
        if len(data) >= 2:
            sink.add(f"icmp type={data[0]} code={data[1]}")
            _emit_strings(data[4:], sink)
        else:
            _emit_strings(data, sink)
    elif proto == _IP_ICMPV6:
        if len(data) >= 2:
            sink.add(f"icmpv6 type={data[0]} code={data[1]}")
            _emit_strings(data[4:], sink)
        else:
            _emit_strings(data, sink)
    else:
        sink.add(f"l4 proto={proto} len={len(data)}")
        _emit_strings(data, sink)


def _dissect_tcp(data: bytes, sink: _Sink) -> None:
    if len(data) < 20:
        sink.add("# WARNING: short TCP header")
        _emit_strings(data, sink)
        return
    sport = int.from_bytes(data[0:2], "big")
    dport = int.from_bytes(data[2:4], "big")
    data_ofs = (data[12] >> 4) * 4
    flags = data[13]
    sink.add(f"tcp {sport} -> {dport} flags={_tcp_flags(flags)} len={len(data)}")
    if data_ofs < 20:
        data_ofs = 20
    payload = data[data_ofs:] if data_ofs <= len(data) else b""
    if sport == 53 or dport == 53:
        _dissect_dns(payload, sink, tcp=True)
    else:
        _emit_strings(payload, sink)


def _dissect_udp(data: bytes, sink: _Sink) -> None:
    if len(data) < 8:
        sink.add("# WARNING: short UDP header")
        _emit_strings(data, sink)
        return
    sport = int.from_bytes(data[0:2], "big")
    dport = int.from_bytes(data[2:4], "big")
    length = int.from_bytes(data[4:6], "big")
    sink.add(f"udp {sport} -> {dport} len={length}")
    payload = data[8:]
    if sport == 53 or dport == 53:
        _dissect_dns(payload, sink, tcp=False)
    else:
        _emit_strings(payload, sink)


# ---------------------------------------------------------------------------
# L3 dissection


def _dissect_arp(data: bytes, sink: _Sink) -> None:
    if len(data) < 28:
        sink.add("# WARNING: short ARP")
        _emit_strings(data, sink)
        return
    hlen = data[4]
    plen = data[5]
    oper = int.from_bytes(data[6:8], "big")
    if hlen == 6 and plen == 4:
        sha = _mac(data[8:14])
        spa = _ipv4_str(data[14:18])
        tha = _mac(data[18:24])
        tpa = _ipv4_str(data[24:28])
        sink.add(f"arp oper={oper} sender {sha} {spa} target {tha} {tpa}")
    else:
        sink.add(f"arp oper={oper} hlen={hlen} plen={plen}")


def _dissect_ipv4(data: bytes, sink: _Sink) -> None:
    if len(data) < 20:
        sink.add("# WARNING: short IPv4 header")
        _emit_strings(data, sink)
        return
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20:
        ihl = 20
    total_len = int.from_bytes(data[2:4], "big")
    flags_frag = int.from_bytes(data[6:8], "big")
    mf = bool(flags_frag & 0x2000)
    frag_off = (flags_frag & 0x1FFF) * 8
    ttl = data[8]
    proto = data[9]
    src = _ipv4_str(data[12:16])
    dst = _ipv4_str(data[16:20])
    line = f"ipv4 {src} -> {dst} proto={proto} ttl={ttl}"
    if frag_off or mf:
        line += f" frag_offset={frag_off} mf={int(mf)}"
    sink.add(line)
    if frag_off > 0:
        # A non-first fragment carries no L4 header; dissect only the first.
        sink.add(f"# note: IPv4 fragment offset={frag_off}, L4 not dissected")
        return
    if ihl >= len(data):
        return
    end = total_len if (ihl <= total_len <= len(data)) else len(data)
    _dissect_l4(proto, data[ihl:end], sink)


def _dissect_ipv6(data: bytes, sink: _Sink) -> None:
    if len(data) < 40:
        sink.add("# WARNING: short IPv6 header")
        _emit_strings(data, sink)
        return
    payload_len = int.from_bytes(data[4:6], "big")
    nexthdr = data[6]
    hop = data[7]
    src = _ipv6_str(data[8:24])
    dst = _ipv6_str(data[24:40])
    sink.add(f"ipv6 {src} -> {dst} nexthdr={nexthdr} hoplimit={hop}")
    end = 40 + payload_len if 0 < payload_len <= len(data) - 40 else len(data)
    payload = data[40:end]
    proto = nexthdr
    if nexthdr == _IP_FRAG6 and len(payload) >= 8:
        frag = int.from_bytes(payload[2:4], "big") & 0xFFF8
        inner = payload[0]
        sink.add(f"# note: IPv6 fragment offset={frag}")
        if frag > 0:
            return
        proto = inner
        payload = payload[8:]
    _dissect_l4(proto, payload, sink)


def _dissect_l3(ethertype: int, payload: bytes, sink: _Sink) -> None:
    if ethertype == _ET_IPV4:
        _dissect_ipv4(payload, sink)
    elif ethertype == _ET_IPV6:
        _dissect_ipv6(payload, sink)
    elif ethertype == _ET_ARP:
        _dissect_arp(payload, sink)
    else:
        sink.add(f"l3 ethertype=0x{ethertype:04x} len={len(payload)}")
        _emit_strings(payload, sink)


# ---------------------------------------------------------------------------
# Link-layer dissection (per link type)


def _dissect_ethernet(data: bytes, sink: _Sink) -> None:
    if len(data) < 14:
        sink.add("# WARNING: short Ethernet frame")
        _emit_strings(data, sink)
        return
    dst = _mac(data[0:6])
    src = _mac(data[6:12])
    ethertype = int.from_bytes(data[12:14], "big")
    off = 14
    vlans: list[int] = []
    while ethertype in (_ET_VLAN, _ET_QINQ) and off + 4 <= len(data):
        tci = int.from_bytes(data[off:off + 2], "big")
        vlans.append(tci & 0x0FFF)
        ethertype = int.from_bytes(data[off + 2:off + 4], "big")
        off += 4
    vlan_str = "".join(f" [vlan {v}]" for v in vlans)
    sink.add(f"eth {src} -> {dst} type=0x{ethertype:04x}{vlan_str}")
    _dissect_l3(ethertype, data[off:], sink)


def _dissect_null(data: bytes, sink: _Sink) -> None:
    if len(data) < 4:
        _emit_strings(data, sink)
        return
    fam_le = int.from_bytes(data[0:4], "little")
    fam_be = int.from_bytes(data[0:4], "big")
    fam = fam_le if fam_le in (2, 10, 24, 28, 30) else fam_be
    sink.add(f"null family={fam}")
    rest = data[4:]
    if fam == 2:
        _dissect_ipv4(rest, sink)
    elif fam in (10, 24, 28, 30):
        _dissect_ipv6(rest, sink)
    else:
        _emit_strings(rest, sink)


def _dissect_raw_ip(data: bytes, sink: _Sink) -> None:
    if not data:
        return
    version = data[0] >> 4
    if version == 4:
        _dissect_ipv4(data, sink)
    elif version == 6:
        _dissect_ipv6(data, sink)
    else:
        sink.add(f"# raw IP unknown version={version}")
        _emit_strings(data, sink)


def _dissect_sll(data: bytes, sink: _Sink) -> None:
    if len(data) < 16:
        sink.add("# WARNING: short Linux SLL header")
        _emit_strings(data, sink)
        return
    pkttype = int.from_bytes(data[0:2], "big")
    addr_len = int.from_bytes(data[4:6], "big")
    proto = int.from_bytes(data[14:16], "big")
    line = f"sll pkttype={pkttype} proto=0x{proto:04x}"
    if addr_len == 6:
        line += f" src={_mac(data[6:12])}"
    sink.add(line)
    _dissect_l3(proto, data[16:], sink)


def _dissect_sll2(data: bytes, sink: _Sink) -> None:
    if len(data) < 20:
        sink.add("# WARNING: short Linux SLL2 header")
        _emit_strings(data, sink)
        return
    proto = int.from_bytes(data[0:2], "big")
    pkttype = data[10]
    addr_len = data[11]
    line = f"sll2 pkttype={pkttype} proto=0x{proto:04x}"
    if addr_len == 6:
        line += f" src={_mac(data[12:18])}"
    sink.add(line)
    _dissect_l3(proto, data[20:], sink)


def _dissect_by_linktype(linktype: int, data: bytes, sink: _Sink) -> None:
    if linktype == _LT_ETHERNET:
        _dissect_ethernet(data, sink)
    elif linktype == _LT_NULL:
        _dissect_null(data, sink)
    elif linktype == _LT_LINUX_SLL:
        _dissect_sll(data, sink)
    elif linktype == _LT_LINUX_SLL2:
        _dissect_sll2(data, sink)
    elif linktype == _LT_RAW:
        _dissect_raw_ip(data, sink)
    elif linktype == _LT_IPV4:
        _dissect_ipv4(data, sink)
    elif linktype == _LT_IPV6:
        _dissect_ipv6(data, sink)
    else:
        # Unknown link type: a note + printable-string extraction, never a hex
        # dump (raw hex could smuggle PII past the text detectors).
        sink.add(f"# link unknown type={linktype} len={len(data)}")
        _emit_strings(data, sink)


# ---------------------------------------------------------------------------
# Container parsing: classic pcap


def _parse_classic(data: bytes, endian: str, ns: bool, sink: _Sink,
                   warnings: list[str]) -> None:
    if len(data) < 24:
        raise ExtractError("classic pcap global header truncated")
    snaplen = struct.unpack_from(endian + "I", data, 16)[0]
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    pos = 24
    idx = 0
    n = len(data)
    while pos + 16 <= n:
        ts_sec, ts_sub, incl, orig = struct.unpack_from(endian + "IIII", data, pos)
        pos += 16
        if incl > n - pos:
            warnings.append("truncated capture (incomplete final packet)")
            sink.add("# WARNING: truncated capture (incomplete final packet)")
            break
        pkt = data[pos:pos + incl]
        pos += incl
        idx += 1
        frac = ts_sub / 1e9 if ns else ts_sub / 1e6
        sink.add(f"# packet {idx} ts={_fmt_ts(ts_sec + frac)} "
                 f"caplen={incl} origlen={orig}")
        try:
            _dissect_by_linktype(linktype, pkt, sink)
        except ExtractError:
            raise
        except Exception:      # noqa: BLE001 - a bad packet is not a bad file
            sink.add("# WARNING: packet dissection error")
    if pos < n and n - pos < 16:
        warnings.append("trailing bytes after final packet")


# ---------------------------------------------------------------------------
# Container parsing: pcapng


def _parse_idb_tsresol(data: bytes, start: int, end: int,
                       endian: str) -> tuple[str, int]:
    """Scan IDB options for ``if_tsresol`` (option code 9). Returns a
    ``(kind, exp)`` tuple: ``("pow10", 6)`` (the default, microseconds) or
    ``("pow2", exp)`` when the high bit is set."""
    result = ("pow10", 6)
    pos = start
    while pos + 4 <= end:
        code, length = struct.unpack_from(endian + "HH", data, pos)
        pos += 4
        if code == 0:          # opt_endofopt
            break
        if pos + length > end:
            break
        if code == 9 and length >= 1:
            b = data[pos]
            if b & 0x80:
                result = ("pow2", b & 0x7F)
            else:
                result = ("pow10", b & 0x7F)
        pos += length + ((-length) % 4)
    return result


def _pcapng_seconds(ts64: int, tsresol: tuple[str, int]) -> float:
    kind, exp = tsresol
    if kind == "pow2":
        return ts64 * (2.0 ** (-exp))
    return ts64 * (10.0 ** (-exp))


def _parse_pcapng(data: bytes, sink: _Sink, warnings: list[str]) -> None:
    pos = 0
    endian: str | None = None
    interfaces: list[tuple[int, tuple[str, int]]] = []   # (linktype, tsresol)
    idx = 0
    n = len(data)
    while pos + 12 <= n:
        if data[pos:pos + 4] == _PCAPNG_SHB:
            bom = data[pos + 8:pos + 12]
            if bom == _BOM_BE:
                endian = ">"
            elif bom == _BOM_LE:
                endian = "<"
            else:
                warnings.append("bad section header byte-order magic")
                sink.add("# WARNING: bad SHB byte-order magic; stopping")
                break
            block_type = _BT_SHB
            total_len = struct.unpack_from(endian + "I", data, pos + 4)[0]
            interfaces = []                # a new section resets interfaces
        else:
            if endian is None:
                warnings.append("pcapng did not start with a section header")
                sink.add("# WARNING: missing section header; stopping")
                break
            block_type = struct.unpack_from(endian + "I", data, pos)[0]
            total_len = struct.unpack_from(endian + "I", data, pos + 4)[0]
        if total_len < 12 or total_len % 4 != 0 or pos + total_len > n:
            warnings.append("bad/truncated block length")
            sink.add("# WARNING: bad or truncated block length; stopping")
            break
        try:
            if block_type == _BT_IDB:
                linktype = struct.unpack_from(endian + "H", data, pos + 8)[0]
                tsresol = _parse_idb_tsresol(
                    data, pos + 16, pos + total_len - 4, endian)
                interfaces.append((linktype, tsresol))
            elif block_type == _BT_EPB:
                idx = _emit_epb(data, pos, total_len, endian,
                                interfaces, idx, sink)
            elif block_type == _BT_SPB:
                idx = _emit_spb(data, pos, total_len, endian,
                                interfaces, idx, sink)
            # All other block types (name resolution, stats, custom, …) are
            # skipped by length, exactly as the format intends.
        except ExtractError:
            raise
        except Exception:      # noqa: BLE001 - a bad block is not a bad file
            sink.add("# WARNING: block dissection error")
        pos += total_len


def _emit_epb(data: bytes, pos: int, total_len: int, endian: str,
              interfaces: list[tuple[int, tuple[str, int]]], idx: int,
              sink: _Sink) -> int:
    iface_id, ts_hi, ts_lo, caplen, origlen = struct.unpack_from(
        endian + "IIIII", data, pos + 8)
    avail = total_len - 32          # 8 header + 20 fixed + 4 trailer
    if caplen > avail:
        caplen = max(avail, 0)
    pkt = data[pos + 28:pos + 28 + caplen]
    if iface_id < len(interfaces):
        linktype, tsresol = interfaces[iface_id]
    else:
        linktype, tsresol = _LT_ETHERNET, ("pow10", 6)
    ts64 = (ts_hi << 32) | ts_lo
    idx += 1
    sink.add(f"# packet {idx} ts={_fmt_ts(_pcapng_seconds(ts64, tsresol))} "
             f"caplen={caplen} origlen={origlen}")
    _dissect_by_linktype(linktype, pkt, sink)
    return idx


def _emit_spb(data: bytes, pos: int, total_len: int, endian: str,
              interfaces: list[tuple[int, tuple[str, int]]], idx: int,
              sink: _Sink) -> int:
    origlen = struct.unpack_from(endian + "I", data, pos + 8)[0]
    avail = total_len - 16          # 8 header + 4 origlen + 4 trailer
    caplen = min(origlen, avail) if avail > 0 else 0
    pkt = data[pos + 12:pos + 12 + caplen]
    linktype = interfaces[0][0] if interfaces else _LT_ETHERNET
    idx += 1
    sink.add(f"# packet {idx} ts=n/a caplen={caplen} origlen={origlen}")
    _dissect_by_linktype(linktype, pkt, sink)
    return idx


# ---------------------------------------------------------------------------
# Handler


class _PcapHandler:
    """Dissect a packet capture into one scrubbed text block per packet.

    Output is a ``.txt`` derivative (``capture.pcap`` -> ``capture.pcap.txt``);
    kind is always ``"derivative"``.
    """

    name = "pcap"
    suffixes = (".pcap", ".pcapng", ".cap")

    def process(
        self,
        path: Path,
        rel: str,
        out_path: Path | None,
        scrub: ScrubFn,
        *,
        write: bool,
        limits: ExtractLimits,
    ) -> ExtractOutcome:
        try:
            data = path.read_bytes()
        except OSError as e:
            # Unreadable source: fail open to copy-through + flag.
            raise ExtractError(f"could not read capture: {e}") from e
        sink = _Sink(limits.max_out_bytes)
        warnings: list[str] = []

        magic = data[:4]
        if magic == _PCAPNG_SHB:
            _parse_pcapng(data, sink, warnings)
        elif magic in _CLASSIC_MAGICS:
            endian, ns = _CLASSIC_MAGICS[magic]
            _parse_classic(data, endian, ns, sink, warnings)
        else:
            # Structurally not a capture: fail open to copy-through + flag.
            raise ExtractError(
                f"unrecognized capture magic {magic.hex() or '(empty)'}"
            )

        # Scrub the whole dissected text in one pass (its size is bounded by
        # max_out_bytes); the closure aliases every recovered value.
        scrubbed, n = scrub(rel, sink.text())

        out_rel = rel + ".txt"
        if write and out_path is not None:
            deriv = out_path.parent / (out_path.name + ".txt")
            try:
                deriv.parent.mkdir(parents=True, exist_ok=True)
                deriv.write_text(scrubbed, encoding="utf-8", newline="")
            except OSError as e:
                # Never leave a half-written derivative for the fallback path.
                if deriv.exists():
                    deriv.unlink()
                raise ExtractError(f"could not write derivative: {e}") from e

        return ExtractOutcome(
            kind="derivative", out_rel=out_rel, replacements=n,
            warnings=warnings,
        )


HANDLER = register(_PcapHandler())
