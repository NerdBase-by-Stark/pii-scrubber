"""Detector registry: the built-in PII patterns plus helpers to build the
active detector set from operator config.

A Detector exposes a compiled regex. The *sensitive span* of a match is the
named group ``pii`` if the pattern defines one, otherwise the whole match
(group 0). Only that span is tokenised, so e.g. ``C:\\Users\\jdoe\\`` keeps its
``C:\\Users\\`` prefix and only the username becomes ``<WINUSER_1>``.

Detectors are stdlib-only (``re``). No third-party dependencies, so the frozen
Windows .exe stays small and low-AV-risk.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, replace
from typing import Callable


@dataclass(frozen=True)
class Detector:
    category: str                 # stable category key, e.g. "ipv4"
    prefix: str                   # alias prefix → <IP_1>, <EMAIL_3>
    pattern: re.Pattern
    priority: int                 # higher claims overlapping spans first
    on_by_default: bool
    casefold_key: bool = False    # alias key is value.casefold() (email/host)
    # Optional context filter: return True to keep the match, False to drop it.
    accept: Callable[[re.Match, str], bool] | None = None
    # When set, matches are grouped under this operator-declared entity and get
    # an entity-scoped alias (<DEV0001.HOST_1>) instead of a plain one.
    entity_id: str | None = None


# ----------------------------------------------------------------------
# Validators / context filters
# ----------------------------------------------------------------------

def _luhn(num: str) -> bool:
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


def _credit_card_accept(m: re.Match, _text: str) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    return 13 <= len(digits) <= 19 and _luhn(digits)


_VER_KEYWORD_TAIL = re.compile(
    r"\b(?:version|firmware|build|release|rev|ver)\b\W*$", re.IGNORECASE
)


def _ipv4_accept(m: re.Match, text: str) -> bool:
    """Drop dotted-quads that are clearly firmware/software versions
    (e.g. ``version 2.0.0.0`` or ``v1.2.3.4``) rather than IP addresses."""
    line_start = text.rfind("\n", 0, m.start()) + 1
    tail = text[line_start:m.start()][-24:]
    if _VER_KEYWORD_TAIL.search(tail):
        return False
    i = m.start()
    if i > 0 and text[i - 1] in "vV":
        # Version marker only at a token boundary: "v1.2.3.4" is a version,
        # but "dev10.0.0.1" / "srv10.0.0.2" are hostname-prefixed IPs — keep
        # those (drop only when the v is NOT preceded by another alnum).
        if i < 2 or not text[i - 2].isalnum():
            return False
    return True


def _ipv6_full_accept(m: re.Match, _text: str) -> bool:
    # Drop pure-decimal ALL-short-group sequences (colon-separated byte/time
    # fields like 1:22:3:44:…) — but keep realistic decimal-only IPv6: accept
    # when a hex letter is present OR any group has 3+ digits (zone stripped
    # first so "%eth0" letters can't vouch for a decimal address).
    value = m.group(0).split("%", 1)[0]
    if re.search(r"[a-fA-F]", value):
        return True
    return any(len(g) >= 3 for g in value.split(":"))


def _mac_cisco_accept(m: re.Match, _text: str) -> bool:
    # Require a hex letter so dotted numeric triplets ("1234.5678.9012"
    # serial/part numbers) stay untouched.
    return bool(re.search(r"[a-fA-F]", m.group(0)))


def _phone_accept(m: re.Match, _text: str) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    return 10 <= len(digits) <= 15


# ----------------------------------------------------------------------
# Well-known addresses
# ----------------------------------------------------------------------
# Values that are identical on every network and identify nothing (loopback,
# broadcast, standard multicast groups). Kept verbatim by default:
# build_active() wraps the ipv4/ipv6/mac accept filters so these matches are
# dropped, and verify inherits the exemption because it runs the same
# detectors. keep_wellknown=False restores full tokenisation.

_WK_IPV4_EXACT = frozenset({
    ipaddress.IPv4Address("0.0.0.0"),           # unspecified / "this host"
    ipaddress.IPv4Address("255.255.255.255"),   # limited broadcast
})
_WK_IPV4_NETS = (
    ipaddress.IPv4Network("127.0.0.0/8"),    # loopback
    ipaddress.IPv4Network("224.0.0.0/24"),   # local control (mDNS .251, LLMNR .252, …)
)
_WK_IPV4_PTP_LO = int(ipaddress.IPv4Address("224.0.1.129"))  # PTP primary …
_WK_IPV4_PTP_HI = int(ipaddress.IPv4Address("224.0.1.132"))  # … + alternates 1-3

_WK_IPV6_EXACT = frozenset({
    ipaddress.IPv6Address("::"),         # unspecified
    ipaddress.IPv6Address("::1"),        # loopback
    ipaddress.IPv6Address("ff02::1"),    # all-nodes
    ipaddress.IPv6Address("ff02::2"),    # all-routers
    ipaddress.IPv6Address("ff02::fb"),   # mDNS
    ipaddress.IPv6Address("ff02::1:2"),  # DHCPv6
    ipaddress.IPv6Address("ff02::6b"),   # PTP peer-delay
})

_WK_MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
_WK_MAC_PREFIXES = (
    "01:00:5e:",  # IPv4 multicast
    "33:33:",     # IPv6 multicast
    "01:1b:19:",  # PTP
    "01:80:c2:",  # STP/LLDP/PTP-peer
)


def _is_wellknown_ipv4(value: str) -> bool:
    # Parse defensively: a regex-matched string can still fail to parse.
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    if ip in _WK_IPV4_EXACT or any(ip in net for net in _WK_IPV4_NETS):
        return True
    return _WK_IPV4_PTP_LO <= int(ip) <= _WK_IPV4_PTP_HI


def _is_wellknown_ipv6(value: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(value.split("%", 1)[0])  # drop zone index
    except ValueError:
        return False
    if ip in _WK_IPV6_EXACT:
        return True
    # PTP primary group ff0X::181 — well-known at ANY scope nibble X.
    p = ip.packed
    return (p[0] == 0xFF and p[1] >> 4 == 0
            and not any(p[2:14]) and p[14] == 0x01 and p[15] == 0x81)


def _is_wellknown_mac(value: str) -> bool:
    mac = value.casefold().replace("-", ":")
    if mac.startswith("33:33:ff:"):
        # Solicited-node multicast (33:33:ff:xx:xx:xx) embeds the low 3 bytes
        # of a host's IPv6 interface-id — identifying, so NOT well-known even
        # though it sits inside the 33:33:* IPv6-multicast prefix.
        return False
    return mac == _WK_MAC_BROADCAST or mac.startswith(_WK_MAC_PREFIXES)


_WK_PREDICATES: dict[str, Callable[[str], bool]] = {
    "ipv4": _is_wellknown_ipv4,
    "ipv6": _is_wellknown_ipv6,
    "mac": _is_wellknown_mac,
}


def _wrap_keep_wellknown(det: Detector, is_wk: Callable[[str], bool]) -> Detector:
    """Return a copy of ``det`` whose accept also drops well-known values
    (leaving them verbatim in the text). The existing filter still applies."""
    inner = det.accept

    def accept(m: re.Match, text: str) -> bool:
        if inner is not None and not inner(m, text):
            return False
        return not is_wk(m.group(0))

    return replace(det, accept=accept)


# ----------------------------------------------------------------------
# Built-in detector patterns
# ----------------------------------------------------------------------

# FQDN TLD group — curated to avoid colliding with common file extensions
# (no js/sh/py/app/dev/css …). Operators can still add custom host patterns.
_TLDS = (
    r"com|net|org|io|co|edu|gov|mil|info|biz|local|internal|corp|lan|intranet|"
    r"invalid|uk|de|ch|fr|nl|us|jp|cn|in|ru|ca|au|eu|es|it|se|no|fi|pl|br|za"
)

# One dotted-quad octet. ``0\d{1,2}`` admits inet_aton-style leading zeros
# ("010", "001" — max 3 chars, value necessarily ≤ 99 so range logic holds);
# the ipv6 compressed detector's v4-mapped tail shares this and inherits it.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|0\d{1,2}|[1-9]?\d)"

# Trailing guard for a dotted quad (ipv4 detector and the IPv6 dotted tail).
# A dotted quad must not continue with ".digit" or a bare digit (version-style
# runs like 1.2.3.4.5 stay untouched), and must not be the head of a larger
# FQDN ("192.0.2.10.example.com" — the fqdn detector claims the whole name;
# splitting it would leak the domain tail). A dot NOT followed by either — a
# sentence period, ellipsis, or PTR ".in-addr.arpa" — no longer blocks the
# match ("arpa" is not a recognised TLD, and "in" is followed by "-").
_V4_TAIL_GUARD = (
    r"(?!\.?\d)"
    rf"(?!(?i:\.(?:[A-Za-z0-9][A-Za-z0-9-]{{0,62}}\.)*(?:{_TLDS})(?![\w-])))"
)

BUILTIN_DETECTORS: list[Detector] = [
    Detector(
        "private_key", "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        priority=95, on_by_default=True,
    ),
    Detector(
        "url", "URL",
        re.compile(
            r"(?i)\b(?:https?|ftp)://[^\s<>\"'\)\]\}]*[^\s<>\"'\)\]\}\.,;:!?]",
        ),
        priority=90, on_by_default=True,
    ),
    Detector(
        "jwt", "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        priority=85, on_by_default=True,
    ),
    Detector(
        "email", "EMAIL",
        re.compile(
            r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"
        ),
        priority=80, on_by_default=True, casefold_key=True,
    ),
    Detector(
        "aws_key", "AWSKEY",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        priority=75, on_by_default=True,
    ),
    Detector(
        "google_api_key", "GAPIKEY",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        priority=75, on_by_default=True,
    ),
    Detector(
        "bearer_token", "BEARER",
        re.compile(r"(?i)\bBearer\s+(?P<pii>[A-Za-z0-9._~+/=-]{8,})"),
        priority=75, on_by_default=True,
    ),
    Detector(
        "windows_sid", "SID",
        re.compile(r"\bS-1-\d+(?:-\d+){1,15}\b"),
        priority=70, on_by_default=True,
    ),
    Detector(
        "uuid", "UUID",
        re.compile(
            r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
        ),
        priority=65, on_by_default=True,
    ),
    Detector(
        # Cisco dotted MAC notation (aabb.ccdd.eeff). Same category as the
        # colon/dash detector below (two detectors, one category — like ipv6).
        # Known limitation: alias keys are raw-value based, so the same
        # physical MAC in colon and Cisco notation gets two different aliases
        # — acceptable, each notation is internally consistent. Listed BEFORE
        # the colon form so classify_identifier's last-wins category map keeps
        # the colon detector as the "mac" representative.
        "mac", "MAC",
        re.compile(r"(?<![\w.])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![\w.])"),
        priority=60, on_by_default=True, casefold_key=True,
        accept=_mac_cisco_accept,
    ),
    Detector(
        "mac", "MAC",
        re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])"),
        priority=60, on_by_default=True, casefold_key=True,
    ),
    Detector(
        # PTPv2 clockIdentity (EUI-64) as 8 colon-hex bytes, e.g. from the
        # pcap dissector. Priority must beat ipv6 (55) so an 8×2-hex-digit
        # string is claimed as CLOCKID, not IPV6; mac is 6 groups, unaffected.
        "ptp_clockid", "CLOCKID",
        re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}:){7}[0-9A-Fa-f]{2}(?![\w:-])"),
        priority=58, on_by_default=True, casefold_key=True,
    ),
    Detector(
        # Compressed form. The pre-:: groups must be part of the match: the
        # well-known exemption parses the matched value, so a truncated match
        # ("::fb" out of "ff02::fb") would misclassify against the list.
        # The final part may be a dotted-quad IPv4 tail (RFC 4291
        # IPv4-mapped/compatible, e.g. ::ffff:192.0.2.1) so the whole literal
        # is claimed — otherwise the ipv4 candidate loses the overlap and most
        # of a real IPv4 leaks. A final hex group must not be followed by
        # ".digit" (a half-eaten dotted tail, or ratio-like text such as 1::2.5).
        "ipv6", "IPV6",
        re.compile(
            r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?::"
            r"(?:(?:[0-9A-Fa-f]{1,4}:)*"
            rf"(?:(?:{_OCTET}\.){{3}}{_OCTET}{_V4_TAIL_GUARD}|[0-9A-Fa-f]{{1,4}}(?!\.\d)))?"
            r"(?:%[A-Za-z0-9_]+)?(?![\w:])"
        ),
        priority=55, on_by_default=True, casefold_key=True,
    ),
    Detector(
        "ipv6", "IPV6",
        re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?:%[A-Za-z0-9_]+)?\b"
        ),
        priority=55, on_by_default=True, casefold_key=True,
        accept=_ipv6_full_accept,
    ),
    Detector(
        "ipv4", "IP",
        re.compile(
            rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}{_V4_TAIL_GUARD}"
        ),
        priority=50, on_by_default=True, accept=_ipv4_accept,
    ),
    Detector(
        "credit_card", "CC",
        re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])"),
        priority=45, on_by_default=True, accept=_credit_card_accept,
    ),
    Detector(
        "windows_user_path", "WINUSER",
        re.compile(
            r"(?i)(?:[A-Z]:\\Users\\|\\Users\\|/Users/|/home/)"
            # stop at path separators, whitespace, quotes, and < > so the
            # capture never swallows trailing text or re-matches our own
            # <WINUSER_n> alias on the verify re-scan.
            r"(?P<pii>[^\\/\s\"'<>]+)"
        ),
        priority=40, on_by_default=True,
    ),
    Detector(
        "phone", "PHONE",
        re.compile(
            r"(?<![\d.])(?:\+?\d{1,3}[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}(?![\d])"
        ),
        priority=35, on_by_default=False, accept=_phone_accept,
    ),
    Detector(
        "fqdn", "HOST",
        re.compile(
            r"\b(?:[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.)+(?:" + _TLDS + r")\b",
            re.IGNORECASE,
        ),
        priority=30, on_by_default=True, casefold_key=True,
    ),
]


# ----------------------------------------------------------------------
# Build the active detector set from config
# ----------------------------------------------------------------------

def _prefix_from_name(name: str) -> str:
    p = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    return p or "CUSTOM"


# (category, prefix) used to classify a lone identifier from the entity table.
_CLASSIFY_ORDER = ["ipv4", "ipv6", "mac", "email", "uuid", "url", "fqdn"]
_CLASSIFY_PREFIX = {"ipv4": "IP", "ipv6": "IPV6", "mac": "MAC",
                    "email": "EMAIL", "uuid": "UUID",
                    "url": "URL", "fqdn": "HOST"}


def classify_identifier(value: str) -> tuple[str, str]:
    """Infer (category, alias_prefix) for a single operator-supplied identifier.

    Recognises: ``ipv4`` → ``<IP_n>``, ``ipv6`` → ``<IPV6_n>``,
    ``mac`` → ``<MAC_n>``, ``email`` → ``<EMAIL_n>``, ``uuid`` → ``<UUID_n>``,
    ``url`` → ``<URL_n>`` (must begin with http/https/ftp scheme),
    ``fqdn`` → ``<HOST_n>`` (must contain a recognised TLD).

    Falls back to ``("host", "HOST")`` for bare hostnames such as ``SRV-AB12``
    that carry no TLD and therefore don't match the FQDN detector."""
    by_cat = {d.category: d for d in BUILTIN_DETECTORS}
    for cat in _CLASSIFY_ORDER:
        det = by_cat.get(cat)
        if det and det.pattern.fullmatch(value):
            if det.accept is None or det.accept(det.pattern.fullmatch(value), value):
                return cat, _CLASSIFY_PREFIX[cat]
    return "host", "HOST"


def build_active(
    *,
    disable: set[str] | None = None,
    enable: set[str] | None = None,
    custom: list[dict] | None = None,
    denylist: list[str] | None = None,
    keep_wellknown: bool = True,
) -> list[Detector]:
    """Return the active detector list.

    - built-ins are included when ``on_by_default`` and not in ``disable``,
      or when their category is explicitly in ``enable``.
    - ``keep_wellknown`` (default True) keeps well-known ipv4/ipv6/mac values
      verbatim by wrapping those detectors' accept filters; False restores
      full tokenisation.
    - ``custom`` entries (dicts: name, type=regex|literal, value) get high
      priority so a specific operator rule beats a generic built-in.
    - ``denylist`` literals get top priority (always tokenised).
    """
    disable = disable or set()
    enable = enable or set()
    out: list[Detector] = []

    for d in BUILTIN_DETECTORS:
        if d.category in disable:
            continue
        if d.on_by_default or d.category in enable:
            if keep_wellknown and d.category in _WK_PREDICATES:
                d = _wrap_keep_wellknown(d, _WK_PREDICATES[d.category])
            out.append(d)

    for entry in (custom or []):
        name = entry["name"]
        kind = entry.get("type", "regex")
        value = entry["value"]
        if kind == "literal":
            pat = re.compile(re.escape(value), re.IGNORECASE)
        else:
            pat = re.compile(value)  # raises re.error on bad pattern → fail fast
        out.append(Detector(
            category=name, prefix=_prefix_from_name(name),
            pattern=pat, priority=100, on_by_default=True,
        ))

    for i, lit in enumerate(denylist or []):
        out.append(Detector(
            category=f"denylist", prefix="DENY",
            pattern=re.compile(re.escape(lit), re.IGNORECASE),
            priority=110, on_by_default=True, casefold_key=True,
        ))

    return out
