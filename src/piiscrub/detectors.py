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

import re
from dataclasses import dataclass
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
    if m.start() > 0 and text[m.start() - 1] in "vV":
        return False
    return True


def _ipv6_full_accept(m: re.Match, _text: str) -> bool:
    # Require a hex letter so pure-decimal time-shaped groups don't match.
    return bool(re.search(r"[a-fA-F]", m.group(0)))


def _phone_accept(m: re.Match, _text: str) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    return 10 <= len(digits) <= 15


# ----------------------------------------------------------------------
# Built-in detector patterns
# ----------------------------------------------------------------------

# FQDN TLD group — curated to avoid colliding with common file extensions
# (no js/sh/py/app/dev/css …). Operators can still add custom host patterns.
_TLDS = (
    r"com|net|org|io|co|edu|gov|mil|info|biz|local|internal|corp|lan|intranet|"
    r"invalid|uk|de|ch|fr|nl|us|jp|cn|in|ru|ca|au|eu|es|it|se|no|fi|pl|br|za"
)

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

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
        "mac", "MAC",
        re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])"),
        priority=60, on_by_default=True, casefold_key=True,
    ),
    Detector(
        "ipv6", "IPV6",
        re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{0,4}"
            r"(?:%[A-Za-z0-9_]+)?\b"
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
            rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?![\d.])"
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
) -> list[Detector]:
    """Return the active detector list.

    - built-ins are included when ``on_by_default`` and not in ``disable``,
      or when their category is explicitly in ``enable``.
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
