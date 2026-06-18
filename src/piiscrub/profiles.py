"""Named profiles — preset bundles of detector toggles + filters for common
log types, so an operator picks ``--profile syslog`` instead of configuring a
vendor type from scratch. Stored as plain dicts (config-shaped) so nothing has
to be packaged as a data file into the frozen exe.

Operators refine these over time; a project's own ``piiscrub.toml`` and the
entity table layer on top.
"""

from __future__ import annotations

PROFILES: dict[str, dict] = {
    # Everything on by default; no extra filtering.
    "generic": {},

    # Network device logs: focus on network identifiers; PII like credit cards
    # and Windows user paths are noise here.
    "network-gear": {
        "detectors": {"disable": ["credit_card", "windows_user_path", "windows_sid"]},
    },

    # Linux/Unix syslog-style text logs.
    "syslog": {
        "include": ["*.log", "*.txt"],
    },

    # Windows event/admin logs exported to text.
    "windows-logs": {
        "include": ["*.log", "*.txt", "*.csv"],
    },

    # Packet captures exported to text (e.g. tshark -V / -T fields).
    "pcap-text": {
        "include": ["*.txt", "*.csv"],
    },
}


def profile_names() -> list[str]:
    return sorted(PROFILES)


def get_profile(name: str) -> dict:
    if name not in PROFILES:
        raise KeyError(f"unknown profile '{name}'. Available: {', '.join(profile_names())}")
    return PROFILES[name]
