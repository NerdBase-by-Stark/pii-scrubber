"""Optional LLM second-pass: flag residual PII the regex missed.

STDLIB ONLY. HTTP is done with ``urllib.request`` — no third-party SDKs — so the
frozen Windows .exe stays small and low-AV-risk.

SAFETY MODEL (this tool's whole purpose is local privacy):
  * The model is ONLY ever shown text that has ALREADY been stripped by the
    regex tokenizer. Raw input never reaches it. The caller passes the output of
    :func:`piiscrub.engine.tokenize`.
  * The model is FLAG-ONLY: it returns candidate fragments (verbatim substrings
    it believes are residual PII), one per line, or ``NONE``. It can neither see
    nor alter the existing alias/decode map. The tool re-validates every
    candidate against the stripped text and ignores anything that is not an
    actual substring or that is itself an existing ``<ALIAS_n>`` token.
  * LOCAL is the default (Ollama / OpenAI-compatible on localhost). CLOUD
    endpoints are hard-gated behind ``--allow-cloud``; with the flag absent and a
    non-local endpoint we REFUSE and send nothing.
  * API keys are read ONLY from an environment variable named by ``--llm-key-env``
    — never from argv, never logged, never persisted to report/manifest/decode.
  * temperature 0, bounded output, a request timeout. On any error we log a
    warning and CONTINUE (fail-open) unless ``strict`` is set (fail-closed).
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

# Matches our own alias tokens — plain (<IP_1>) and entity-scoped
# (<DEV0001.HOST_1>) — so a candidate that is merely an existing alias is
# ignored instead of being re-tokenised.
_ALIAS_RE = re.compile(r"^<[A-Z0-9]+(?:\.[A-Z0-9_]+)?_\d+>$")

# Same token shape but UNanchored, so we can find every alias span *inside* a
# larger body of text (used to make candidate replacement alias-safe — see
# _replace_outside_spans). HIGH 1: a model candidate must never overwrite bytes
# that belong to an existing <ALIAS_n> token, or the decode map can no longer
# reverse the original value (silent, irreversible data loss).
_ALIAS_SCAN_RE = re.compile(r"<[A-Z0-9]+(?:\.[A-Z0-9_]+)?_\d+>")

# Hard cap on how many distinct candidates a single model call may have applied,
# so a hostile/broken model cannot mass-replace ordinary prose.
MAX_CANDIDATES_PER_CALL = 200

# A candidate must be at least this many chars to be considered (rejects 1-2 char
# noise like punctuation pairs that would shred surrounding text).
_MIN_CANDIDATE_LEN = 3

# Categories/labels for LLM-added aliases. Keeps them visibly distinct in the
# decode map and lets verify_tree know they are intentional.
LLM_CATEGORY = "llm"
LLM_PREFIX = "LLM"

DEFAULT_ENDPOINTS = {
    "ollama": "http://127.0.0.1:11434",
    "openai": "http://127.0.0.1:11434",   # most local OpenAI-compatible servers
    "anthropic": "https://api.anthropic.com",
}
DEFAULT_MODELS = {
    "ollama": "llama3.1",
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-haiku-latest",
}
ANTHROPIC_VERSION = "2023-06-01"

_SYSTEM_PROMPT = (
    "You are a strict PII residue detector. You are given text that has ALREADY "
    "had its obvious identifiers replaced with opaque <ALIAS_n> tokens. Your only "
    "job is to find any REMAINING fragments that still look like personal or "
    "sensitive data the automated pass missed (names, account numbers, ticket "
    "ids, hostnames, secrets, addresses, etc.). "
    "Output ONLY the offending fragments, copied VERBATIM, one per line. Copy "
    "each fragment exactly as it appears in the text. Do NOT explain, number, "
    "quote, or comment. Do NOT output any existing <ALIAS_n> token. If nothing "
    "residual is found, output exactly: NONE"
)

_USER_PROMPT = (
    "Find residual PII fragments in the following already-stripped text. "
    "Output each verbatim fragment on its own line, or NONE.\n\n"
    "----- BEGIN TEXT -----\n{text}\n----- END TEXT -----"
)


class LLMError(Exception):
    """Any failure of the LLM pass (config, gating, network, parse)."""


@dataclass
class ProviderCfg:
    provider: str = "ollama"
    endpoint: str = ""
    model: str = ""
    key_env: str = "PIISCRUB_LLM_KEY"
    allow_cloud: bool = False
    strict: bool = False
    timeout: float = 60.0
    forget_key: bool = False
    max_output_chars: int = 4096

    def resolved_endpoint(self) -> str:
        return self.endpoint or DEFAULT_ENDPOINTS.get(self.provider, "")

    def resolved_model(self) -> str:
        return self.model or DEFAULT_MODELS.get(self.provider, "")


# ----------------------------------------------------------------------
# Local-vs-cloud gating
# ----------------------------------------------------------------------

_LOCAL_NAMES = {"localhost", "127.0.0.1", "::1", "[::1]"}


def is_local_endpoint(endpoint: str) -> bool:
    """True if ``endpoint``'s host is OBVIOUS loopback (no data leaves the box).

    LOW 5: IPv4-mapped (``::ffff:127.0.0.1``) and IPv4-translated
    (``::ffff:0:127.0.0.1``) IPv6 forms are treated as NON-local even though the
    embedded v4 address is loopback — they are an indirection an attacker could
    use to dress up a non-obvious host, so the gate stays "obvious loopback only".
    """
    host = (urlsplit(endpoint).hostname or "").strip()
    if not host:
        return False
    if host.casefold() in {"localhost"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    # Reject any IPv6 address that merely *embeds* an IPv4 address (mapped or
    # translated) — only direct loopback counts.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return False
    if getattr(ip, "sixtofour", None) is not None:
        return False
    return ip.is_loopback


def validate_endpoint(endpoint: str) -> None:
    """MED 3: reject a structurally invalid endpoint EARLY (before any per-file
    work) so a scheme-less / hostless URL surfaces as a clean ``LLMError`` rather
    than a raw ``ValueError`` from :class:`urllib.request.Request` mid-run.

    A scheme-less host like ``"api.openai.com"`` parses with an empty scheme and
    an empty hostname (urlsplit treats it as a path), which would later crash
    request building; catch it here."""
    parts = urlsplit(endpoint)
    if parts.scheme.lower() not in ("http", "https"):
        raise LLMError(
            f"invalid LLM endpoint {endpoint!r}: missing or unsupported scheme "
            f"(expected http:// or https://). Nothing was sent."
        )
    if not (parts.hostname or "").strip():
        raise LLMError(
            f"invalid LLM endpoint {endpoint!r}: no host. Nothing was sent."
        )


def enforce_cloud_gate(cfg: ProviderCfg, *, warn=None) -> None:
    """Refuse a non-local endpoint unless ``allow_cloud`` is set. When cloud is
    explicitly allowed, emit a prominent warning. ``warn`` is a callable taking a
    string so tests/CLI can capture it; pass an explicit no-op to suppress the
    warning (LOW 6: the per-file ``second_pass`` gate call does this so the
    "data WILL leave this machine" warning is printed once per run by the CLI,
    not once per file). When ``warn`` is None we fall back to stderr.

    Raises LLMError on a blocked endpoint BEFORE any network call.
    """
    endpoint = cfg.resolved_endpoint()
    if is_local_endpoint(endpoint):
        return
    if not cfg.allow_cloud:
        raise LLMError(
            f"refusing to send already-stripped text to non-local endpoint "
            f"{endpoint!r}: pass --allow-cloud to override (data WILL leave this "
            f"machine). Nothing was sent."
        )
    msg = (
        "WARNING: --allow-cloud is set — already-stripped text will be sent to "
        f"the EXTERNAL service at {endpoint!r}. This is NOT local-only."
    )
    if warn is not None:
        warn(msg)
    else:
        sys.stderr.write("piiscrub: " + msg + "\n")


# ----------------------------------------------------------------------
# API key handling (env var only)
# ----------------------------------------------------------------------

def provider_needs_key(provider: str, endpoint: str) -> bool:
    """Local providers need no key. Cloud OpenAI/Anthropic do. A local
    OpenAI-compatible server (e.g. Ollama's /v1) does not."""
    if provider == "ollama":
        return False
    if is_local_endpoint(endpoint):
        return False
    return provider in ("openai", "anthropic")


def load_key(cfg: ProviderCfg, environ=None) -> str | None:
    """Read the API key from ``os.environ[cfg.key_env]`` ONLY. Never from argv.
    Returns None for providers that need no key. Raises a clear LLMError if a key
    is required but the env var is missing/empty."""
    import os
    environ = os.environ if environ is None else environ
    endpoint = cfg.resolved_endpoint()
    if not provider_needs_key(cfg.provider, endpoint):
        return None
    val = environ.get(cfg.key_env, "")
    if not val:
        raise LLMError(
            f"provider {cfg.provider!r} needs an API key but environment variable "
            f"{cfg.key_env!r} is not set. Set it (never pass keys on the command "
            f"line) or use --llm-key-env to name a different variable."
        )
    return val


# ----------------------------------------------------------------------
# HTTP — the SINGLE network entry point (monkeypatched in tests)
# ----------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """HIGH 2: never follow a 3xx. urllib's default opener follows redirects and
    re-sends *custom* request headers (Python only strips ``Authorization``
    cross-origin, NOT ``x-api-key`` / ``anthropic-*``), so a malicious or MITM
    redirect from the configured endpoint would leak the API key to a second
    host. Returning None from ``redirect_request`` makes urllib raise the 3xx as
    an HTTPError instead of following it, so the key is only ever sent to the one
    host the operator configured."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# A single opener with redirects disabled and DEFAULT TLS verification left ON
# (no unverified SSL context). Built once; reused for every POST.
_OPENER = urllib.request.build_opener(_NoRedirect)


def _http_post(url: str, headers: dict, payload: dict, timeout: float) -> dict:
    """POST ``payload`` as JSON to ``url`` and return the parsed JSON response.

    This is the ONLY place that touches the network. Tests monkeypatch this to
    return canned responses so they never make a real call. Raises on transport
    error, redirect (HIGH 2: never followed), or non-200 status (the caller turns
    that into warn-and-continue or fail-closed depending on ``strict``)."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        # Use the no-redirect opener (NOT bare urlopen) so a 3xx can never carry
        # the auth header to another host. TLS cert verification stays ON.
        with _OPENER.open(req, timeout=timeout) as resp:  # nosec: gated above
            status = getattr(resp, "status", 200)
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        # _NoRedirect turns any 3xx into an HTTPError; treat redirects (and any
        # other non-2xx HTTPError) as a hard failure rather than following them.
        if 300 <= e.code < 400:
            raise LLMError(
                f"refusing to follow HTTP {e.code} redirect from {url} "
                f"(would re-send the auth header to another host)"
            ) from e
        raise LLMError(f"HTTP {e.code} from {url}") from e
    if status != 200:
        raise LLMError(f"HTTP {status} from {url}")
    try:
        return json.loads(body)
    except (ValueError, json.JSONDecodeError) as e:
        raise LLMError(f"malformed JSON response from {url}: {e}") from e


# ----------------------------------------------------------------------
# Provider request builders + response extractors
# ----------------------------------------------------------------------

def _build_request(cfg: ProviderCfg, key: str | None, text: str):
    """Return (url, headers, payload) for the configured provider."""
    endpoint = cfg.resolved_endpoint().rstrip("/")
    model = cfg.resolved_model()
    system = _SYSTEM_PROMPT
    user = _USER_PROMPT.format(text=text)
    if cfg.provider == "ollama":
        url = f"{endpoint}/api/chat"
        headers: dict = {}
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": 0, "num_predict": 1024},
        }
    elif cfg.provider == "openai":
        url = f"{endpoint}/v1/chat/completions"
        headers = {}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "max_tokens": 1024,
        }
    elif cfg.provider == "anthropic":
        url = f"{endpoint}/v1/messages"
        headers = {"anthropic-version": ANTHROPIC_VERSION}
        if key:
            headers["x-api-key"] = key
        payload = {
            "model": model,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "temperature": 0,
            "max_tokens": 1024,
        }
    else:
        raise LLMError(f"unknown provider: {cfg.provider!r}")
    return url, headers, payload


def _extract_text(provider: str, resp: dict) -> str:
    """Pull the model's text out of a provider-shaped response."""
    try:
        if provider == "ollama":
            # /api/chat -> {"message": {"content": ...}}; /api/generate -> {"response": ...}
            if isinstance(resp.get("message"), dict):
                return resp["message"].get("content", "") or ""
            return resp.get("response", "") or ""
        if provider == "openai":
            return resp["choices"][0]["message"]["content"] or ""
        if provider == "anthropic":
            parts = resp.get("content", [])
            out = []
            for p in parts:
                if isinstance(p, dict) and p.get("type", "text") == "text":
                    out.append(p.get("text", ""))
            return "".join(out)
    except (KeyError, IndexError, TypeError) as e:
        raise LLMError(f"unexpected {provider} response shape: {e}") from e
    raise LLMError(f"unknown provider: {provider!r}")


# ----------------------------------------------------------------------
# Candidate parsing + validation
# ----------------------------------------------------------------------

def parse_candidates(raw: str, max_output_chars: int) -> list[str]:
    """Turn the model's raw output into a de-duplicated, ordered list of
    candidate fragments. Bounded: only the first ``max_output_chars`` are read."""
    raw = (raw or "")[:max_output_chars]
    out: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        cand = line.strip()
        if not cand or cand.upper() == "NONE":
            continue
        if cand in seen:
            continue
        seen.add(cand)
        out.append(cand)
    return out


def is_existing_alias(cand: str) -> bool:
    return bool(_ALIAS_RE.match(cand))


def _validate(cand: str, text: str) -> bool:
    """Keep a candidate only if it is a real, non-trivial substring of the
    stripped text and is not itself an existing alias token.

    HIGH 1: reject candidates shorter than ``_MIN_CANDIDATE_LEN`` and
    candidates that are pure whitespace/punctuation (no alphanumeric char), so a
    hostile model can't get a near-empty or all-punctuation fragment applied as a
    blind replace across surrounding text."""
    if not cand or len(cand) < _MIN_CANDIDATE_LEN:
        return False
    if is_existing_alias(cand):
        return False
    if not any(ch.isalnum() for ch in cand):
        return False
    if cand not in text:
        return False
    return True


def _alias_spans(text: str) -> list[tuple[int, int]]:
    """Character spans (start, end) of every existing alias token in ``text``."""
    return [(m.start(), m.end()) for m in _ALIAS_SCAN_RE.finditer(text)]


def _overlaps_any(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    """True if [start, end) overlaps any (s, e) in ``spans``."""
    for s, e in spans:
        if start < e and s < end:
            return True
    return False


def _has_replaceable_occurrence(text: str, needle: str) -> bool:
    """True if ``needle`` appears at least once OUTSIDE every existing alias
    span — i.e. there is something a span-aware replace could actually change.
    Used to reject a candidate whose only occurrences are inside alias tokens
    BEFORE we register an alias for it (HIGH 1)."""
    spans = _alias_spans(text)
    nlen = len(needle)
    pos = 0
    while True:
        idx = text.find(needle, pos)
        if idx < 0:
            return False
        if not _overlaps_any(idx, idx + nlen, spans):
            return True
        pos = idx + 1
    return False


def _replace_outside_spans(text: str, needle: str, alias: str) -> tuple[str, int]:
    """Replace every occurrence of ``needle`` in ``text`` with ``alias`` EXCEPT
    occurrences that overlap an existing alias-token span.

    HIGH 1: a blind ``str.replace`` could clobber bytes inside an existing
    ``<ALIAS_n>`` token (e.g. candidate "P_1" inside "<IP_1>"), making the
    decode map unable to reverse the original value. We compute alias spans
    on the CURRENT text and skip any match that overlaps one. Returns
    ``(new_text, n_replaced)``; ``n_replaced`` is 0 when every occurrence was
    inside an alias (the candidate is then a no-op and should be rejected)."""
    spans = _alias_spans(text)
    out: list[str] = []
    pos = 0
    n = 0
    nlen = len(needle)
    while True:
        idx = text.find(needle, pos)
        if idx < 0:
            out.append(text[pos:])
            break
        end = idx + nlen
        if _overlaps_any(idx, end, spans):
            # Keep this occurrence verbatim; do not let it bleed into an alias.
            out.append(text[pos:end])
            pos = end
        else:
            out.append(text[pos:idx])
            out.append(alias)
            pos = end
            n += 1
    return "".join(out), n


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------

def second_pass(text, amap, *, provider_cfg: ProviderCfg, file=None):
    """Run the LLM second pass on ALREADY-STRIPPED ``text``.

    Calls the model, parses candidate fragments, validates each (real substring,
    not an existing alias), tokenises survivors into new ``<LLM_n>`` aliases via
    the shared ``amap``, replaces every occurrence, and returns
    ``(new_text, count)`` where ``count`` is the number of distinct fragments
    aliased.

    The model NEVER sees or alters the existing alias/decode map. On any failure
    (gating refusal, network, timeout, HTTP!=200, malformed response, malformed
    endpoint) this raises :class:`LLMError`; the CLI decides warn-and-continue vs
    fail-closed.
    """
    # LOW 6: pass a no-op ``warn`` so the per-file gate check stays silent — the
    # "data WILL leave this machine" warning is emitted ONCE per run by the CLI's
    # up-front gate check, not once per file. The refusal itself is unchanged.
    enforce_cloud_gate(provider_cfg, warn=lambda _msg: None)
    key = load_key(provider_cfg)

    # MED 3: building the Request from a structurally bad endpoint raises a
    # ValueError that previously escaped second_pass and crashed the whole run.
    # Validate the endpoint up-front (turning a scheme-less/hostless URL into a
    # clean LLMError) AND broaden the catch around request building + the POST so
    # EVERY model-pass failure flows through the CLI's warn-and-continue /
    # fail-closed logic instead of crashing the run.
    try:
        validate_endpoint(provider_cfg.resolved_endpoint())
        url, headers, payload = _build_request(provider_cfg, key, text)
        resp = _http_post(url, headers, payload, provider_cfg.timeout)
    except LLMError:
        raise
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as e:
        raise LLMError(f"LLM request failed: {e}") from e
    except Exception as e:  # noqa: BLE001 - any other surprise becomes an LLMError
        raise LLMError(f"unexpected LLM pass failure: {e}") from e

    raw = _extract_text(provider_cfg.provider, resp)
    candidates = parse_candidates(raw, provider_cfg.max_output_chars)

    new_text = text
    count = 0
    # Longest-first so a fragment that is a substring of another is handled
    # without corrupting the longer replacement.
    for cand in sorted(candidates, key=len, reverse=True):
        # HIGH 1: cap how many candidates a single call may apply so a hostile
        # model cannot mass-replace ordinary prose.
        if count >= MAX_CANDIDATES_PER_CALL:
            break
        # Re-validate against the MUTATING text: a longer candidate's
        # replacement may have already consumed a shorter one.
        if not _validate(cand, new_text):
            continue
        # HIGH 1: alias-SAFE replace — never overwrite bytes inside an existing
        # <ALIAS_n> token. Determine FIRST whether there is any non-overlapping
        # occurrence; only register an alias (mutating the decode map) when the
        # candidate will actually be applied. If EVERY occurrence overlaps an
        # alias the candidate is a no-op and is rejected outright.
        if not _has_replaceable_occurrence(new_text, cand):
            continue
        alias = amap.alias_for(cand, cand, LLM_CATEGORY, LLM_PREFIX, file)
        new_text, n_done = _replace_outside_spans(new_text, cand, alias)
        if n_done == 0:
            # Should not happen (we checked above) but never count a no-op.
            continue
        count += 1
    return new_text, count
