"""Tests for the optional LLM second pass.

CRITICAL: these tests MUST NOT make real network calls. The single HTTP entry
point ``piiscrub.llm._http_post`` is monkeypatched everywhere to return canned
responses (or to assert it is never reached for the cloud-gate refusal).
"""

import json
from pathlib import Path

import pytest

from piiscrub import llm as llm_mod
from piiscrub.cli import main
from piiscrub.engine import AliasMap, reverse_text


# --------------------------------------------------------------------------
# Helpers: build a canned _http_post and record what it received.
# --------------------------------------------------------------------------

def _ollama_resp(text: str) -> dict:
    return {"message": {"role": "assistant", "content": text}}


def _openai_resp(text: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


def _anthropic_resp(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


class _Recorder:
    """Records every _http_post call so tests can assert on it (or that it was
    never called)."""

    def __init__(self, response: dict | None = None):
        self.calls: list[dict] = []
        self.response = response if response is not None else _ollama_resp("NONE")

    def __call__(self, url, headers, payload, timeout):
        self.calls.append({"url": url, "headers": dict(headers),
                           "payload": payload, "timeout": timeout})
        return self.response


def _write(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


# --------------------------------------------------------------------------
# (a) A residual fragment the regex misses is flagged and tokenised, round-trips.
# --------------------------------------------------------------------------

def test_residual_fragment_flagged_and_tokenised(monkeypatch, tmp_path):
    # "ACCT-99-XYZ" is not matched by any built-in detector, so after the regex
    # pass it survives in the stripped text. The (mocked) model flags it.
    src = tmp_path / "src"
    _write(src / "a.log", "ticket ACCT-99-XYZ for ip 10.0.0.5\n")
    dst = tmp_path / "dst"

    rec = _Recorder(_ollama_resp("ACCT-99-XYZ\n"))
    monkeypatch.setattr(llm_mod, "_http_post", rec)

    rc = main(["strip", str(src), str(dst), "--llm", "--no-progress"])
    assert rc == 0
    assert rec.calls, "model should have been called"

    out = (dst / "a.log").read_text(encoding="utf-8")
    assert "ACCT-99-XYZ" not in out          # the residual fragment is gone
    assert "<LLM_1>" in out                   # ...replaced by an LLM alias
    assert "<IP_1>" in out                    # regex aliases still present

    # the model was shown the ALREADY-STRIPPED text, never the raw IP
    sent = json.dumps(rec.calls[0]["payload"])
    assert "10.0.0.5" not in sent
    assert "<IP_1>" in sent

    # decode map records the LLM-added alias under category "llm"
    decode = json.loads((src / "_pii" / "decode.json").read_text())
    assert decode["<LLM_1>"]["original"] == "ACCT-99-XYZ"
    assert decode["<LLM_1>"]["category"] == "llm"

    # round-trips back to the original via reverse
    restored = tmp_path / "r.log"
    rc = main(["reverse", str(dst / "a.log"), str(restored),
               "--map", str(src / "_pii" / "decode.json")])
    assert rc == 0
    assert restored.read_text(encoding="utf-8") == (src / "a.log").read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# (b) Candidates that are existing aliases or not present are ignored.
# --------------------------------------------------------------------------

def test_existing_alias_and_absent_candidates_ignored(monkeypatch, tmp_path):
    src = tmp_path / "src"
    _write(src / "a.log", "ip 10.0.0.5 here\n")
    dst = tmp_path / "dst"

    # Model returns: an existing alias, a fragment not in the text, and NONE-ish
    # noise. None should be tokenised.
    rec = _Recorder(_ollama_resp("<IP_1>\nNOT-IN-THE-TEXT-AT-ALL\n<DEV0001.HOST_1>\n"))
    monkeypatch.setattr(llm_mod, "_http_post", rec)

    rc = main(["strip", str(src), str(dst), "--llm", "--no-progress"])
    assert rc == 0
    out = (dst / "a.log").read_text(encoding="utf-8")
    assert "<LLM_1>" not in out               # nothing was tokenised
    decode = json.loads((src / "_pii" / "decode.json").read_text())
    assert not any(m["category"] == "llm" for m in decode.values())


def test_second_pass_unit_validation(monkeypatch):
    # Direct unit test of second_pass against an AliasMap.
    text = "alias <IP_1> and residual SECRET-7 here"
    rec = _Recorder(_ollama_resp("<IP_1>\nSECRET-7\nGHOST\n"))
    monkeypatch.setattr(llm_mod, "_http_post", rec)
    amap = AliasMap()
    cfg = llm_mod.ProviderCfg(provider="ollama")  # local default
    new_text, count = llm_mod.second_pass(text, amap, provider_cfg=cfg)
    assert count == 1                          # only SECRET-7 survives validation
    assert "SECRET-7" not in new_text
    assert "<IP_1>" in new_text                # existing alias untouched
    assert "GHOST" not in text                 # never present, ignored


# --------------------------------------------------------------------------
# (c) A remote/cloud endpoint without --allow-cloud refuses and sends nothing.
# --------------------------------------------------------------------------

def test_cloud_endpoint_refused_without_allow_cloud(monkeypatch, tmp_path):
    src = tmp_path / "src"
    _write(src / "a.log", "ip 10.0.0.5\n")
    dst = tmp_path / "dst"

    rec = _Recorder()
    monkeypatch.setattr(llm_mod, "_http_post", rec)

    with pytest.raises(SystemExit):
        main(["strip", str(src), str(dst), "--llm",
              "--llm-provider", "openai",
              "--llm-endpoint", "https://api.openai.com",
              "--no-progress"])
    assert rec.calls == [], "NOTHING must be sent to a refused cloud endpoint"


def test_cloud_gate_unit_refusal_sends_nothing(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(llm_mod, "_http_post", rec)
    cfg = llm_mod.ProviderCfg(provider="anthropic",
                             endpoint="https://api.anthropic.com",
                             allow_cloud=False)
    with pytest.raises(llm_mod.LLMError):
        llm_mod.second_pass("already <IP_1> stripped", AliasMap(), provider_cfg=cfg)
    assert rec.calls == []


def test_cloud_allowed_warns_and_proceeds(monkeypatch):
    warnings_seen: list[str] = []
    cfg = llm_mod.ProviderCfg(provider="anthropic",
                             endpoint="https://api.anthropic.com",
                             allow_cloud=True)
    llm_mod.enforce_cloud_gate(cfg, warn=warnings_seen.append)
    assert warnings_seen and "EXTERNAL" in warnings_seen[0]


def test_is_local_endpoint():
    assert llm_mod.is_local_endpoint("http://127.0.0.1:11434")
    assert llm_mod.is_local_endpoint("http://localhost:11434")
    assert llm_mod.is_local_endpoint("http://[::1]:8080")
    assert not llm_mod.is_local_endpoint("https://api.openai.com")
    assert not llm_mod.is_local_endpoint("http://10.0.0.5:11434")


# --------------------------------------------------------------------------
# (d) Key read from named env var; absent key for a cloud provider errors;
#     key never in argv.
# --------------------------------------------------------------------------

def test_key_read_from_named_env_var(monkeypatch):
    monkeypatch.setenv("MY_SECRET_KEY", "sk-abc123")
    cfg = llm_mod.ProviderCfg(provider="openai",
                             endpoint="https://api.openai.com",
                             key_env="MY_SECRET_KEY", allow_cloud=True)
    assert llm_mod.load_key(cfg) == "sk-abc123"
    # and it lands in the request header, not anywhere we log
    url, headers, payload = llm_mod._build_request(cfg, "sk-abc123", "<IP_1> text")
    assert headers["Authorization"] == "Bearer sk-abc123"
    assert "sk-abc123" not in json.dumps(payload)


def test_missing_cloud_key_errors_clearly(monkeypatch):
    monkeypatch.delenv("ABSENT_KEY", raising=False)
    cfg = llm_mod.ProviderCfg(provider="anthropic",
                             endpoint="https://api.anthropic.com",
                             key_env="ABSENT_KEY", allow_cloud=True)
    with pytest.raises(llm_mod.LLMError) as ei:
        llm_mod.load_key(cfg)
    assert "ABSENT_KEY" in str(ei.value)


def test_local_provider_needs_no_key(monkeypatch):
    monkeypatch.delenv("PIISCRUB_LLM_KEY", raising=False)
    cfg = llm_mod.ProviderCfg(provider="ollama")
    assert llm_mod.load_key(cfg) is None


def test_key_never_in_argv(monkeypatch, tmp_path):
    # The CLI exposes --llm-key-env (the NAME), never a --llm-key (the value).
    from piiscrub.cli import build_parser
    parser = build_parser()
    help_text = parser.format_help()
    # there must be no flag that takes the key value itself
    assert "--llm-key " not in help_text
    # the env-var-name flag exists
    src = tmp_path / "src"
    _write(src / "a.log", "x\n")
    args = parser.parse_args(["strip", str(src), str(tmp_path / "d"),
                              "--llm", "--llm-key-env", "FOO"])
    assert args.llm_key_env == "FOO"
    # the parsed namespace carries the NAME, not a secret value
    assert not hasattr(args, "llm_key")


def test_forget_key_scrubs_env(monkeypatch, tmp_path):
    monkeypatch.setenv("PIISCRUB_LLM_KEY", "sk-temp")
    src = tmp_path / "src"
    _write(src / "a.log", "ip 10.0.0.5\n")
    dst = tmp_path / "dst"
    rec = _Recorder(_ollama_resp("NONE"))
    monkeypatch.setattr(llm_mod, "_http_post", rec)
    # local provider + forget-key: after the run the env var must be gone
    rc = main(["strip", str(src), str(dst), "--llm", "--forget-key", "--no-progress"])
    assert rc == 0
    import os
    assert "PIISCRUB_LLM_KEY" not in os.environ


# --------------------------------------------------------------------------
# (e) With --llm absent, no model call happens and output is identical.
# --------------------------------------------------------------------------

def test_no_llm_flag_no_call_identical_output(monkeypatch, tmp_path):
    src = tmp_path / "src"
    _write(src / "a.log", "ticket ACCT-99-XYZ for ip 10.0.0.5\n")

    rec = _Recorder(_ollama_resp("ACCT-99-XYZ\n"))
    monkeypatch.setattr(llm_mod, "_http_post", rec)

    # baseline strip WITHOUT --llm
    dst_no = tmp_path / "dst_no"
    rc = main(["strip", str(src), str(dst_no), "--no-progress"])
    assert rc == 0
    assert rec.calls == [], "no model call when --llm is absent"
    out_no = (dst_no / "a.log").read_text(encoding="utf-8")
    # the residual fragment is left untouched (regex doesn't catch it)
    assert "ACCT-99-XYZ" in out_no
    assert "<LLM_1>" not in out_no


# --------------------------------------------------------------------------
# Robustness: errors warn-and-continue (fail-open) by default; --llm-strict
# fails closed.
# --------------------------------------------------------------------------

def test_llm_error_fail_open_by_default(monkeypatch, tmp_path):
    src = tmp_path / "src"
    _write(src / "a.log", "ip 10.0.0.5\n")
    dst = tmp_path / "dst"

    def _boom(url, headers, payload, timeout):
        raise llm_mod.LLMError("simulated network failure")

    monkeypatch.setattr(llm_mod, "_http_post", _boom)
    rc = main(["strip", str(src), str(dst), "--llm", "--no-progress"])
    assert rc == 0                              # strip did not crash
    out = (dst / "a.log").read_text(encoding="utf-8")
    assert "<IP_1>" in out                      # regex output intact


def test_llm_strict_fails_closed(monkeypatch, tmp_path):
    src = tmp_path / "src"
    _write(src / "a.log", "ip 10.0.0.5\n")
    dst = tmp_path / "dst"

    def _boom(url, headers, payload, timeout):
        raise llm_mod.LLMError("simulated network failure")

    monkeypatch.setattr(llm_mod, "_http_post", _boom)
    rc = main(["strip", str(src), str(dst), "--llm", "--llm-strict", "--no-progress"])
    assert rc != 0                              # fail-closed
    # output was still written (regex result), strip itself didn't crash
    out = (dst / "a.log").read_text(encoding="utf-8")
    assert "<IP_1>" in out


# --------------------------------------------------------------------------
# verify_tree must not flag the new <LLM_n> aliases.
# --------------------------------------------------------------------------

def test_llm_aliases_pass_verify(monkeypatch, tmp_path):
    src = tmp_path / "src"
    _write(src / "a.log", "residual ACCT-99-XYZ and ip 10.0.0.5\n")
    dst = tmp_path / "dst"
    rec = _Recorder(_ollama_resp("ACCT-99-XYZ\n"))
    monkeypatch.setattr(llm_mod, "_http_post", rec)
    rc = main(["strip", str(src), str(dst), "--llm", "--no-progress"])
    assert rc == 0                              # verify ran and passed
    summary = json.loads((src / "_pii" / "report.json").read_text())
    assert summary["verify"] == "PASS"
    # an explicit verify of the stripped tree is also clean
    rc2 = main(["verify", str(dst), "--no-progress"])
    assert rc2 == 0


# --------------------------------------------------------------------------
# Provider response extraction across all three shapes.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("provider,resp", [
    ("ollama", _ollama_resp("FRAG-A\nFRAG-B\n")),
    ("openai", _openai_resp("FRAG-A\nFRAG-B\n")),
    ("anthropic", _anthropic_resp("FRAG-A\nFRAG-B\n")),
])
def test_extract_text_all_providers(provider, resp):
    text = llm_mod._extract_text(provider, resp)
    assert "FRAG-A" in text and "FRAG-B" in text


# ==========================================================================
# SECURITY-AUDIT REGRESSIONS
# ==========================================================================

# --- HIGH 1: a model candidate must never corrupt an existing alias token ---

def test_high1_candidate_cannot_corrupt_alias_token(monkeypatch):
    """Repro: stripped text contains <IP_1>; the model returns the substring
    "P_1" (which lives inside <IP_1>) plus a genuine residual "ACCT-77-XYZ".
    The blind str.replace path would turn <IP_1> into <I<LLM_n>> and break the
    reverse map. The alias-safe replace must leave <IP_1> intact and only alias
    the genuine residual; reverse must recover BOTH the original IP and ACCT."""
    text = "connect to <IP_1> now and acct ACCT-77-XYZ"
    rec = _Recorder(_ollama_resp("P_1\nACCT-77-XYZ\n"))
    monkeypatch.setattr(llm_mod, "_http_post", rec)
    amap = AliasMap()
    # Seed the IP alias so <IP_1> exists in the decode map and is reversible.
    amap.alias_for("10.9.9.9", "10.9.9.9", "ipv4", "IP", "f.log")
    cfg = llm_mod.ProviderCfg(provider="ollama")

    new_text, count = llm_mod.second_pass(text, amap, provider_cfg=cfg)

    # "P_1" overlapped the only existing alias span -> rejected (no-op).
    assert count == 1
    assert "<IP_1>" in new_text                       # alias token untouched
    assert "ACCT-77-XYZ" not in new_text              # genuine residual aliased
    assert "<I<LLM" not in new_text                   # no corruption

    # Round-trips: reverse recovers the original IP AND the residual.
    restored = reverse_text(new_text, amap.reverse_pairs())
    assert "10.9.9.9" in restored
    assert "ACCT-77-XYZ" in restored


def test_high1_validate_rejects_short_and_punctuation():
    """_validate rejects <3-char candidates and pure punctuation/whitespace."""
    text = "ab !!! 12 ok-frag here"
    assert llm_mod._validate("ab", text) is False        # too short (2 chars)
    assert llm_mod._validate("12", text) is False        # too short (2 chars)
    assert llm_mod._validate("!!!", text) is False       # punctuation only
    assert llm_mod._validate("   ", "x   y") is False     # whitespace only
    assert llm_mod._validate("ok-frag", text) is True     # real >=3 char frag


def test_high1_candidate_cap_limits_mass_replace(monkeypatch):
    """A hostile model returning thousands of distinct residual fragments must
    not alias more than MAX_CANDIDATES_PER_CALL of them."""
    cap = llm_mod.MAX_CANDIDATES_PER_CALL
    frags = [f"FRAG-{i:05d}" for i in range(cap + 50)]
    text = " ".join(frags)
    rec = _Recorder(_ollama_resp("\n".join(frags) + "\n"))
    monkeypatch.setattr(llm_mod, "_http_post", rec)
    amap = AliasMap()
    cfg = llm_mod.ProviderCfg(provider="ollama")
    _new_text, count = llm_mod.second_pass(text, amap, provider_cfg=cfg)
    assert count == cap


# --- HIGH 2: the auth header must never follow a redirect to another host ---

def test_high2_redirect_not_followed_no_header_leak():
    """_http_post must refuse to follow a 3xx; the x-api-key sent to the first
    host must NEVER reach the redirect target (key exfiltration)."""
    import http.server
    import threading

    seen = {"first": None, "second": None}
    state = {"port": None}

    class _Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            return

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            self.rfile.read(n)
            if self.path == "/redirect":
                seen["first"] = self.headers.get("x-api-key")
                self.send_response(302)
                self.send_header(
                    "Location", f"http://127.0.0.1:{state['port']}/leaked")
                self.end_headers()
            elif self.path == "/leaked":
                seen["second"] = self.headers.get("x-api-key")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"content":[{"type":"text","text":"NONE"}]}')
            else:
                self.send_response(404)
                self.end_headers()

    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    state["port"] = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{state['port']}/redirect"
        with pytest.raises(llm_mod.LLMError) as ei:
            llm_mod._http_post(url, {"x-api-key": "sk-SECRET"}, {"a": 1}, 5.0)
        assert "redirect" in str(ei.value).lower()
    finally:
        srv.shutdown()
    # The first hop saw the key (as configured); the redirect target NEVER did.
    assert seen["first"] == "sk-SECRET"
    assert seen["second"] is None


# --- MED 3: a malformed (scheme-less) endpoint must not crash the run ---

def test_med3_schemeless_endpoint_fail_open(monkeypatch, tmp_path):
    """A scheme-less endpoint (which makes urllib.request.Request raise
    ValueError) must flow through warn-and-continue in normal mode: the run
    completes (rc 0), the regex output is written, and no model call corrupts
    anything. Key env is present + --allow-cloud so the up-front gate passes and
    we reach the per-file request-build crash path."""
    monkeypatch.setenv("PIISCRUB_LLM_KEY", "sk-x")
    src = tmp_path / "src"
    _write(src / "a.log", "ip 10.0.0.5\n")
    dst = tmp_path / "dst"
    # _http_post must never be reached (the crash happens building the Request).
    rec = _Recorder()
    monkeypatch.setattr(llm_mod, "_http_post", rec)

    rc = main(["strip", str(src), str(dst), "--llm",
               "--llm-provider", "openai",
               "--llm-endpoint", "api.openai.com",   # scheme-less -> ValueError
               "--allow-cloud", "--no-progress"])
    assert rc == 0                                    # did NOT crash
    assert rec.calls == []                            # never sent anything
    out = (dst / "a.log").read_text(encoding="utf-8")
    assert "<IP_1>" in out                            # regex output intact


def test_med3_schemeless_endpoint_strict_clean_exit(monkeypatch, tmp_path):
    """Strict mode: a scheme-less endpoint yields a clean non-zero exit (not a
    crash); regex output and the decode map are still written."""
    monkeypatch.setenv("PIISCRUB_LLM_KEY", "sk-x")
    src = tmp_path / "src"
    _write(src / "a.log", "ip 10.0.0.5\n")
    dst = tmp_path / "dst"
    rec = _Recorder()
    monkeypatch.setattr(llm_mod, "_http_post", rec)

    rc = main(["strip", str(src), str(dst), "--llm", "--llm-strict",
               "--llm-provider", "openai",
               "--llm-endpoint", "api.openai.com",
               "--allow-cloud", "--no-progress"])
    assert rc != 0                                    # fail-closed, but clean
    assert rec.calls == []
    out = (dst / "a.log").read_text(encoding="utf-8")
    assert "<IP_1>" in out                            # regex output intact
    decode = json.loads((src / "_pii" / "decode.json").read_text())  # map written
    assert any(m["category"] == "ipv4" for m in decode.values())


def test_med3_validate_endpoint_helper():
    import pytest as _pytest
    with _pytest.raises(llm_mod.LLMError):
        llm_mod.validate_endpoint("api.openai.com")    # no scheme
    with _pytest.raises(llm_mod.LLMError):
        llm_mod.validate_endpoint("ftp://x/y")          # wrong scheme
    with _pytest.raises(llm_mod.LLMError):
        llm_mod.validate_endpoint("http://")            # no host
    # valid endpoints do not raise
    llm_mod.validate_endpoint("http://127.0.0.1:11434")
    llm_mod.validate_endpoint("https://api.anthropic.com")


# --- MED 4: --forget-key must scrub the env var even when the run errors ---

def test_med4_forget_key_scrubs_on_error(monkeypatch, tmp_path):
    """Even when the run fails, --forget-key must remove the key from os.environ
    (the finally-block scrub), not only on the fully-successful path."""
    import os
    monkeypatch.setenv("PIISCRUB_LLM_KEY", "sk-temp")
    src = tmp_path / "src"
    _write(src / "a.log", "ip 10.0.0.5\n")
    dst = tmp_path / "dst"

    # Force every per-file LLM call to fail, and run strict so the run exits
    # non-zero (an error path). The key must STILL be gone afterwards.
    def _boom(url, headers, payload, timeout):
        raise llm_mod.LLMError("simulated failure")

    monkeypatch.setattr(llm_mod, "_http_post", _boom)
    rc = main(["strip", str(src), str(dst), "--llm", "--llm-strict",
               "--forget-key", "--no-progress"])
    assert rc != 0                                    # the run errored
    assert "PIISCRUB_LLM_KEY" not in os.environ        # ...but key was scrubbed


# --- LOW 5: IPv4-mapped / translated IPv6 loopback is NON-local ---

def test_low5_ipv4_mapped_ipv6_is_not_local():
    # obvious loopback stays local
    assert llm_mod.is_local_endpoint("http://127.0.0.1:11434")
    assert llm_mod.is_local_endpoint("http://[::1]:8080")
    # IPv4-mapped loopback is rejected (NOT local)
    assert not llm_mod.is_local_endpoint("http://[::ffff:127.0.0.1]:8080")
    # IPv4-translated loopback is rejected (NOT local)
    assert not llm_mod.is_local_endpoint("http://[::ffff:0:127.0.0.1]:8080")


# --- LOW 6: the cloud "data WILL leave this machine" warning prints once ---

def test_low6_cloud_warning_once_per_run(monkeypatch, tmp_path):
    """With --allow-cloud and multiple files, the EXTERNAL-service warning is
    emitted ONCE (the CLI up-front gate), not once per file. The per-file
    second_pass gate call is silenced."""
    monkeypatch.setenv("PIISCRUB_LLM_KEY", "sk-x")
    src = tmp_path / "src"
    _write(src / "a.log", "ip 10.0.0.5\n")
    _write(src / "b.log", "ip 10.0.0.6\n")
    _write(src / "c.log", "ip 10.0.0.7\n")
    dst = tmp_path / "dst"

    rec = _Recorder(_anthropic_resp("NONE"))
    monkeypatch.setattr(llm_mod, "_http_post", rec)

    import sys as _sys
    captured: list[str] = []
    real_write = _sys.stderr.write

    def _capture(s):
        captured.append(s)
        return real_write(s)

    monkeypatch.setattr(_sys.stderr, "write", _capture)

    rc = main(["strip", str(src), str(dst), "--llm",
               "--llm-provider", "anthropic",
               "--llm-endpoint", "https://api.anthropic.com",
               "--allow-cloud", "--no-progress"])
    assert rc == 0
    # three files were processed (the model was called per file)
    assert len(rec.calls) == 3
    # the EXTERNAL-service warning appears exactly once across the whole run
    warns = [s for s in captured if "EXTERNAL" in s]
    assert len(warns) == 1
