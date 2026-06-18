import json
from pathlib import Path

from piiscrub.cli import main


def _make_src(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.log").write_text(
        "user jane@example.com from 10.0.0.5 hit https://api.example.com/v1\n"
        "again 10.0.0.5 mac de:ad:be:ef:00:11\n",
        encoding="utf-8",
    )
    return src


def test_selftest_passes(capsys):
    assert main(["--selftest"]) == 0


def test_scan_writes_no_stripped_output(tmp_path, capsys):
    src = _make_src(tmp_path)
    rc = main(["scan", str(src)])
    assert rc == 0
    assert (src / "_pii" / "scan_report.json").is_file()
    assert (src / "_pii" / "scan_report.html").is_file()
    # scan must not create a target / stripped tree
    assert list(tmp_path.iterdir()) == [src]


def test_strip_then_verify_clean(tmp_path, capsys):
    src = _make_src(tmp_path)
    dst = tmp_path / "dst"
    rc = main(["strip", str(src), str(dst)])
    assert rc == 0
    out = (dst / "app.log").read_text(encoding="utf-8")
    assert "10.0.0.5" not in out and "jane@example.com" not in out
    assert "<IP_1>" in out and out.count("<IP_1>") == 2  # consistency
    # decode map lives with originals, NOT in the stripped tree
    assert (src / "_pii" / "decode.json").is_file()
    assert not (dst / "_pii").exists()
    assert not (dst / "decode.json").exists()
    # report records a passing verify
    summary = json.loads((src / "_pii" / "report.json").read_text())
    assert summary["verify"] == "PASS"


def test_verify_catches_planted_leak(tmp_path, capsys):
    dst = tmp_path / "dst"
    dst.mkdir()
    (dst / "leak.log").write_text("oops raw 192.168.1.50 here", encoding="utf-8")
    rc = main(["verify", str(dst)])
    assert rc == 10


def test_reverse_restores_original(tmp_path, capsys):
    src = _make_src(tmp_path)
    dst = tmp_path / "dst"
    main(["strip", str(src), str(dst)])
    decode = src / "_pii" / "decode.json"
    restored = tmp_path / "restored.log"
    rc = main(["reverse", str(dst / "app.log"), str(restored), "--map", str(decode)])
    assert rc == 0
    assert restored.read_text(encoding="utf-8") == (src / "app.log").read_text(encoding="utf-8")


def test_strip_refuses_nested_target(tmp_path, capsys):
    src = _make_src(tmp_path)
    nested = src / "inside"
    try:
        main(["strip", str(src), str(nested)])
    except SystemExit as e:
        assert "nested" in str(e.code)
        return
    raise AssertionError("expected SystemExit for nested target")


# --------------------------------------------------------------------------
# FIX 4: --max-bytes / --stream-threshold use "is not None" + validate > 0.
# --------------------------------------------------------------------------

import argparse  # noqa: E402
from piiscrub.cli import _merge_cli_into_config  # noqa: E402
from piiscrub.config import Config  # noqa: E402


def _ns(**kw):
    base = dict(enable=None, disable=None, include=None, exclude=None,
                max_bytes=None, stream_threshold=None)
    base.update(kw)
    return argparse.Namespace(**base)


def test_max_bytes_zero_rejected():
    try:
        _merge_cli_into_config(Config(), _ns(max_bytes=0))
    except SystemExit as e:
        assert "--max-bytes" in str(e.code)
        return
    raise AssertionError("expected SystemExit for --max-bytes 0")


def test_stream_threshold_zero_rejected():
    try:
        _merge_cli_into_config(Config(), _ns(stream_threshold=0))
    except SystemExit as e:
        assert "--stream-threshold" in str(e.code)
        return
    raise AssertionError("expected SystemExit for --stream-threshold 0")


def test_negative_values_rejected():
    for kw in (dict(max_bytes=-1), dict(stream_threshold=-5)):
        try:
            _merge_cli_into_config(Config(), _ns(**kw))
        except SystemExit:
            continue
        raise AssertionError(f"expected SystemExit for {kw}")


def test_positive_values_applied():
    cfg = _merge_cli_into_config(Config(), _ns(max_bytes=123, stream_threshold=456))
    assert cfg.max_bytes == 123
    assert cfg.stream_threshold == 456


def test_none_leaves_defaults():
    default = Config()
    cfg = _merge_cli_into_config(Config(), _ns())  # both None
    assert cfg.max_bytes == default.max_bytes
    assert cfg.stream_threshold == default.stream_threshold
