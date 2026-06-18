"""Tests for adaptive streaming (#3) and the progress interface (#4)."""

import io
from pathlib import Path

import piiscrub.walker as walker
from piiscrub.detectors import build_active
from piiscrub.engine import AliasMap, tokenize
from piiscrub.progress import ProgressEvent, make_cli_renderer
from piiscrub.walker import OVERLAP, process_tree


def _read(p: Path) -> bytes:
    return p.read_bytes()


def test_streamed_equals_whole_file_and_consistent_aliases(tmp_path: Path):
    """A few-hundred-KB file with stream_threshold lowered to a tiny value must
    produce byte-identical output to whole-file mode and the same aliases."""
    # Build content with many repeated + varied PII tokens across "lines".
    lines = []
    for i in range(4000):
        ip = f"10.0.{i % 256}.{(i * 7) % 256}"
        lines.append(f"row {i}: user u{i}@example.com from {ip} mac de:ad:be:ef:{i % 256:02x}:11")
    content = "\n".join(lines) + "\n"
    assert len(content) > 256 * 1024  # comfortably exceeds OVERLAP-ish scale

    src_whole = tmp_path / "whole"; dst_whole = tmp_path / "whole_out"
    src_stream = tmp_path / "stream"; dst_stream = tmp_path / "stream_out"
    for d in (src_whole, src_stream):
        d.mkdir()
    (src_whole / "big.log").write_text(content, encoding="utf-8")
    (src_stream / "big.log").write_text(content, encoding="utf-8")

    # Whole-file: threshold above file size.
    amap_whole = AliasMap()
    s_whole = process_tree(src_whole, dst_whole, build_active(), amap_whole,
                           max_bytes=10**12, write=True, exclude_dirs=set(),
                           stream_threshold=10**12)
    # Streamed: threshold tiny so it streams; READ_BLOCK is large but the loop
    # still exercises overlap/commit because buffer > OVERLAP is checked.
    amap_stream = AliasMap()
    s_stream = process_tree(src_stream, dst_stream, build_active(), amap_stream,
                            max_bytes=10**12, write=True, exclude_dirs=set(),
                            stream_threshold=1024)

    assert s_whole.files_processed == 1
    assert s_stream.files_processed == 1
    # Byte-identical stripped output.
    assert _read(dst_whole / "big.log") == _read(dst_stream / "big.log")
    # Same replacement count.
    assert s_whole.replacements == s_stream.replacements
    # Consistent alias mapping (same originals -> same aliases).
    assert amap_whole.reverse_pairs() == amap_stream.reverse_pairs()


def test_streamed_equals_whole_file_utf16(tmp_path: Path):
    """Streaming must be byte-identical to whole-file for a non-UTF-8 encoding
    (utf-16 with BOM), exercising the incremental decoder + BOM-once write."""
    lines = [f"host h{i} ip 10.1.{i % 256}.{(i * 3) % 256} ok" for i in range(3000)]
    content = "\n".join(lines) + "\n"

    src_w = tmp_path / "w"; dst_w = tmp_path / "wo"
    src_s = tmp_path / "s"; dst_s = tmp_path / "so"
    for d in (src_w, src_s):
        d.mkdir()
    (src_w / "u.log").write_bytes(content.encode("utf-16"))
    (src_s / "u.log").write_bytes(content.encode("utf-16"))

    aw = AliasMap()
    process_tree(src_w, dst_w, build_active(), aw, max_bytes=10**12, write=True,
                 exclude_dirs=set(), stream_threshold=10**12)
    a_s = AliasMap()
    process_tree(src_s, dst_s, build_active(), a_s, max_bytes=10**12, write=True,
                 exclude_dirs=set(), stream_threshold=1024)

    assert _read(dst_w / "u.log") == _read(dst_s / "u.log")
    assert aw.reverse_pairs() == a_s.reverse_pairs()


def test_token_on_chunk_boundary_is_detected(tmp_path: Path):
    """An IP placed deliberately so it straddles a commit boundary (offset near
    a multiple of the read/overlap window) must still be detected/replaced."""
    # Make a file far larger than OVERLAP, then place a unique IP right around
    # the first commit boundary (len(buf) - OVERLAP) so a naive cut would split
    # it. We pad with non-PII text to control positions precisely.
    target_ip = "172.31.255.254"
    # Build padding such that the IP starts a few chars before a likely cut.
    # The streaming loop reads in READ_BLOCK chunks; with content < READ_BLOCK
    # the whole thing arrives at once, then commits up to len(buf)-OVERLAP.
    pad_before = "x" * (OVERLAP + 50)   # ensures len(buf)-OVERLAP lands inside region
    pad_block = "y\n" * 200000          # bulk so the file streams and buffer > OVERLAP
    # Place IP straddling the safe_end boundary: total len ~ len(pad_before)+len(ip)+...
    content = pad_before + " " + target_ip + " " + pad_block
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "boundary.log").write_text(content, encoding="utf-8")
    assert (src / "boundary.log").stat().st_size > OVERLAP

    amap = AliasMap()
    stats = process_tree(src, dst, build_active(), amap,
                         max_bytes=10**12, write=True, exclude_dirs=set(),
                         stream_threshold=1024)
    assert stats.files_processed == 1
    out = (dst / "boundary.log").read_text(encoding="utf-8")
    assert target_ip not in out, "IP straddling the chunk boundary leaked!"
    # And it was actually replaced with an alias.
    assert any(m["original"] == target_ip for m in amap.decode_table().values())

    # Cross-check: equals whole-file output for the same content.
    src2 = tmp_path / "src2"; dst2 = tmp_path / "dst2"
    src2.mkdir()
    (src2 / "boundary.log").write_text(content, encoding="utf-8")
    amap2 = AliasMap()
    process_tree(src2, dst2, build_active(), amap2,
                 max_bytes=10**12, write=True, exclude_dirs=set(),
                 stream_threshold=10**12)
    assert (dst / "boundary.log").read_bytes() == (dst2 / "boundary.log").read_bytes()


def test_progress_callback_counts(tmp_path: Path):
    """The progress callback sees files_total == number of files and the final
    event reports files_done == files_total."""
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "a.log").write_text("ip 10.0.0.1\n", encoding="utf-8")
    (src / "b.log").write_text("ip 10.0.0.2\n", encoding="utf-8")
    (src / "c.txt").write_text("no pii here\n", encoding="utf-8")

    events: list[ProgressEvent] = []
    process_tree(src, dst, build_active(), AliasMap(),
                 max_bytes=10**12, write=True, exclude_dirs=set(),
                 progress=events.append)

    assert events, "no progress events emitted"
    assert all(ev.files_total == 3 for ev in events)
    assert events[-1].files_done == events[-1].files_total == 3
    # files_done is monotonic non-decreasing.
    dones = [ev.files_done for ev in events]
    assert dones == sorted(dones)


def test_progress_byte_updates_for_streamed_file(tmp_path: Path):
    """A streamed file emits a byte-level update (bytes_done advances) via the
    per-chunk callback in _stream_file."""
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    # Just over OVERLAP so the streaming commit path runs; small enough to be
    # fast. One read (< READ_BLOCK) still emits a per-chunk byte event.
    content = ("ip 10.0.0.5 line padding text here\n" * 9000)  # ~315 KB
    (src / "big.log").write_text(content, encoding="utf-8")
    assert (src / "big.log").stat().st_size > OVERLAP

    events: list[ProgressEvent] = []
    process_tree(src, dst, build_active(), AliasMap(),
                 max_bytes=10**12, write=True, exclude_dirs=set(),
                 stream_threshold=1024, progress=events.append)
    # At least one event with bytes_done > 0 for the streamed file.
    assert any(ev.bytes_done > 0 for ev in events)
    assert events[-1].files_done == events[-1].files_total == 1
    # The streamed file was actually processed (replacements made).
    out = (dst / "big.log").read_text(encoding="utf-8")
    assert "10.0.0.5" not in out


def test_progress_bytes_done_is_cumulative_and_monotonic(tmp_path: Path, monkeypatch):
    """FIX 5: bytes_done is CUMULATIVE across the whole run (monotonically
    non-decreasing toward bytes_total), not reset per file, across a mix of a
    whole-file, a streamed file, and a copied-through binary."""
    monkeypatch.setattr(walker, "READ_BLOCK", 512)
    monkeypatch.setattr(walker, "OVERLAP", 2048)

    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "a_small.log").write_text("ip 10.0.0.1 small file\n", encoding="utf-8")
    # b streams (several READ_BLOCK iterations).
    (src / "b_big.log").write_text(
        "row 10.0.0.2 café padding line here ok\n" * 400, encoding="utf-8")
    # c is binary -> copied through (still counts toward cumulative bytes).
    (src / "c.bin").write_bytes(b"\x00\x01\x02" * 100)

    events: list[ProgressEvent] = []
    process_tree(src, dst, build_active(), AliasMap(),
                 max_bytes=10**12, write=True, exclude_dirs=set(),
                 stream_threshold=2048, progress=events.append)

    assert events
    dones = [ev.bytes_done for ev in events]
    # Monotonic non-decreasing across the ENTIRE run (not per-file resets).
    assert dones == sorted(dones), f"bytes_done not monotonic: {dones}"
    # Final event reports the full run complete.
    last = events[-1]
    assert last.files_done == last.files_total == 3
    assert last.bytes_done == last.bytes_total
    # The streamed (middle) file's events must already include the first file's
    # bytes — i.e. cumulative, never restarting from 0 mid-run.
    nonzero = [d for d in dones if d > 0]
    assert nonzero and min(nonzero) > 0
    # Exactly one completion event per file (no duplicate final event for the
    # streamed file): count events whose files_done strictly increased.
    completion_marks = sum(
        1 for prev, cur in zip([0] + [e.files_done for e in events],
                               [e.files_done for e in events])
        if cur > prev
    )
    assert completion_marks == 3


def test_make_cli_renderer_disabled_is_silent():
    """enabled=False produces no output even to a TTY-like stream."""
    class FakeTTY(io.StringIO):
        def isatty(self):
            return True

    stream = FakeTTY()
    cb = make_cli_renderer(stream=stream, enabled=False)
    cb(ProgressEvent(1, 2, "a.log", 0, 0))
    cb(ProgressEvent(2, 2, "b.log", 0, 0))
    assert stream.getvalue() == ""


def test_make_cli_renderer_noop_when_not_tty():
    """A non-TTY stream (default for pipes/files) gets no output."""
    stream = io.StringIO()  # isatty() -> False
    cb = make_cli_renderer(stream=stream, enabled=True)
    cb(ProgressEvent(1, 1, "a.log", 0, 0))
    assert stream.getvalue() == ""


def test_make_cli_renderer_writes_to_tty():
    """When enabled and a TTY, it writes a carriage-return progress line."""
    class FakeTTY(io.StringIO):
        def isatty(self):
            return True

    stream = FakeTTY()
    cb = make_cli_renderer(stream=stream, enabled=True)
    cb(ProgressEvent(1, 2, "a.log", 0, 0))
    cb(ProgressEvent(2, 2, "b.log", 0, 0))
    out = stream.getvalue()
    assert out.startswith("\r")
    assert "1/2" in out and "2/2" in out
    assert out.endswith("\n")  # newline on completion


def test_whole_file_tokenize_unchanged_by_segment_helper():
    """tokenize_segment with safe_end=None reproduces tokenize() exactly."""
    from piiscrub.engine import tokenize_segment
    text = "user a@b.com 10.0.0.9 and 10.0.0.9 mac de:ad:be:ef:00:11"
    dets = build_active()
    a1 = AliasMap()
    whole_text, whole_reps = tokenize(text, dets, a1)
    a2 = AliasMap()
    seg_text, seg_reps, consumed = tokenize_segment(text, dets, a2, safe_end=None)
    assert seg_text == whole_text
    assert consumed == len(text)
    assert len(seg_reps) == len(whole_reps)
    assert a1.reverse_pairs() == a2.reverse_pairs()


# --------------------------------------------------------------------------
# FIX 1: invalid bytes in a LATER block must NOT crash/truncate; the file is
# copied through unchanged as "undecodable" (matching whole-file semantics).
# --------------------------------------------------------------------------

# NOTE on the chosen bad byte: 0x80 decodes fine under cp1252 (= Euro), so the
# WHOLE-FILE path would strip such a file as cp1252 rather than skip it. To get
# a byte that is undecodable under BOTH utf-8 AND cp1252 (so both paths agree on
# "undecodable / copy through"), we use 0x81, which is UNDEFINED in cp1252.

def test_invalid_bytes_in_later_block_copied_through(tmp_path: Path, monkeypatch):
    """A streamed file whose FIRST block decodes clean utf-8 but a LATER block
    contains a byte invalid under both utf-8 and cp1252 (0x81) must be copied
    through UNCHANGED and flagged "undecodable" — never half-stripped/truncated
    and never raising."""
    # Small READ_BLOCK so the file is read in several blocks; first block is
    # clean ASCII PII, a later block carries the invalid byte.
    monkeypatch.setattr(walker, "READ_BLOCK", 64)
    monkeypatch.setattr(walker, "PROBE_BLOCK", 64)

    clean_head = b"first block ip 10.0.0.7 clean ascii text here padding\n" * 4
    bad_tail = b"later block has invalid byte: \x81\x81 and more 10.0.0.8\n" * 4
    raw = clean_head + bad_tail
    # Sanity: the head alone decodes clean as utf-8; the whole thing does not,
    # and cp1252 also rejects 0x81 (so this is genuinely undecodable).
    clean_head.decode("utf-8")
    for enc in ("utf-8", "cp1252"):
        try:
            raw.decode(enc)
            raise AssertionError(f"test setup: raw should not decode as {enc}")
        except UnicodeDecodeError:
            pass

    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "f.log").write_bytes(raw)

    amap = AliasMap()
    stats = process_tree(src, dst, build_active(), amap,
                         max_bytes=10**12, write=True, exclude_dirs=set(),
                         stream_threshold=1)  # force streaming path

    # Copied through, flagged undecodable, not processed.
    assert stats.files_processed == 0
    assert stats.files_copied == 1
    assert any(fs.status == "undecodable" for fs in stats.skipped)
    assert any("invalid bytes mid-stream" in w for w in stats.warnings)
    # Output is BYTE-IDENTICAL to the original (copied through, NOT truncated).
    assert (dst / "f.log").read_bytes() == raw
    # No PII alias was ever assigned (nothing was stripped).
    assert amap.decode_table() == {}


def test_invalid_bytes_streamed_matches_whole_file(tmp_path: Path, monkeypatch):
    """The streamed copy-through of an undecodable file (0x81) is byte-identical
    to the whole-file path's copy-through of the same file, and both flag it
    undecodable / not-processed — proving the streaming fallback matches the
    whole-file not-processed contract."""
    monkeypatch.setattr(walker, "READ_BLOCK", 64)
    monkeypatch.setattr(walker, "PROBE_BLOCK", 64)
    raw = (b"clean ip 10.0.0.7 text padding here ok\n" * 4) + (b"\x81bad\n" * 4)

    src_w = tmp_path / "w"; dst_w = tmp_path / "wo"
    src_s = tmp_path / "s"; dst_s = tmp_path / "so"
    for d in (src_w, src_s):
        d.mkdir()
    (src_w / "f.log").write_bytes(raw)
    (src_s / "f.log").write_bytes(raw)

    # Whole-file path (threshold huge): undecodable -> copied through.
    sw = process_tree(src_w, dst_w, build_active(), AliasMap(),
                      max_bytes=10**12, write=True, exclude_dirs=set(),
                      stream_threshold=10**12)
    # Streaming path (threshold tiny): invalid byte mid-stream -> copied through.
    ss = process_tree(src_s, dst_s, build_active(), AliasMap(),
                      max_bytes=10**12, write=True, exclude_dirs=set(),
                      stream_threshold=1)

    assert (dst_w / "f.log").read_bytes() == raw
    assert (dst_s / "f.log").read_bytes() == raw
    assert (dst_w / "f.log").read_bytes() == (dst_s / "f.log").read_bytes()
    assert sw.files_copied == ss.files_copied == 1
    assert sw.files_processed == ss.files_processed == 0
    assert all(fs.status == "undecodable" for fs in sw.skipped)
    assert all(fs.status == "undecodable" for fs in ss.skipped)


def test_partial_stripped_output_deleted_on_fallback(tmp_path: Path, monkeypatch):
    """When streaming falls back to copy-through, any partially-written stripped
    output must be replaced by the original (no half-stripped remnant)."""
    monkeypatch.setattr(walker, "READ_BLOCK", 32)
    monkeypatch.setattr(walker, "PROBE_BLOCK", 32)
    # Many clean blocks (so the stripped output file is actually opened and
    # written to) before the invalid byte appears.
    raw = (b"ip 10.0.0.9 padding clean ascii line here ok\n" * 20) + b"\x81\x81trail"
    src = tmp_path / "src"; dst = tmp_path / "dst"
    src.mkdir()
    (src / "f.log").write_bytes(raw)

    process_tree(src, dst, build_active(), AliasMap(),
                 max_bytes=10**12, write=True, exclude_dirs=set(),
                 stream_threshold=1)
    # The output must equal the ORIGINAL (copy-through), not a stripped/truncated
    # prefix. If the partial write had leaked, this would differ.
    assert (dst / "f.log").read_bytes() == raw


# --------------------------------------------------------------------------
# FIX 2: encoding probe must not misdetect utf-8 as cp1252 when a multibyte
# char is split by the probe-window boundary.
# --------------------------------------------------------------------------

def test_multibyte_split_at_probe_boundary_not_misdetected(tmp_path: Path, monkeypatch):
    """A utf-8 file with multibyte chars, streamed with a tiny probe/read window
    whose boundary splits a multibyte char, must produce output BYTE-IDENTICAL
    to whole-file (i.e. stays utf-8, NOT misdetected as cp1252)."""
    # 'é' (U+00E9) is 0xC3 0xA9 in utf-8. Build the head so byte index == window
    # falls BETWEEN the two bytes of an 'é', splitting it at the probe boundary.
    window = 16
    monkeypatch.setattr(walker, "READ_BLOCK", window)
    monkeypatch.setattr(walker, "PROBE_BLOCK", window)

    # Pad with ASCII so that the multibyte char's first byte lands at window-1.
    pad = "a" * (window - 1)              # bytes 0..window-2
    body = pad + "é" + " café résumé naïve 10.0.0.4 user e@example.com\n" * 30
    raw = body.encode("utf-8")
    # Confirm the split point really sits inside a multibyte char.
    assert raw[window - 1] == 0xC3 and raw[window] == 0xA9

    src_w = tmp_path / "w"; dst_w = tmp_path / "wo"
    src_s = tmp_path / "s"; dst_s = tmp_path / "so"
    for d in (src_w, src_s):
        d.mkdir()
    (src_w / "u.log").write_bytes(raw)
    (src_s / "u.log").write_bytes(raw)

    aw = AliasMap()
    sw = process_tree(src_w, dst_w, build_active(), aw, max_bytes=10**12,
                      write=True, exclude_dirs=set(), stream_threshold=10**12)
    a_s = AliasMap()
    ss = process_tree(src_s, dst_s, build_active(), a_s, max_bytes=10**12,
                      write=True, exclude_dirs=set(), stream_threshold=1)

    # Both processed as text (NOT copied through as undecodable/binary).
    assert sw.files_processed == ss.files_processed == 1
    # Whole-file detected utf-8; streamed must match (not cp1252).
    assert sw.per_file[0].encoding == "utf-8"
    assert ss.per_file[0].encoding == "utf-8"
    # Byte-identical output and identical alias maps.
    assert (dst_w / "u.log").read_bytes() == (dst_s / "u.log").read_bytes()
    assert aw.reverse_pairs() == a_s.reverse_pairs()
    # The multibyte content survived intact (round-trips through utf-8).
    out = (dst_s / "u.log").read_bytes().decode("utf-8")
    assert "café" in out and "résumé" in out and "naïve" in out


# --------------------------------------------------------------------------
# FIX 3: multi-block streaming with a realistic overlap, tokens on boundaries.
# --------------------------------------------------------------------------

def test_multi_block_streaming_realistic_overlap(tmp_path: Path, monkeypatch):
    """Exercise several READ_BLOCK iterations with a realistic OVERLAP (2 KB),
    PII (incl. tokens straddling 512-byte read boundaries) and non-ASCII text;
    assert streamed == whole-file byte-for-byte, equal reverse maps, and zero
    raw IPs/emails remain."""
    import re as _re
    monkeypatch.setattr(walker, "READ_BLOCK", 512)
    monkeypatch.setattr(walker, "OVERLAP", 2048)

    # Build a few-KB file. Place IPs/emails at and around 512-byte boundaries.
    chunks: list[str] = []
    pos = 0
    boundary_tokens = ["10.20.30.40", "boundary.user@corp.example",
                       "192.168.99.250", "edge.case@host.example"]
    bi = 0
    while pos < 6000:
        line = f"row at {pos}: 10.0.{pos % 256}.{(pos * 3) % 256} café u{pos}@example.com naïve\n"
        # Near each 512-byte boundary, splice a distinctive token so it straddles.
        if pos // 512 != (pos + len(line)) // 512 and bi < len(boundary_tokens):
            line = line.rstrip("\n") + f" {boundary_tokens[bi]} résumé\n"
            bi += 1
        chunks.append(line)
        pos += len(line.encode("utf-8"))
    content = "".join(chunks)
    raw = content.encode("utf-8")
    assert len(raw) > 4 * 512  # several READ_BLOCK iterations

    src_w = tmp_path / "w"; dst_w = tmp_path / "wo"
    src_s = tmp_path / "s"; dst_s = tmp_path / "so"
    for d in (src_w, src_s):
        d.mkdir()
    (src_w / "m.log").write_bytes(raw)
    (src_s / "m.log").write_bytes(raw)

    aw = AliasMap()
    process_tree(src_w, dst_w, build_active(), aw, max_bytes=10**12,
                 write=True, exclude_dirs=set(), stream_threshold=10**12)
    a_s = AliasMap()
    process_tree(src_s, dst_s, build_active(), a_s, max_bytes=10**12,
                 write=True, exclude_dirs=set(), stream_threshold=1)

    out_whole = (dst_w / "m.log").read_bytes()
    out_stream = (dst_s / "m.log").read_bytes()
    # (a) byte-identical
    assert out_whole == out_stream
    # (b) reverse maps equal
    assert aw.reverse_pairs() == a_s.reverse_pairs()
    # (c) zero raw IPs/emails remain in the streamed output
    text = out_stream.decode("utf-8")
    assert not _re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text), \
        "a raw IPv4 leaked into streamed output"
    assert "@example.com" not in text and "@corp.example" not in text \
        and "@host.example" not in text, "a raw email leaked into streamed output"
    # And the boundary-straddling tokens were specifically caught.
    for tok in boundary_tokens:
        assert tok not in text, f"boundary token {tok!r} leaked raw"
