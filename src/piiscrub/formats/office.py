"""docx / xlsx / pptx text extraction -> scrubbed text/CSV derivative.

All three OOXML families are ZIP containers of XML parts, so this handler reads
them with :mod:`zipfile` + :mod:`xml.etree.ElementTree` (stdlib only — never
``openpyxl``/``python-docx``) and produces a *text derivative* rather than a
re-serialised document:

* ``report.docx`` / ``deck.pptx`` -> ``….txt`` (one line per paragraph),
* ``book.xlsx``                  -> ``….csv`` (``# sheet: <name>`` sections,
  one CSV line per row).

Rationale (design doc, decision #3): re-writing OOXML risks corrupt documents,
and aliases contain ``<``/``>`` which would need XML-escaping *inside* the
document body — a text export is safe, shareable, and goes through the one proven
tokeniser. Every recovered string (paragraph text, cell, slide/notes run, and
``docProps/core.xml`` author names) is concatenated and handed to the walker's
``scrub`` closure once, so this module never imports the engine or sees aliases.

Fail-open invariant (see ``base.py``): an OLE/encrypted container, a non-OOXML
zip, or malformed XML in a *primary* part raises :class:`ExtractError`, and the
walker copies the original through + flags it. Nothing is written before the
whole derivative has been built and scrubbed in memory, so an ``ExtractError``
never leaves a partial derivative behind; a failure *during* the final write
deletes the half-written file before re-raising.
"""

from __future__ import annotations

import csv
import io
import posixpath
import re
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path

from . import register
from .base import ExtractError, ExtractLimits, ExtractOutcome, ScrubFn


def _local(tag: str) -> str:
    """Return an element/attribute's local name, dropping any ``{ns}`` prefix.

    OOXML parts differ only in namespace URI across producers (Word, LibreOffice,
    …); matching on the local name keeps the reader robust without pinning exact
    namespace strings."""
    return tag.rsplit("}", 1)[-1]


def _read_xml(zf: zipfile.ZipFile, name: str) -> ET.Element:
    """Parse a zip member as XML or raise :class:`ExtractError`.

    Used for *primary* parts (``word/document.xml``, worksheets, slides) whose
    corruption means the document cannot be trusted to have been fully read."""
    try:
        return ET.fromstring(zf.read(name))
    except ET.ParseError as e:
        raise ExtractError(f"malformed XML in {name}: {e}") from e


def _paragraph_lines(root: ET.Element) -> list[str]:
    """One text line per paragraph (``<w:p>`` / ``<a:p>``), concatenating the
    ``<w:t>`` / ``<a:t>`` runs inside it in document order.

    Runs are joined *within* a paragraph so a value split across runs (Word/
    PowerPoint routinely fragment a typed email into several ``<*:t>`` nodes) is
    reassembled before scrubbing and cannot leak."""
    out: list[str] = []
    for p in root.iter():
        if _local(p.tag) != "p":
            continue
        out.append("".join(t.text or "" for t in p.iter() if _local(t.tag) == "t"))
    return out


# ----------------------------------------------------------------------
# docProps/core.xml — author usernames

def _author_lines(zf: zipfile.ZipFile) -> list[str]:
    """``# author: <name>`` lines for ``dc:creator`` / ``cp:lastModifiedBy``.

    These core properties routinely hold usernames, so they are extracted and
    scrubbed like body text. Malformed/absent core props are non-fatal (the
    document body is still worth extracting) — they simply contribute no lines."""
    if "docProps/core.xml" not in zf.namelist():
        return []
    try:
        root = ET.fromstring(zf.read("docProps/core.xml"))
    except ET.ParseError:
        return []
    out: list[str] = []
    for e in root.iter():
        if _local(e.tag) in ("creator", "lastModifiedBy"):
            val = (e.text or "").strip()
            if val:
                out.append(f"# author: {val}")
    return out


# ----------------------------------------------------------------------
# docx

_HEADER_FOOTER = re.compile(r"(?:header|footer)\d+\.xml$")


def _docx(zf: zipfile.ZipFile, emit) -> None:
    names = zf.namelist()
    if "word/document.xml" not in names:
        raise ExtractError("not a docx (no word/document.xml)")
    for line in _paragraph_lines(_read_xml(zf, "word/document.xml")):
        emit(line)

    # Headers/footers/footnotes/endnotes/comments — same <w:t>/<w:p> model.
    # A malformed *auxiliary* part is skipped with a note rather than failing the
    # whole extraction (the main body was read cleanly).
    for n in sorted(names):
        base = n.rsplit("/", 1)[-1]
        if not n.startswith("word/"):
            continue
        if not (_HEADER_FOOTER.match(base)
                or base in ("footnotes.xml", "endnotes.xml", "comments.xml")):
            continue
        try:
            root = ET.fromstring(zf.read(n))
        except ET.ParseError:
            emit(f"# skipped malformed part {n}")
            continue
        plines = _paragraph_lines(root)
        if any(p.strip() for p in plines):
            emit(f"# {n}")
            for line in plines:
                emit(line)


# ----------------------------------------------------------------------
# xlsx

def _shared_strings(zf: zipfile.ZipFile) -> list[str]:
    name = "xl/sharedStrings.xml"
    if name not in zf.namelist():
        return []
    root = _read_xml(zf, name)
    out: list[str] = []
    for si in root:
        if _local(si.tag) != "si":
            continue
        out.append("".join(t.text or "" for t in si.iter() if _local(t.tag) == "t"))
    return out


def _workbook_rels(zf: zipfile.ZipFile) -> dict[str, str]:
    """Relationship-id -> target path (relative to ``xl/``) for the workbook."""
    name = "xl/_rels/workbook.xml.rels"
    if name not in zf.namelist():
        return {}
    try:
        root = ET.fromstring(zf.read(name))
    except ET.ParseError:
        return {}
    out: dict[str, str] = {}
    for rel in root.iter():
        if _local(rel.tag) == "Relationship":
            rid, target = rel.get("Id"), rel.get("Target")
            if rid and target:
                out[rid] = target
    return out


# Excel's real maximum column is XFD (16384). Cell refs are clamped to it so a
# CRAFTED ref like ``r="ZZZZZZZZ1"`` (which decodes to ~2.2e11) cannot make
# ``_emit_sheet`` build a per-row list of that many cells: that allocation raises
# MemoryError, which is NOT an ExtractError, so the whole strip/scan run would
# abort with a traceback instead of falling back to copy-through+flag. The
# malicious XML part is only a few hundred bytes, so the declared-size pre-check
# in ``_OfficeHandler.process`` does not catch it — this clamp is the guard.
_MAX_COL = 16384


def _col_index(ref: str) -> int:
    """Excel cell ref (``"AB12"``) -> 1-based column index (``28``), clamped to
    Excel's real column maximum :data:`_MAX_COL` (XFD, 16384).

    The clamp is a fail-safe against a crafted cell ref with many column letters
    (see :data:`_MAX_COL`); a real worksheet never exceeds 16384 columns."""
    letters = ""
    for ch in ref:
        if not ch.isalpha():
            break
        letters += ch.upper()
        if len(letters) >= 4:
            # 4+ column letters already exceed XFD; stop before building a huge
            # index (and never accumulate an unbounded-length ``letters`` string).
            return _MAX_COL
    idx = 0
    for ch in letters:
        idx = idx * 26 + (ord(ch) - 64)
    return min(idx, _MAX_COL) or 1


def _cell_value(c: ET.Element, shared: list[str]) -> str:
    """Resolve a ``<c>`` cell to its display string.

    Shared-string cells (``t="s"``) index into ``shared``; ``t="inlineStr"``
    holds its text inline; everything else (numeric, formula-string ``str``,
    boolean, date) uses the ``<v>`` value verbatim."""
    t = c.get("t")
    if t == "s":
        v = next((e.text for e in c if _local(e.tag) == "v"), None)
        if v is None:
            return ""
        try:
            idx = int(v)
        except (TypeError, ValueError):
            return ""
        return shared[idx] if 0 <= idx < len(shared) else ""
    if t == "inlineStr":
        return "".join(e.text or "" for e in c.iter() if _local(e.tag) == "t")
    v = next((e.text for e in c if _local(e.tag) == "v"), None)
    if v is not None:
        return v
    # Defensive: some producers emit a bare <t> without the <is> wrapper.
    return next((e.text or "" for e in c.iter() if _local(e.tag) == "t"), "")


def _csv_line(cells: list[str]) -> str:
    """Format one row as a single CSV line (no trailing newline)."""
    buf = io.StringIO()
    csv.writer(buf, lineterminator="").writerow(cells)
    return buf.getvalue()


def _emit_sheet(zf: zipfile.ZipFile, path: str, shared: list[str], emit) -> None:
    root = _read_xml(zf, path)
    for row in root.iter():
        if _local(row.tag) != "row":
            continue
        cells: dict[int, str] = {}
        next_col = 1
        maxcol = 0
        for c in row:
            if _local(c.tag) != "c":
                continue
            ref = c.get("r")
            col = _col_index(ref) if ref else next_col
            next_col = col + 1
            cells[col] = _cell_value(c, shared)
            maxcol = max(maxcol, col)
        emit(_csv_line([cells.get(i, "") for i in range(1, maxcol + 1)]))


def _xlsx(zf: zipfile.ZipFile, emit) -> None:
    names = zf.namelist()
    shared = _shared_strings(zf)

    worksheet_files = sorted(
        n for n in names
        if n.startswith("xl/worksheets/") and n.endswith(".xml") and "/_rels/" not in n
    )

    # Preferred order + names come from workbook.xml -> relationship targets.
    ordered: list[tuple[str, str]] = []
    used: set[str] = set()
    if "xl/workbook.xml" in names:
        wb = _read_xml(zf, "xl/workbook.xml")
        rels = _workbook_rels(zf)
        for sh in wb.iter():
            if _local(sh.tag) != "sheet":
                continue
            name = sh.get("name") or ""
            rid = next((v for k, v in sh.attrib.items() if _local(k) == "id"), None)
            target = rels.get(rid) if rid else None
            path = None
            if target:
                t = target[1:] if target.startswith("/") else "xl/" + target
                t = posixpath.normpath(t)
                if t in names:
                    path = t
            if path is None:  # rels missing/broken: fall back to file order
                path = next((w for w in worksheet_files if w not in used), None)
            if path:
                used.add(path)
                ordered.append((name or path, path))

    # No workbook mapping (or none resolved): emit worksheet files directly.
    for i, w in enumerate(worksheet_files, 1):
        if w not in used:
            ordered.append((f"Sheet{i}", w))
            used.add(w)

    if not ordered:
        raise ExtractError("no worksheets found (not an xlsx?)")

    for name, path in ordered:
        emit(f"# sheet: {name}")
        _emit_sheet(zf, path, shared, emit)


# ----------------------------------------------------------------------
# pptx

_SLIDE = re.compile(r"ppt/slides/slide(\d+)\.xml$")


def _pptx(zf: zipfile.ZipFile, emit) -> None:
    names = zf.namelist()
    slides = sorted(
        (n for n in names if _SLIDE.match(n)),
        key=lambda n: int(_SLIDE.match(n).group(1)),
    )
    if not slides:
        raise ExtractError("no slides found (not a pptx?)")
    for path in slides:
        num = int(_SLIDE.match(path).group(1))
        emit(f"# slide {num}")
        for line in _paragraph_lines(_read_xml(zf, path)):
            emit(line)
        notes = f"ppt/notesSlides/notesSlide{num}.xml"
        if notes in names:
            try:
                root = ET.fromstring(zf.read(notes))
            except ET.ParseError:
                emit(f"# skipped malformed part {notes}")
                continue
            note_lines = [ln for ln in _paragraph_lines(root) if ln]
            if note_lines:
                emit(f"# slide {num} notes")
                for line in note_lines:
                    emit(line)


class _OfficeHandler:
    """Extract visible text/cells from an OOXML document into a scrubbed
    derivative (``.docx``/``.pptx`` -> ``.txt``, ``.xlsx`` -> ``.csv``).

    Kind is always ``"derivative"``.
    """

    name = "office"
    suffixes = (".docx", ".xlsx", ".pptx")

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
        suffix = path.suffix.lower()
        ext = ".csv" if suffix == ".xlsx" else ".txt"

        # Accumulate the derivative in memory with a running byte guard so a
        # decompression-bomb OOXML trips ``max_out_bytes`` (-> ExtractError ->
        # copy+flag) before it can exhaust memory. Nothing is written yet, so
        # tripping the guard leaves no partial output.
        lines: list[str] = []
        budget = limits.max_out_bytes
        used = 0

        def emit(line: str) -> None:
            nonlocal used
            used += len(line.encode("utf-8")) + 1
            if used > budget:
                raise ExtractError(
                    f"expanded text exceeds max_out_bytes ({budget})")
            lines.append(line)

        try:
            zf = zipfile.ZipFile(path)
        except (zipfile.BadZipFile, OSError) as e:
            # OLE/encrypted container or plain garbage — not a readable zip.
            raise ExtractError(
                f"not a readable OOXML zip (encrypted/corrupt?): {e}") from e

        try:
            with zf:
                # Decompression-bomb pre-check (mirrors archives.py): reject any
                # part whose DECLARED uncompressed size already exceeds the budget
                # before ``zf.read`` materialises it. The per-emit() byte guard
                # only trips AFTER a part is fully decompressed into memory, so a
                # tiny .docx whose document.xml expands to several GB would
                # otherwise exhaust RAM before the first emit().
                for info in zf.infolist():
                    if info.file_size > budget:
                        raise ExtractError(
                            f"OOXML part {info.filename!r} declares "
                            f"{info.file_size} bytes > max_out_bytes ({budget})")
                for author in _author_lines(zf):
                    emit(author)
                if suffix == ".docx":
                    _docx(zf, emit)
                elif suffix == ".xlsx":
                    _xlsx(zf, emit)
                else:
                    _pptx(zf, emit)
        except RuntimeError as e:
            # zipfile raises RuntimeError("File is encrypted ...") when reading an
            # encrypted member of an otherwise-openable container.
            raise ExtractError(f"encrypted OOXML member: {e}") from e
        except (zipfile.BadZipFile, NotImplementedError, EOFError, OSError,
                zlib.error) as e:
            # A member with a bad CRC raises BadZipFile, a broken deflate stream
            # raises zlib.error, an unsupported compression method raises
            # NotImplementedError — all from ``zf.read`` INSIDE the body (central
            # directory intact, member bytes corrupt). Convert to ExtractError so
            # the walker falls back to copy-through + flag instead of aborting the
            # whole run.
            raise ExtractError(f"corrupt OOXML member: {e}") from e

        text = "\n".join(lines)
        if text:
            text += "\n"
        scrubbed, n = scrub(f"{rel}!body", text)

        out_rel = rel + ext
        if write and out_path is not None:
            deriv = out_path.parent / (out_path.name + ext)
            try:
                deriv.parent.mkdir(parents=True, exist_ok=True)
                deriv.write_text(scrubbed, encoding="utf-8")
            except OSError as e:
                # A failure mid-write must not leave a truncated derivative for
                # the copy-through fallback to race with (fail-open invariant),
                # AND must not abort the whole run: convert to ExtractError so the
                # walker copies the original through under its (shorter) name +
                # flags it. Concretely, a source whose name + ext exceeds NAME_MAX
                # raises OSError(ENAMETOOLONG) here; the copy-through fallback
                # succeeds because it writes the original, shorter name.
                # NB: unlink is guarded because ``Path.exists()``/``unlink`` on a
                # too-long name itself raises OSError, which would otherwise mask
                # the conversion and re-abort the run.
                try:
                    deriv.unlink()
                except OSError:
                    pass
                raise ExtractError(f"could not write derivative: {e}") from e
        return ExtractOutcome(kind="derivative", out_rel=out_rel, replacements=n)


HANDLER = register(_OfficeHandler())
