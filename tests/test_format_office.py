"""Tests for the office (docx / xlsx / pptx) format extractor.

Every fixture is a minimal OOXML document assembled programmatically with
:mod:`zipfile` — no binary blobs live in git. The assertions all follow the same
contract: real PII placed in paragraphs / cells / slide notes / core-props must
appear ALIASED in the derivative and never survive raw, the derivative gets the
right suffix (``.txt`` for docx/pptx, ``.csv`` for xlsx), and an OLE/encrypted /
garbage container or malformed primary XML falls open to :class:`ExtractError`.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from piiscrub.detectors import build_active
from piiscrub.engine import AliasMap, reverse_text, tokenize
from piiscrub.formats import ExtractError, ExtractLimits, get_handler
from piiscrub.walker import process_tree

# OOXML namespace URIs (exact strings a real producer emits).
NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS_S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
NS_A = "http://schemas.openxmlformats.org/drawingml/2006/main"
NS_P = "http://schemas.openxmlformats.org/presentationml/2006/main"
NS_CP = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
NS_DC = "http://purl.org/dc/elements/1.1/"
NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS_PKG = "http://schemas.openxmlformats.org/package/2006/relationships"

XMLDECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'


# ----------------------------------------------------------------------
# Fixture builders

def _core_props(creator: str = "", last_mod: str = "") -> str:
    inner = ""
    if creator:
        inner += f"<dc:creator>{creator}</dc:creator>"
    if last_mod:
        inner += f"<cp:lastModifiedBy>{last_mod}</cp:lastModifiedBy>"
    return (f'{XMLDECL}<cp:coreProperties xmlns:cp="{NS_CP}" '
            f'xmlns:dc="{NS_DC}">{inner}</cp:coreProperties>')


def make_docx(path: Path, paragraphs, *, creator="", last_mod="",
              extra: dict[str, list[str]] | None = None) -> None:
    """Write a minimal .docx. ``extra`` maps aux part names (e.g.
    ``"word/comments.xml"``) to their paragraph text."""
    def body(paras):
        runs = "".join(
            f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paras
        )
        return f'{XMLDECL}<w:document xmlns:w="{NS_W}"><w:body>{runs}</w:body></w:document>'

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml", body(paragraphs))
        if creator or last_mod:
            z.writestr("docProps/core.xml", _core_props(creator, last_mod))
        for name, paras in (extra or {}).items():
            z.writestr(name, body(paras))


def make_xlsx(path: Path, sheets, *, creator="") -> None:
    """Write a minimal .xlsx. ``sheets`` is a list of (name, rows) where each
    row is a list of cells; a str cell -> shared string, an (\"inline\", s) cell
    -> inline string, an (\"num\", n) cell -> numeric."""
    shared: list[str] = []
    shared_index: dict[str, int] = {}

    def si(value: str) -> int:
        if value not in shared_index:
            shared_index[value] = len(shared)
            shared.append(value)
        return shared_index[value]

    # First pass to populate the shared-strings table.
    sheet_xml: list[str] = []
    for _name, rows in sheets:
        row_xml = []
        for r, row in enumerate(rows, 1):
            cells = []
            for cidx, cell in enumerate(row):
                col = chr(ord("A") + cidx)
                ref = f"{col}{r}"
                if isinstance(cell, tuple) and cell[0] == "inline":
                    cells.append(
                        f'<c r="{ref}" t="inlineStr"><is><t>{cell[1]}</t></is></c>')
                elif isinstance(cell, tuple) and cell[0] == "num":
                    cells.append(f'<c r="{ref}"><v>{cell[1]}</v></c>')
                else:
                    cells.append(f'<c r="{ref}" t="s"><v>{si(str(cell))}</v></c>')
            row_xml.append(f'<row r="{r}">{"".join(cells)}</row>')
        sheet_xml.append(
            f'{XMLDECL}<worksheet xmlns="{NS_S}"><sheetData>'
            f'{"".join(row_xml)}</sheetData></worksheet>')

    sst = (f'{XMLDECL}<sst xmlns="{NS_S}" count="{len(shared)}" '
           f'uniqueCount="{len(shared)}">'
           + "".join(f"<si><t>{s}</t></si>" for s in shared) + "</sst>")

    sheet_tags = "".join(
        f'<sheet name="{name}" sheetId="{i}" r:id="rId{i}"/>'
        for i, (name, _rows) in enumerate(sheets, 1))
    workbook = (f'{XMLDECL}<workbook xmlns="{NS_S}" xmlns:r="{NS_R}">'
                f'<sheets>{sheet_tags}</sheets></workbook>')
    rels = (f'{XMLDECL}<Relationships xmlns="{NS_PKG}">'
            + "".join(
                f'<Relationship Id="rId{i}" '
                f'Type="{NS_R}/worksheet" Target="worksheets/sheet{i}.xml"/>'
                for i in range(1, len(sheets) + 1))
            + "</Relationships>")

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", rels)
        z.writestr("xl/sharedStrings.xml", sst)
        for i, xml in enumerate(sheet_xml, 1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", xml)
        if creator:
            z.writestr("docProps/core.xml", _core_props(creator))


def make_pptx(path: Path, slides, notes=None, *, creator="") -> None:
    """Write a minimal .pptx. ``slides`` is a list of paragraph lists (one per
    slide); ``notes`` (optional) maps 1-based slide number -> paragraph list."""
    def para_body(paras, root_ns):
        runs = "".join(
            f"<a:p><a:r><a:t>{p}</a:t></a:r></a:p>" for p in paras)
        return (f'{XMLDECL}<p:{root_ns} xmlns:p="{NS_P}" xmlns:a="{NS_A}">'
                f'<p:cSld><p:spTree><p:sp><p:txBody>{runs}'
                f'</p:txBody></p:sp></p:spTree></p:cSld></p:{root_ns}>')

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for i, paras in enumerate(slides, 1):
            z.writestr(f"ppt/slides/slide{i}.xml", para_body(paras, "sld"))
        for num, paras in (notes or {}).items():
            z.writestr(f"ppt/notesSlides/notesSlide{num}.xml",
                       para_body(paras, "notes"))
        if creator:
            z.writestr("docProps/core.xml", _core_props(creator))


# A "scrub" closure exactly like the one the walker builds, over a fresh amap.
def _scrubber(amap: AliasMap):
    dets = build_active()

    def scrub(rel: str, text: str):
        new, reps = tokenize(text, dets, amap, frozenset(), file=rel)
        return new, len(reps)

    return scrub


def _process(path: Path, amap: AliasMap, *, out_path=None, write=False,
             limits: ExtractLimits | None = None):
    handler = get_handler(path.suffix)
    assert handler is not None and handler.name == "office"
    return handler.process(path, path.name, out_path, _scrubber(amap),
                           write=write, limits=limits or ExtractLimits())


# ----------------------------------------------------------------------
# docx

def test_docx_paragraphs_aliased(tmp_path: Path):
    doc = tmp_path / "report.docx"
    make_docx(doc, [
        "Contact alice@corp.com for access.",
        "Server sits at 10.0.0.9 on the LAN.",
        "",  # empty paragraph preserved as a blank line
    ])
    amap = AliasMap()
    out = _process(doc, amap, out_path=tmp_path / "out" / "report.docx", write=True)

    assert out.kind == "derivative"
    assert out.out_rel == "report.docx.txt"
    deriv = tmp_path / "out" / "report.docx.txt"
    body = deriv.read_text()
    # Raw PII gone, aliases present.
    assert "alice@corp.com" not in body and "10.0.0.9" not in body
    assert "<EMAIL_1>" in body and "<IP_1>" in body
    assert out.replacements >= 2
    # Structure: still one line per paragraph.
    assert len(body.splitlines()) == 3


def test_docx_runs_split_email_reassembled(tmp_path: Path):
    # Word fragments a typed value across several <w:t> runs; the handler must
    # rejoin runs within a paragraph so the whole email is one span.
    doc = tmp_path / "frag.docx"
    body = (f'{XMLDECL}<w:document xmlns:w="{NS_W}"><w:body><w:p>'
            '<w:r><w:t>mail bo</w:t></w:r>'
            '<w:r><w:t>b@corp.</w:t></w:r>'
            '<w:r><w:t>com now</w:t></w:r>'
            '</w:p></w:body></w:document>')
    with zipfile.ZipFile(doc, "w") as z:
        z.writestr("word/document.xml", body)
    amap = AliasMap()
    out = _process(doc, amap)
    # The reassembled email got aliased (would be missed if runs weren't joined).
    assert out.replacements == 1
    assert any(m["category"] == "email" for m in amap.decode_table().values())


def test_docx_headers_footnotes_comments_scanned(tmp_path: Path):
    doc = tmp_path / "aux.docx"
    make_docx(doc, ["body has no pii"], extra={
        "word/header1.xml": ["header email head@corp.com"],
        "word/footnotes.xml": ["footnote ip 172.16.5.4"],
        "word/comments.xml": ["comment from carol@corp.com"],
    })
    amap = AliasMap()
    out = _process(doc, amap)
    cats = {m["category"] for m in amap.decode_table().values()}
    assert {"email", "ipv4"} <= cats
    assert out.replacements >= 3


def test_docx_core_props_author_emitted_and_scanned(tmp_path: Path):
    doc = tmp_path / "meta.docx"
    make_docx(doc, ["nothing here"],
              creator="dave@corp.com", last_mod="erin@corp.com")
    amap = AliasMap()
    out = _process(doc, amap, out_path=tmp_path / "meta.docx", write=True)
    body = (tmp_path / "meta.docx.txt").read_text()
    # author lines present, raw emails scrubbed out of them
    assert "# author:" in body
    assert "dave@corp.com" not in body and "erin@corp.com" not in body
    assert out.replacements >= 2


# ----------------------------------------------------------------------
# xlsx

def test_xlsx_shared_inline_and_numeric_cells(tmp_path: Path):
    book = tmp_path / "book.xlsx"
    make_xlsx(book, [
        ("People", [
            ["name", "email", "host", "count"],
            ["Alice", "alice@corp.com", ("inline", "srv1.corp.com"), ("num", 42)],
            ["Bob", "bob@corp.com", ("inline", "10.0.0.5"), ("num", 7)],
        ]),
    ])
    amap = AliasMap()
    out = _process(book, amap, out_path=tmp_path / "book.xlsx", write=True)

    assert out.out_rel == "book.xlsx.csv"
    body = (tmp_path / "book.xlsx.csv").read_text()
    # Sheet section header + one CSV line per row.
    assert "# sheet: People" in body
    assert "alice@corp.com" not in body and "bob@corp.com" not in body
    assert "srv1.corp.com" not in body and "10.0.0.5" not in body
    # numeric cells survive verbatim
    assert "42" in body and "7" in body
    cats = {m["category"] for m in amap.decode_table().values()}
    assert {"email", "fqdn", "ipv4"} <= cats


def test_xlsx_multiple_sheets_named_from_workbook(tmp_path: Path):
    book = tmp_path / "multi.xlsx"
    make_xlsx(book, [
        ("Employees", [["frank@corp.com"]]),
        ("Servers", [["10.1.1.1"]]),
    ])
    amap = AliasMap()
    _process(book, amap, out_path=tmp_path / "multi.xlsx", write=True)
    body = (tmp_path / "multi.xlsx.csv").read_text()
    assert "# sheet: Employees" in body and "# sheet: Servers" in body
    # Employees section precedes Servers (workbook order preserved).
    assert body.index("# sheet: Employees") < body.index("# sheet: Servers")


def test_xlsx_csv_quotes_values_with_commas(tmp_path: Path):
    book = tmp_path / "comma.xlsx"
    make_xlsx(book, [("S", [["a, b", "plain"]])])
    amap = AliasMap()
    _process(book, amap, out_path=tmp_path / "comma.xlsx", write=True)
    body = (tmp_path / "comma.xlsx.csv").read_text()
    # comma-containing cell is CSV-quoted so columns stay parseable
    assert '"a, b",plain' in body


# ----------------------------------------------------------------------
# pptx

def test_pptx_slides_and_notes(tmp_path: Path):
    deck = tmp_path / "deck.pptx"
    make_pptx(
        deck,
        slides=[
            ["Title", "reach greg@corp.com"],
            ["Second slide, host www.corp.com"],
        ],
        notes={1: ["speaker note ip 192.168.1.50"]},
    )
    amap = AliasMap()
    out = _process(deck, amap, out_path=tmp_path / "deck.pptx", write=True)

    assert out.out_rel == "deck.pptx.txt"
    body = (tmp_path / "deck.pptx.txt").read_text()
    assert "# slide 1" in body and "# slide 2" in body
    assert "# slide 1 notes" in body
    assert "greg@corp.com" not in body and "www.corp.com" not in body
    assert "192.168.1.50" not in body
    cats = {m["category"] for m in amap.decode_table().values()}
    assert {"email", "fqdn", "ipv4"} <= cats


def test_pptx_slide_order_numeric_not_lexical(tmp_path: Path):
    deck = tmp_path / "order.pptx"
    # slide10 must come after slide2 (numeric), not before (lexical).
    make_pptx(deck, slides=[[f"slide-{i}-marker"] for i in range(1, 11)])
    amap = AliasMap()
    out = _process(deck, amap, out_path=tmp_path / "order.pptx", write=True)
    body = (tmp_path / "order.pptx.txt").read_text()
    assert body.index("# slide 2") < body.index("# slide 10")


# ----------------------------------------------------------------------
# Failure / fail-open paths

def test_garbage_container_raises_extracterror(tmp_path: Path):
    bad = tmp_path / "bad.docx"
    bad.write_bytes(b"this is not a zip at all")
    amap = AliasMap()
    with pytest.raises(ExtractError):
        _process(bad, amap)


def test_ole_encrypted_container_raises_extracterror(tmp_path: Path):
    # Encrypted OOXML files are OLE/CFBF compound files (magic D0CF11E0...),
    # which zipfile rejects -> ExtractError -> walker copies+flags.
    enc = tmp_path / "locked.xlsx"
    enc.write_bytes(bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 512)
    amap = AliasMap()
    with pytest.raises(ExtractError):
        _process(enc, amap)


def test_malformed_primary_xml_raises_and_leaves_no_partial(tmp_path: Path):
    doc = tmp_path / "torn.docx"
    with zipfile.ZipFile(doc, "w") as z:
        z.writestr("word/document.xml", "<w:document><w:body><w:p>UNCLOSED")
    amap = AliasMap()
    out_path = tmp_path / "out" / "torn.docx"
    with pytest.raises(ExtractError):
        _process(doc, amap, out_path=out_path, write=True)
    # fail-open: no half-written derivative left behind
    assert not (tmp_path / "out" / "torn.docx.txt").exists()


def test_docx_missing_primary_part_raises(tmp_path: Path):
    # a valid zip that is not actually a docx (no word/document.xml)
    notdoc = tmp_path / "empty.docx"
    with zipfile.ZipFile(notdoc, "w") as z:
        z.writestr("random.txt", "hello")
    amap = AliasMap()
    with pytest.raises(ExtractError):
        _process(notdoc, amap)


def test_max_out_bytes_guard_trips(tmp_path: Path):
    doc = tmp_path / "big.docx"
    make_docx(doc, [f"line {i} padding padding padding" for i in range(2000)])
    amap = AliasMap()
    out_path = tmp_path / "out" / "big.docx"
    with pytest.raises(ExtractError):
        _process(doc, amap, out_path=out_path, write=True,
                 limits=ExtractLimits(max_out_bytes=1024))
    assert not (tmp_path / "out" / "big.docx.txt").exists()


# ----------------------------------------------------------------------
# scan (write=False) and reverse round-trip

def test_scan_runs_extraction_without_writing(tmp_path: Path):
    doc = tmp_path / "scan.docx"
    make_docx(doc, ["email helen@corp.com ip 10.2.2.2"])
    amap = AliasMap()
    out = _process(doc, amap, out_path=None, write=False)
    assert out.replacements >= 2
    # nothing written next to the source
    assert list(tmp_path.iterdir()) == [doc]
    # aliases still populated so the report reflects a strip
    assert any(m["category"] == "email" for m in amap.decode_table().values())


def test_derivative_reverses_to_originals(tmp_path: Path):
    doc = tmp_path / "rev.docx"
    make_docx(doc, ["ivan@corp.com from 10.9.9.9"])
    amap = AliasMap()
    _process(doc, amap, out_path=tmp_path / "rev.docx", write=True)
    body = (tmp_path / "rev.docx.txt").read_text()
    restored = reverse_text(body, amap.reverse_pairs())
    assert "ivan@corp.com" in restored and "10.9.9.9" in restored


# ----------------------------------------------------------------------
# Walker integration: strip a tree containing office docs.

def test_walker_extracts_office_and_drops_original(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    make_docx(src / "d.docx", ["email jack@corp.com"])
    make_xlsx(src / "b.xlsx", [("S", [["10.4.4.4", "kate@corp.com"]])])
    make_pptx(src / "p.pptx", slides=[["ip 10.5.5.5"]])
    (src / "note.txt").write_text("plain log 10.4.4.4\n")

    amap = AliasMap()
    stats = process_tree(src, dst, build_active(), amap, max_bytes=10**9,
                         write=True, exclude_dirs=set())

    assert stats.files_extracted == 3
    # derivatives written, originals NOT copied into DST
    assert (dst / "d.docx.txt").exists() and not (dst / "d.docx").exists()
    assert (dst / "b.xlsx.csv").exists() and not (dst / "b.xlsx").exists()
    assert (dst / "p.pptx.txt").exists() and not (dst / "p.pptx").exists()
    # no raw PII anywhere in the DST tree
    for f in dst.rglob("*"):
        if f.is_file():
            blob = f.read_text()
            for raw in ("jack@corp.com", "kate@corp.com", "10.4.4.4",
                        "10.5.5.5"):
                assert raw not in blob, (f.name, raw)
    # cross-source aliasing: the IP shared by the xlsx and the plain log is one
    # alias (shared amap over the whole run).
    ip_aliases = [a for a, m in amap.decode_table().items()
                  if m["category"] == "ipv4" and m["original"] == "10.4.4.4"]
    assert len(ip_aliases) == 1


def test_walker_bad_office_falls_back_to_copy_flag(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    (src / "broken.docx").write_bytes(b"not a zip")
    stats = process_tree(src, dst, build_active(), AliasMap(), max_bytes=10**9,
                         write=True, exclude_dirs=set())
    assert stats.files_extracted == 0 and stats.files_copied == 1
    # original copied through unchanged + flagged
    assert (dst / "broken.docx").read_bytes() == b"not a zip"
    warn = next(w for w in stats.warnings if "broken.docx" in w)
    assert "may contain PII" in warn and "extraction skipped" in warn
