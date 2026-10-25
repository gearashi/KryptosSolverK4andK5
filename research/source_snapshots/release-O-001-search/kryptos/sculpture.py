"""Verified inscription text coordinates and explicitly hypothetical fixed routes.

Rows and columns are transcription ordinals, not measured physical positions.
No origin search, cyclic offset, null insertion, or geometry fitting is done.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import html
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LAYOUT = ROOT / "research/sculpture_layout.json"
PACKAGED_LAYOUT_SHA256 = "7b62e96a89677b09d1655b609389d534e5583d45dec3ab3625a3e2cc893193b3"
TRANSFORMS = ("identity", "rotate90", "rotate180", "rotate270", "reflect_columns",
              "reflect_rows", "transpose", "antitranspose")
SCANS = ("row-major", "row-serpentine")


@dataclass(frozen=True)
class Cell:
    panel: str
    row: int
    column: int
    symbol: str
    stream_index: int | None = None
    section: str | None = None
    section_index: int | None = None

    def to_dict(self):
        return asdict(self)


def load_layout(path=DEFAULT_LAYOUT, *, verify_sources=True):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    return _validate_layout(value, verify_sources=verify_sources)


def load_packaged_layout(path=DEFAULT_LAYOUT):
    """Verify the pinned normalized dataset without redistributing source pages.

    This is an explicit package-integrity mode. It does not re-read primary
    sources; use load_layout's unchanged strict default for that separate audit.
    """
    raw = Path(path).read_bytes()
    actual = sha256(raw).hexdigest()
    if actual != PACKAGED_LAYOUT_SHA256:
        raise ValueError("Packaged sculpture dataset differs from its pinned SHA256")
    value = _validate_layout(json.loads(raw.decode("utf-8")), verify_sources=False)
    value["verification"] = {"mode": "pinned-normalized-dataset", "dataset_sha256": actual,
                             "structure_and_section_hashes_verified": True,
                             "primary_source_snapshots_reverified": False,
                             "source_audit": "Explicit load_layout() requires retained primary-source snapshots."}
    return value


def _validate_layout(value, *, verify_sources):
    if value.get("schema") != "kryptos.sculpture-text-layout.v1":
        raise ValueError("Unsupported sculpture layout schema")
    for name in ("cipher", "tableau"):
        panel = value["panels"][name]
        rows = panel["rows"]
        if (len(rows) != 28 or any(not isinstance(r, str) or not r or len(r) > 33
                                   or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ? " for ch in r) for r in rows)
                or panel["row_lengths"] != list(map(len, rows))
                or panel["row_count"] != 28 or panel["maximum_ordinal_width"] != max(map(len, rows))):
            raise ValueError("Invalid transcription rows or dimensions")
    stream = "".join(ch for r in value["panels"]["cipher"]["rows"] for ch in r if ch.isalpha())
    start = 0
    for name, length in (("K1", 63), ("K2", 369), ("K3", 336), ("K4", 97)):
        section = value["sections"][name]
        if (section["letter_span_zero_based_half_open"] != [start, start + length]
                or section["letters"] != length
                or sha256(stream[start:start + length].encode("ascii")).hexdigest() != section["ciphertext_sha256"]):
            raise ValueError("Invalid section span or digest")
        start += length
    if len(stream) != start:
        raise ValueError("Unassigned or missing inscription letters")
    if verify_sources:
        for source in value["sources"]:
            path = (ROOT / source["path"]).resolve()
            if not path.is_relative_to(ROOT) or sha256(path.read_bytes()).hexdigest() != source["sha256"]:
                raise ValueError("Source snapshot missing, outside workspace, or changed")
        source = ROOT / value["sources"][0]["path"]
        blocks = re.findall(r"<pre><font[^>]*>(.*?)</font></pre>", source.read_text(encoding="utf-8"), re.S)
        if len(blocks) != 4:
            raise ValueError("Expected the source's four transcription blocks")
        rows = [html.unescape(block).replace("\xa0", " ").strip("\r\n").splitlines() for block in blocks]
        if (value["panels"]["cipher"]["rows"] != rows[0] + rows[2]
                or value["panels"]["tableau"]["rows"] != rows[1] + rows[3]):
            raise ValueError("Dataset disagrees with retained primary transcription")
    return value


def cells(panel="cipher", layout=None):
    layout = load_packaged_layout() if layout is None else layout
    if panel not in ("cipher", "tableau"):
        raise ValueError("panel must be cipher or tableau")
    result, stream_index = [], 0
    for row, text in enumerate(layout["panels"][panel]["rows"]):
        for column, symbol in enumerate(text):
            index, section, section_index = None, None, None
            if panel == "cipher" and symbol.isalpha():
                index = stream_index
                stream_index += 1
                for name, record in layout["sections"].items():
                    start, stop = record["letter_span_zero_based_half_open"]
                    if start <= index < stop:
                        section, section_index = name, index - start
                        break
            result.append(Cell(panel, row, column, symbol, index, section, section_index))
    return tuple(result)


def section_cells(section, layout=None):
    if section not in ("K1", "K2", "K3", "K4", "ALL"):
        raise ValueError("section must be K1, K2, K3, K4, or ALL")
    return tuple(cell for cell in cells("cipher", layout)
                 if cell.stream_index is not None and (section == "ALL" or cell.section == section))


def section_text(section, layout=None):
    return "".join(cell.symbol for cell in section_cells(section, layout))


def transform_coordinate(row, column, height, width, transform):
    if (any(type(n) is not int for n in (row, column, height, width))
            or not 1 <= height <= 4096 or not 1 <= width <= 4096
            or not 0 <= row < height or not 0 <= column < width or transform not in TRANSFORMS):
        raise ValueError("A valid integer coordinate, bounded rectangle and fixed transform are required")
    return {
        "identity": (row, column), "rotate90": (column, height - 1 - row),
        "rotate180": (height - 1 - row, width - 1 - column),
        "rotate270": (width - 1 - column, row), "reflect_columns": (row, width - 1 - column),
        "reflect_rows": (height - 1 - row, column), "transpose": (column, row),
        "antitranspose": (width - 1 - column, height - 1 - row),
    }[transform]


def transformed_shape(height, width, transform):
    transform_coordinate(0, 0, height, width, transform)
    return (width, height) if transform in ("rotate90", "rotate270", "transpose", "antitranspose") else (height, width)


def route_mapping(section, transform="identity", scan="row-major", layout=None):
    layout = load_packaged_layout() if layout is None else layout
    if scan not in SCANS:
        raise ValueError("scan must be row-major or row-serpentine")
    panel = layout["panels"]["cipher"]
    height, width = panel["row_count"], panel["maximum_ordinal_width"]
    source = section_cells(section, layout)
    mapped = [transform_coordinate(c.row, c.column, height, width, transform) for c in source]
    def key(index):
        row, col = mapped[index]
        return row, -col if scan == "row-serpentine" and row % 2 else col
    gather = tuple(sorted(range(len(source)), key=key))
    return {"section": section, "transform": transform, "scan": scan,
            "coordinate_basis": "whole cipher transcription rectangle; holes skipped; absolute row parity",
            "transformed_shape": list(transformed_shape(height, width, transform)),
            "permutation": list(gather),
            "mapping": [{"output_index": j, "input_index": i,
                         "source_row": source[i].row, "source_column": source[i].column,
                         "transformed_row": mapped[i][0], "transformed_column": mapped[i][1]}
                        for j, i in enumerate(gather)]}


def fixed_routes(section="K4", layout=None):
    layout = load_packaged_layout() if layout is None else layout
    grouped = {}
    for transform in TRANSFORMS:
        for scan in SCANS:
            record = route_mapping(section, transform, scan, layout)
            permutation = tuple(record["permutation"])
            alias = {"transform": transform, "scan": scan}
            if permutation in grouped:
                grouped[permutation]["aliases"].append(alias)
            else:
                grouped[permutation] = {**record, "aliases": [alias]}
    return tuple(grouped.values())


def fixed_overlay(section="K4", transform="identity", layout=None):
    """Top-left ordinal registration only; unmatched positions remain explicit."""
    layout = load_packaged_layout() if layout is None else layout
    panel = layout["panels"]["cipher"]
    lookup = {(c.row, c.column): c for c in cells("tableau", layout)}
    mapping = []
    for index, cell in enumerate(section_cells(section, layout)):
        row, column = transform_coordinate(cell.row, cell.column, panel["row_count"],
                                           panel["maximum_ordinal_width"], transform)
        target = lookup.get((row, column))
        mapping.append({"input_index": index, "source_row": cell.row, "source_column": cell.column,
                        "cipher_symbol": cell.symbol, "tableau_row": row, "tableau_column": column,
                        "tableau_symbol": target.symbol if target else None,
                        "occupied_tableau_letter": bool(target and target.symbol.isalpha())})
    return {"section": section, "transform": transform,
            "assumption": "Top-left registration of transcribed ordinal coordinates; no measured physical alignment",
            "mapping": mapping, "matched_letters": sum(row["occupied_tableau_letter"] for row in mapping),
            "missing_or_blank": [row["input_index"] for row in mapping if not row["occupied_tableau_letter"]]}


def apply_gather(text, permutation, *, inverse=False):
    if (not isinstance(text, str) or not isinstance(permutation, (list, tuple))
            or len(permutation) != len(text) or any(type(i) is not int for i in permutation)
            or sorted(permutation) != list(range(len(text)))):
        raise ValueError("permutation must be a full gather bijection")
    if not inverse:
        return "".join(text[i] for i in permutation)
    result = [""] * len(text)
    for j, i in enumerate(permutation):
        result[i] = text[j]
    return "".join(result)
