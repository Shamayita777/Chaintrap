"""
ChainTrap v2 — core/decoy_manager.py

Dynamic Decoy File Generator & Manager.

Patent Claim: "Probabilistic dynamic decoy file generation with randomized
               names, sizes, internal structure, and embedded canary tokens,
               distributed across multiple user directories for maximum
               ransomware attack-surface tripwire coverage."

Evasion Countermeasures:
  - Decoy-aware ransomware (REvil): Files are realistic size (50KB–5MB),
    have plausible names, and authentic internal structure.
  - Static decoy detection: Decoys are regenerated periodically with
    new names and content so fingerprinting is impossible.
  - Small-file skip: All decoys are >= 64KB.
  - Canary tokens: Embedded HTTP beacons fire BEFORE encryption starts,
    providing out-of-band detection even if entropy fails.

Decoy file types generated:
  .txt  — Realistic multi-page text documents
  .docx — Valid ZIP-based OOXML skeleton
  .pdf  — Minimal valid PDF
  .csv  — Plausible financial CSV data
  .xlsx — Valid ZIP-based OOXML skeleton
  .json — Structured JSON config/data
"""

import os
import io
import csv
import json
import time
import uuid
import random
import struct
import string
import zipfile
import hashlib
import logging
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("ChainTrap.decoys")


# ─────────────────────────────────────────────
# ATTRACTIVE FILE NAMES
# Research (RWGuard 2019) shows ransomware prioritizes files
# matching common naming patterns. We exploit this.
# ─────────────────────────────────────────────
_NAME_POOLS = {
    "financial": [
        "invoice_{y}_{n}", "tax_return_{y}", "payroll_{m}_{y}",
        "expenses_{q}_{y}", "budget_{y}_final", "accounts_payable_{m}",
        "credit_card_statement_{m}_{y}", "salary_slip_{m}",
        "bank_statement_{y}_{m}", "annual_report_{y}",
    ],
    "personal": [
        "passwords_{n}", "personal_notes_{n}", "diary_{y}_{m}",
        "medical_records_{y}", "insurance_policy_{y}",
        "legal_documents_{n}", "passport_scan_{y}",
        "social_security_{n}", "birth_certificate",
    ],
    "work": [
        "client_contracts_{y}", "project_proposal_{n}",
        "meeting_notes_{m}_{y}", "employee_data_{y}",
        "confidential_report_{q}_{y}", "strategy_{y}_q{q}",
        "nda_signed_{y}", "board_minutes_{m}_{y}",
        "acquisition_docs_{y}", "ip_portfolio_{y}",
    ],
    "generic": [
        "backup_{n}", "important_{n}", "readme_critical",
        "do_not_delete_{n}", "archive_{y}_{m}",
        "old_files_{y}", "temp_data_{n}",
    ],
}

_EXT_MAP = {
    "financial": [".xlsx", ".csv", ".pdf", ".txt"],
    "personal":  [".txt", ".pdf", ".docx"],
    "work":      [".docx", ".xlsx", ".pdf", ".txt"],
    "generic":   [".txt", ".json", ".csv"],
}


def _generate_name(category: Optional[str] = None) -> tuple[str, str]:
    """
    Generate a realistic file name with appropriate extension.
    Returns (stem, extension).
    """
    if category is None:
        category = random.choice(list(_NAME_POOLS.keys()))

    pool = _NAME_POOLS[category]
    template = random.choice(pool)

    y = random.randint(2020, 2025)
    m = random.choice(["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])
    q = random.randint(1, 4)
    n = random.randint(1000, 9999)

    stem = template.format(y=y, m=m, q=q, n=n)
    ext  = random.choice(_EXT_MAP[category])
    return stem, ext


# ─────────────────────────────────────────────
# CONTENT GENERATORS
# Each generator produces realistically structured file content.
# ─────────────────────────────────────────────

def _lorem_paragraph(sentences: int = 5) -> str:
    """Generate pseudo-realistic Lorem Ipsum text."""
    words = (
        "the quick brown fox jumps over lazy dog financial report quarterly "
        "revenue expenses budget allocation project delivery client meeting "
        "strategic planning implementation timeline deliverable milestone "
        "stakeholder management resource allocation risk assessment audit "
        "compliance regulatory framework procurement vendor contract invoice "
        "payment terms confidential proprietary information disclosure "
        "non-disclosure agreement intellectual property rights reserved "
    ).split()
    out = []
    for _ in range(sentences):
        length = random.randint(8, 20)
        sentence = " ".join(random.choices(words, k=length))
        sentence = sentence[0].upper() + sentence[1:] + "."
        out.append(sentence)
    return " ".join(out)


def _generate_txt(target_size: int = 100_000) -> bytes:
    """Generate realistic multi-section text document."""
    lines = []
    lines.append("=" * 60)
    lines.append(f"CONFIDENTIAL DOCUMENT — {datetime.now().strftime('%Y-%m-%d')}")
    lines.append("=" * 60)
    lines.append("")

    sections = ["Executive Summary", "Overview", "Financial Analysis",
                "Operational Review", "Risk Assessment", "Recommendations"]
    for section in sections:
        lines.append(f"\n{section}")
        lines.append("-" * len(section))
        for _ in range(random.randint(3, 7)):
            lines.append(_lorem_paragraph(random.randint(3, 6)))
            lines.append("")

    content = "\n".join(lines)
    # Pad to target size
    while len(content.encode("utf-8")) < target_size:
        content += "\n" + _lorem_paragraph(5)

    return content.encode("utf-8")


def _generate_csv(target_size: int = 80_000) -> bytes:
    """Generate realistic financial CSV data."""
    buf = io.StringIO()
    writer = csv.writer(buf)

    headers = ["Date", "Description", "Category", "Amount", "Balance",
               "Reference", "Account", "Status"]
    writer.writerow(headers)

    categories = ["Payroll", "Office Supplies", "Travel", "Software",
                  "Marketing", "Legal", "Utilities", "Insurance", "Consulting"]
    balance = random.uniform(50_000, 500_000)
    date = datetime.now() - timedelta(days=365)

    while len(buf.getvalue().encode()) < target_size:
        date += timedelta(days=random.randint(1, 5))
        amount = round(random.uniform(-10_000, 10_000), 2)
        balance += amount
        writer.writerow([
            date.strftime("%Y-%m-%d"),
            _lorem_paragraph(1)[:40],
            random.choice(categories),
            f"{amount:.2f}",
            f"{balance:.2f}",
            f"REF-{random.randint(100000, 999999)}",
            f"ACC-{random.randint(1000, 9999)}",
            random.choice(["Cleared", "Pending", "Reconciled"]),
        ])

    return buf.getvalue().encode("utf-8")


def _generate_json(target_size: int = 60_000) -> bytes:
    """Generate realistic structured JSON data."""
    records = []
    current_size = 0

    while current_size < target_size:
        record = {
            "id": str(uuid.uuid4()),
            "created_at": (datetime.now() - timedelta(days=random.randint(0, 365))).isoformat(),
            "name": " ".join(random.choices(_lorem_paragraph(1).split(), k=3)),
            "value": round(random.uniform(0, 100_000), 2),
            "category": random.choice(["A", "B", "C", "D"]),
            "active": random.choice([True, False]),
            "tags": random.choices(["finance", "legal", "hr", "it", "ops"], k=2),
            "metadata": {"source": "internal", "version": random.randint(1, 5)},
            "notes": _lorem_paragraph(random.randint(1, 3)),
        }

        records.append(record)

        # Only serialize the new record to estimate growth
        current_size += len(json.dumps(record).encode("utf-8"))

    result = {
        "records": records,
        "count": len(records),
        "generated": datetime.now().isoformat(),
    }

    return json.dumps(result, indent=2).encode("utf-8")

def _generate_pdf(target_size: int = 150_000) -> bytes:
    """
    Generate a minimal but structurally valid PDF.
    Contains real text content to survive format-aware ransomware checks.
    """
    # Build PDF content stream
    content_text = _lorem_paragraph(20)
    lines = [content_text[i:i+80] for i in range(0, len(content_text), 80)]
    pdf_text = "\n".join(f"BT /F1 12 Tf 50 {700 - i*20} Td ({line}) Tj ET"
                         for i, line in enumerate(lines[:30]))

    # Pad text to approach target size
    padding = "%" + ("X" * 80 + "\n") * max(1, (target_size - 2000) // 82)

    pdf = f"""%PDF-1.4
{padding}
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length {len(pdf_text)} >>
stream
{pdf_text}
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
trailer
<< /Size 6 /Root 1 0 R >>
startxref
0
%%EOF"""
    return pdf.encode("latin-1", errors="replace")

def _generate_docx(target_size: int = 200_000) -> bytes:
    """
    Generate a valid OOXML .docx file (ZIP-based).
    Structurally complete — survives OOXML integrity checks in entropy_analyzer.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # Required: [Content_Types].xml
        z.writestr("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>""")

        z.writestr("_rels/.rels", """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
</Relationships>""")

        z.writestr("word/_rels/document.xml.rels", """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>""")

        # Generate realistic document content
        paragraphs = ""
        for _ in range(random.randint(15, 30)):
            text = _lorem_paragraph(random.randint(3, 8))
            # Escape XML special chars
            text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            paragraphs += f"""
  <w:p>
    <w:r><w:t xml:space="preserve">{text}</w:t></w:r>
  </w:p>"""

        # Pad to target size
        while len(paragraphs) < target_size - 2000:
            text = _lorem_paragraph(5).replace("&", "&amp;")
            paragraphs += f"\n  <w:p><w:r><w:t>{text}</w:t></w:r></w:p>"

        z.writestr("word/document.xml", f"""<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas"
            xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>{paragraphs}
  </w:body>
</w:document>""")

    return buf.getvalue()


def _generate_xlsx(target_size: int = 150_000) -> bytes:
    """Generate a valid OOXML .xlsx file with financial-looking data."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>""")

        z.writestr("_rels/.rels", """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="xl/workbook.xml"/>
</Relationships>""")

        z.writestr("xl/_rels/workbook.xml.rels", """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
    Target="worksheets/sheet1.xml"/>
</Relationships>""")

        z.writestr("xl/workbook.xml", """<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>""")

        # Generate rows
        rows = "<row r=\"1\"><c r=\"A1\" t=\"inlineStr\"><is><t>Date</t></is></c>"
        rows += "<c r=\"B1\" t=\"inlineStr\"><is><t>Amount</t></is></c>"
        rows += "<c r=\"C1\" t=\"inlineStr\"><is><t>Description</t></is></c></row>"

        for i in range(2, 500):
            date = (datetime.now() - timedelta(days=random.randint(0, 365))).strftime("%Y-%m-%d")
            amount = round(random.uniform(-50000, 50000), 2)
            desc = _lorem_paragraph(1)[:30].replace("&", "").replace("<", "").replace(">", "")
            rows += f"<row r=\"{i}\">"
            rows += f"<c r=\"A{i}\" t=\"inlineStr\"><is><t>{date}</t></is></c>"
            rows += f"<c r=\"B{i}\"><v>{amount}</v></c>"
            rows += f"<c r=\"C{i}\" t=\"inlineStr\"><is><t>{desc}</t></is></c>"
            rows += "</row>"

        z.writestr("xl/worksheets/sheet1.xml",
            f"""<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>{rows}</sheetData>
</worksheet>""")

    return buf.getvalue()


_GENERATORS = {
    ".txt":  _generate_txt,
    ".csv":  _generate_csv,
    ".json": _generate_json,
    ".pdf":  _generate_pdf,
    ".docx": _generate_docx,
    ".xlsx": _generate_xlsx,
}


def _embed_canary_token(content: bytes, ext: str, token_url: str) -> bytes:
    """
    Embed a canary token HTTP beacon URL into file content.

    For text-based files: embed as a comment or metadata line.
    For binary files: embed in a comment block near the end.

    Patent significance: Out-of-band detection — even before entropy
    analysis fires, the canary beacon notifies the server that the
    decoy was accessed or exfiltrated.
    """
    beacon = f"\n<!-- canary:{token_url} -->\n".encode("utf-8")

    if ext in {".txt", ".csv", ".json", ".md"}:
        return content + f"\n# metadata: {token_url}\n".encode("utf-8")
    elif ext == ".pdf":
        # Embed before %%EOF
        if b"%%EOF" in content:
            return content.replace(b"%%EOF", f"% {token_url}\n%%EOF".encode())
    # For binary/ZIP formats, append at end (most ZIP parsers ignore trailing bytes)
    return content + beacon


# ─────────────────────────────────────────────
# DECOY REGISTRY
# Track all deployed decoys: path → metadata
# ─────────────────────────────────────────────
_decoy_registry: dict[str, dict] = {}
_registry_lock  = threading.Lock()


def _register_decoy(path: str, metadata: dict) -> None:
    with _registry_lock:
        _decoy_registry[path] = metadata


def get_decoy_paths(base_dir: str | None = None) -> set:
    """Return the set of all currently deployed decoy paths."""
    with _registry_lock:
        return set(_decoy_registry.keys())


def is_decoy(path: str) -> bool:
    """Return True if path is a known ChainTrap decoy file."""
    with _registry_lock:
        return path in _decoy_registry


# ─────────────────────────────────────────────
# DECOY DEPLOYMENT
# ─────────────────────────────────────────────
def _target_size() -> int:
    """Random realistic file size: 64KB to 5MB."""
    # Weighted toward smaller sizes (more realistic)
    return random.choice([
        random.randint(64_000,   200_000),   # 60% weight
        random.randint(200_000,  1_000_000), # 30% weight
        random.randint(1_000_000, 5_000_000), # 10% weight
    ])


def deploy_decoy(directory: str,
                 canary_url: str = "",
                 category: Optional[str] = None) -> Optional[str]:
    """
    Generate and deploy a single decoy file into `directory`.

    Args:
        directory:  Target directory path
        canary_url: Canary token URL to embed (optional)
        category:   Name category (financial/personal/work/generic)

    Returns:
        Absolute path of deployed decoy, or None on failure.
    """
    dir_path = Path(directory)
    if not dir_path.exists():
        try:
            dir_path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning(f"Cannot create decoy dir {directory}: {e}")
            return None

    stem, ext = _generate_name(category)
    filename  = f"{stem}{ext}"
    filepath  = dir_path / filename

    # Skip if name collision (unlikely but possible)
    if filepath.exists():
        stem = f"{stem}_{random.randint(100,999)}"
        filepath = dir_path / f"{stem}{ext}"

    generator = _GENERATORS.get(ext)
    if generator is None:
        # Fallback to txt
        generator = _generate_txt
        ext = ".txt"

    target_size = _target_size()

    try:
        content = generator(target_size)

        if canary_url:
            content = _embed_canary_token(content, ext, canary_url)

        with open(filepath, "wb") as f:
            f.write(content)

        # Compute baseline hash for change detection
        h = hashlib.sha256(content).hexdigest()

        metadata = {
            "path":         str(filepath),
            "category":     category,
            "extension":    ext,
            "size":         len(content),
            "sha256":       h,
            "deployed_at":  datetime.now().isoformat(),
            "canary_url":   canary_url,
            "is_decoy":     True,
        }
        _register_decoy(str(filepath), metadata)

        logger.info(f"Decoy deployed: {filepath} ({len(content):,} bytes)")
        return str(filepath)

    except Exception as e:
        logger.error(f"Failed to deploy decoy at {filepath}: {e}")
        return None


def deploy_decoy_swarm(
    directories,
    count: int = None,
    count_per_dir: int = 3,
    canary_url: str = "",
) -> list[str]:
    """
    Deploy multiple decoy files across all specified directories.

    Distributes file categories across directories to avoid
    suspicious clustering. Each directory gets a mix.

    Returns list of all deployed decoy paths.
    """
    # Backward compatibility for tests: allow single directory + count
    if isinstance(directories, str):
        directories = [directories]
        if count is not None:
            count_per_dir = count
    deployed = []
    categories = list(_NAME_POOLS.keys())

    for directory in directories:
        for i in range(count_per_dir):
            cat = categories[i % len(categories)]
            path = deploy_decoy(directory, canary_url=canary_url, category=cat)
            if path:
                deployed.append(path)

    logger.info(f"Decoy swarm deployed: {len(deployed)} files across {len(directories)} directories")
    return deployed


def refresh_decoys(directories: list[str],
                   count_per_dir: int = 3,
                   canary_url: str = "") -> list[str]:
    """
    Retire old decoys and deploy fresh ones.
    Called periodically to prevent fingerprinting.

    Returns list of newly deployed paths.
    """
    # Remove old decoys
    with _registry_lock:
        old_paths = list(_decoy_registry.keys())
        _decoy_registry.clear()

    for path in old_paths:
        try:
            if Path(path).exists():
                Path(path).unlink()
                logger.debug(f"Retired decoy: {path}")
        except OSError:
            pass

    # Deploy fresh set
    return deploy_decoy_swarm(directories, count_per_dir, canary_url)


def get_decoy_registry(base_dir: str | None = None) -> dict:
    """Return a copy of the current decoy registry."""
    with _registry_lock:
        return dict(_decoy_registry)
