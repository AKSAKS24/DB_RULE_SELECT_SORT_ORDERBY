from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import re

app = FastAPI(
    title="ABAP Scanner - ORDER BY / SORT Rule (system MSG exact)",
    version="1.1"
)

# ==== Models: System message structure ====
class Finding(BaseModel):
    target_type: Optional[str] = None
    target_name: Optional[str] = None
    table: Optional[str] = None
    start_char_in_unit: Optional[int] = None
    end_char_in_unit: Optional[int] = None
    used_fields: Optional[List[str]] = None
    ambiguous: Optional[bool] = False
    suggested_fields: Optional[List[str]] = None
    suggested_statement: Optional[str] = None
    snippet: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    start_line: int = 0
    end_line: int = 0
    code: Optional[str] = ""
    orderby_sort_findings: Optional[List[Finding]] = None

# ==== Regexes for SQL analysis ====
SQL_SELECT_BLOCK_RE = re.compile(
    r"\bSELECT\b(?P<single>\s+SINGLE)?(?P<select>.+?)\bFROM\b\s+(?P<table>\w+)(?P<rest>.*?\.)",
    re.IGNORECASE | re.DOTALL,
)
FOR_ALL_ENTRIES_RE = re.compile(r"\bFOR\s+ALL\s+ENTRIES\b", re.IGNORECASE)
FIELDS_RE = re.compile(r"\b(\w+)\b", re.IGNORECASE)
ORDERBY_RE = re.compile(r"ORDER\s+BY", re.IGNORECASE)
INTO_TABLE_RE = re.compile(r"\bINTO\s+TABLE\s+(?:@DATA\((\w+)\)|(\w+))", re.IGNORECASE)

def make_sort_re(table_name: str):
    return re.compile(rf"\bSORT\s+{re.escape(table_name)}\b.*?\bBY\b", re.IGNORECASE | re.DOTALL)

# ==== System snippet helper (identical method as system message) ====
def snippet_at(text: str, start: int, end: int) -> str:
    s = max(0, start - 60)
    e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")

# ==== Main scanner, system-message identical finding structure ====
def scan_sql_block_style(code: str):
    findings = []

    for stmt in SQL_SELECT_BLOCK_RE.finditer(code):
        stmt_text = stmt.group(0)
        span = stmt.span()
        start, end = span
        is_single = bool(stmt.group("single"))
        has_fae = FOR_ALL_ENTRIES_RE.search(stmt_text) is not None

        select_fields_raw = stmt.group("select")
        if is_single:
            select_fields_raw = re.sub(r'^\s*SINGLE\s+', '', select_fields_raw, flags=re.IGNORECASE)
        select_fields_raw = re.sub(
            r"\bINTO\b.+", "", select_fields_raw, flags=re.IGNORECASE | re.DOTALL
        )
        select_fields_raw = re.sub(r"\s+", " ", select_fields_raw).strip()

        if "*" in select_fields_raw:
            findings.append(Finding(
                target_type="SQL_SELECT",
                target_name="SELECT_SINGLE" if is_single else ("FOR_ALL_ENTRIES" if has_fae else "NO_FOR_ALL_ENTRIES"),
                table=None,
                start_char_in_unit=start,
                end_char_in_unit=end,
                used_fields=["*"],
                ambiguous=False,
                suggested_fields=None,
                suggested_statement="Avoid SELECT * — not recommended. Please specify fields explicitly.",
                snippet=snippet_at(code, start, end),
                meta=None
            ))
            continue

        fields = []
        for tok in FIELDS_RE.findall(select_fields_raw):
            tok_up = tok.upper()
            if tok_up != "DISTINCT":
                fields.append(tok_up)
        fields = list(dict.fromkeys(fields))

        target_table = None
        m = INTO_TABLE_RE.search(stmt_text)
        if m:
            target_table = m.group(1) or m.group(2)

        suggestion = None
        if is_single:
            suggestion = None
        elif not has_fae:
            if not ORDERBY_RE.search(stmt_text.replace("\n", " ")):
                suggestion = (
                    f"Add ORDER BY {', '.join(fields)} inside SELECT (all fields in select list)."
                    if fields else "Add ORDER BY with all select fields."
                )
        else:
            after_stmt_text = code[end:]
            cleaned_lines = [line for line in after_stmt_text.splitlines() if not line.strip().startswith("*")]
            after_stmt_text = "\n".join(cleaned_lines)

            found_sort = False
            if target_table:
                sort_re = make_sort_re(target_table)
                if sort_re.search(after_stmt_text):
                    found_sort = True

            if not found_sort:
                suggestion = (
                    f"Add SORT by {', '.join(fields)} after this SELECT into {target_table} (all fields in select list)." if fields
                    else f"Add SORT by all select fields after this SELECT into {target_table}."
                )

        if suggestion:
            findings.append(Finding(
                target_type="SQL_SELECT",
                target_name="SELECT_SINGLE" if is_single else ("FOR_ALL_ENTRIES" if has_fae else "NO_FOR_ALL_ENTRIES"),
                table=target_table,
                start_char_in_unit=start,
                end_char_in_unit=end,
                used_fields=fields,
                ambiguous=False,
                suggested_fields=None,
                suggested_statement=suggestion,
                snippet=snippet_at(code, start, end),
                meta=None
            ))
    return findings

@app.post("/assess-orderby-sort")
async def assess(units: List[Unit]):
    results = []
    for u in units:
        code = u.code or ""
        findings = scan_sql_block_style(code)
        obj = u.model_copy()
        obj.orderby_sort_findings = findings
        results.append(obj)
    return results

@app.get("/health")
def health():
    return {"ok": True}