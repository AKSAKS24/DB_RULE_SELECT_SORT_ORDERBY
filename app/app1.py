from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional
import re, json

app = FastAPI(title="ABAP Scanner - ORDER BY / SORT Rule (Final Table-Aware + Select Single Support)")

# Regex: capture SELECT [SINGLE] ... FROM ... until first period (.)
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

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    code: Optional[str] = ""

def scan_sql(code: str):
    results = []

    for stmt in SQL_SELECT_BLOCK_RE.finditer(code):
        stmt_text = stmt.group(0)   # full SELECT statement (ending at ".")
        span = stmt.span()
        is_single = bool(stmt.group("single"))
        has_fae = FOR_ALL_ENTRIES_RE.search(stmt_text) is not None

        # Extract selected fields and clean up 'SINGLE' if present
        select_fields_raw = stmt.group("select")
        if is_single:
            # Remove 'SINGLE' if present at the start
            select_fields_raw = re.sub(r'^\s*SINGLE\s+', '', select_fields_raw, flags=re.IGNORECASE)
        select_fields_raw = re.sub(
            r"\bINTO\b.+", "", select_fields_raw, flags=re.IGNORECASE | re.DOTALL
        )
        select_fields_raw = re.sub(r"\s+", " ", select_fields_raw).strip()

        # Case A: SELECT * → Always suggestion
        if "*" in select_fields_raw:
            results.append({
                "target_type": "SQL_SELECT",
                "target_name": (
                    "SELECT_SINGLE" if is_single else "FOR_ALL_ENTRIES" if has_fae else "NO_FOR_ALL_ENTRIES"
                ),
                "span": span,
                "used_fields": ["*"],
                "suggested_statement": "Avoid SELECT * — not recommended. Please specify fields explicitly."
            })
            continue

        # Extract list of fields
        fields = []
        for tok in FIELDS_RE.findall(select_fields_raw):
            tok_up = tok.upper()
            if tok_up not in ["DISTINCT"]:
                fields.append(tok_up)
        fields = list(dict.fromkeys(fields))  # dedupe

        # Extract INTO TABLE target name
        target_table = None
        m = INTO_TABLE_RE.search(stmt_text)
        if m:
            target_table = m.group(1) or m.group(2)

        suggestion = None

        # Skip ORDER BY check for SELECT SINGLE
        if is_single:
            pass  # No order by or sort required for select single

        elif not has_fae:  # --- Normal SELECT must have ORDER BY
            if not ORDERBY_RE.search(stmt_text.replace("\n", " ")):
                suggestion = (
                    f"Add ORDER BY {', '.join(fields)} inside SELECT (all fields in select list)."
                    if fields else "Add ORDER BY with all select fields."
                )
        else:  # --- FOR ALL ENTRIES must have SORT for same table
            after_stmt_text = code[span[1]:]  # code after SELECT period

            # Strip out comment lines
            cleaned_lines = []
            for line in after_stmt_text.splitlines():
                if line.strip().startswith("*"):
                    continue
                cleaned_lines.append(line)
            after_stmt_text = "\n".join(cleaned_lines)

            found_sort = False
            if target_table:
                sort_re = make_sort_re(target_table)
                if sort_re.search(after_stmt_text):
                    found_sort = True

            if not found_sort:
                suggestion = (
                    f"Add SORT by {', '.join(fields)} after this SELECT into {target_table} (all fields in select list)."
                    if fields else f"Add SORT by all select fields after this SELECT into {target_table}."
                )

        if suggestion:
            results.append({
                "target_type": "SQL_SELECT",
                "target_name": (
                    "SELECT_SINGLE" if is_single else "FOR_ALL_ENTRIES" if has_fae else "NO_FOR_ALL_ENTRIES"
                ),
                "span": span,
                "used_fields": fields,
                "suggested_statement": suggestion,
            })

    return results

@app.post("/assess-orderby-sort")
def assess(units: List[Unit]):
    results = []
    for u in units:
        src = u.code or ""
        findings = []
        seen = set()
        for hit in scan_sql(src):
            key = (hit["target_type"], hit["span"])
            if key not in seen:
                seen.add(key)
                findings.append({
                    "table": None,
                    "target_type": hit["target_type"],
                    "target_name": hit["target_name"],
                    "start_char_in_unit": hit["span"][0],
                    "end_char_in_unit": hit["span"][1],
                    "used_fields": hit["used_fields"],
                    "ambiguous": False,
                    "suggested_fields": None,
                    "suggested_statement": hit["suggested_statement"],
                })
        obj = json.loads(u.model_dump_json())
        obj["selects"] = findings
        results.append(obj)
    return results

@app.get("/health")
def health():
    return {"ok": True, "note": "ORDER_BY_SORT_RULE - with SELECT SINGLE support"}