#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate risk register and ISO27001 compliance summary from parsed findings.

Paths:
- This file lives in:  .../Cyber Risk & Compliance Dashboard (CRCD)/Compliance and risk/
- Inputs (same folder): sample_findings.csv, iso27001_mapping_scaffold.csv/.xlsx
- Outputs (module-local): Compliance and risk/outputs/{risk_register.csv, compliance_summary.csv}

Other notes:
- Coalesces ISO mapping into existing columns (no overlapping-column errors)
- Gracefully handles missing/blank fields
"""

import sys
import re
from pathlib import Path
from typing import Dict

import pandas as pd

# ----------------------------
# Paths & IO helpers
# ----------------------------
# .../Cyber Risk & Compliance Dashboard (CRCD)
ROOT = Path(__file__).resolve().parents[1]
# .../CRCD/Compliance and risk
MOD_DIR = Path(__file__).resolve().parent

DATA_DIR = MOD_DIR                       # CSVs live right next to this script
OUT_DIR  = MOD_DIR / "outputs"           # module-specific outputs
OUT_DIR.mkdir(parents=True, exist_ok=True)

FINDINGS_CSV = DATA_DIR / "sample_findings.csv"
MAPPING_CSV  = DATA_DIR / "iso27001_mapping_scaffold.csv"
MAPPING_XLSX = DATA_DIR / "iso27001_mapping_scaffold.xlsx"

# Choose mapping file: prefer CSV, else XLSX
MAP_PATH = MAPPING_CSV if MAPPING_CSV.exists() else MAPPING_XLSX

def fail_if_missing(path: Path, label: str):
    if not path.exists():
        print(f"❌ Missing {label}: {path}")
        print(f"   (Working dir: {Path.cwd()})")
        sys.exit(1)

fail_if_missing(FINDINGS_CSV, "findings CSV")
fail_if_missing(MAP_PATH, "mapping file (csv/xlsx)")

# ----------------------------
# Load inputs
# ----------------------------
def load_mapping(path: Path) -> pd.DataFrame:
    if path.suffix.lower() in {".xlsx", ".xls"}:
        df = pd.read_excel(path)
    else:
        df = pd.read_csv(path)

    # Normalize expected columns if they exist
    wanted = ["vuln_pattern", "theme", "iso_control_candidate", "control_description", "owner_function"]
    for c in wanted:
        if c not in df.columns:
            df[c] = None  # allow partial mapping files

    # Clean up types/whitespace
    df["vuln_pattern"] = df["vuln_pattern"].astype("string").fillna("").str.strip()
    return df[wanted]

def load_findings(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    # Normalize key columns if missing
    for c in ["risk_score", "cvss", "severity", "status", "vuln_name", "port", "due_date"]:
        if c not in df.columns:
            if c in {"risk_score", "cvss"}:
                df[c] = 0.0
            elif c in {"severity", "status", "vuln_name"}:
                df[c] = ""
            elif c == "port":
                df[c] = ""
            elif c == "due_date":
                df[c] = ""

    # Numeric coercions
    df["cvss"] = pd.to_numeric(df["cvss"], errors="coerce").fillna(0.0)
    df["risk_score"] = pd.to_numeric(df.get("risk_score", df["cvss"]), errors="coerce").fillna(0.0)

    # Dates
    df["due_date"] = pd.to_datetime(df["due_date"], errors="coerce")

    # Strings
    for c in ["severity", "status", "vuln_name"]:
        df[c] = df[c].astype("string").fillna("").str.strip()

    return df

mapping  = load_mapping(MAP_PATH)
findings = load_findings(FINDINGS_CSV)

# ----------------------------
# Mapping (Option A: coalesce)
# ----------------------------
MAP_COLS = ["theme", "iso_control_candidate", "control_description", "owner_function"]

# Ensure target columns exist in findings
for c in MAP_COLS:
    if c not in findings.columns:
        findings[c] = None

# Row-wise mapping result (returns the 4 columns)
def map_control(row: pd.Series) -> pd.Series:
    name = str(row.get("vuln_name", "")).lower()
    if not name:
        return pd.Series({c: None for c in MAP_COLS})

    for _, m in mapping.iterrows():
        pat = str(m.get("vuln_pattern", "") or "").strip().lower()
        if not pat:
            continue
        try:
            if re.search(pat, name):
                return pd.Series({
                    "theme": m.get("theme"),
                    "iso_control_candidate": m.get("iso_control_candidate"),
                    "control_description": m.get("control_description"),
                    "owner_function": m.get("owner_function"),
                })
        except re.error:
            # Bad regex in mapping file; skip gracefully
            continue

    return pd.Series({c: None for c in MAP_COLS})

mapped_series_df = findings.apply(map_control, axis=1)

# Normalize blanks in existing columns to NA so combine_first works as "coalesce"
findings_norm = findings.copy()
for c in MAP_COLS:
    findings_norm[c] = (
        findings_norm[c]
        .astype("string")
        .replace({"": None, "TBD": None, "Unmapped": None, "nan": None}, regex=False)
    )

# Coalesce existing values with newly mapped values
for c in MAP_COLS:
    findings[c] = findings_norm[c].combine_first(mapped_series_df[c]).fillna("TBD")

# Final default for theme
findings["theme"] = findings["theme"].replace({None: "Unmapped", "": "Unmapped"}).fillna("Unmapped")

# ----------------------------
# Risk bucketing & severity rank
# ----------------------------
def bucket(score: float) -> str:
    try:
        s = float(score)
    except Exception:
        s = 0.0
    if s >= 9:   return "Critical"
    if s >= 7:   return "High"
    if s >= 4:   return "Medium"
    if s > 0:    return "Low"
    return "Info"

findings["risk_bucket"] = findings["risk_score"].apply(bucket)

SEV_RANK: Dict[str, int] = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
findings["sev_rank"] = findings["severity"].map(SEV_RANK).fillna(0).astype(int)

# ----------------------------
# Status scoring for compliance
# ----------------------------
def status_score(s: str) -> float:
    s = str(s or "").strip().lower()
    if s.startswith("in progress"):
        return 0.5
    if s.startswith("closed") or s.startswith("remediated"):
        return 1.0
    return 0.0

findings["status_score"] = findings["status"].apply(status_score)

# ----------------------------
# Risk Register export
# ----------------------------
RISK_COLS = [
    "finding_id", "asset_id", "asset_name", "environment", "ip", "port", "service",
    "vuln_name", "category", "severity", "cvss", "likelihood", "impact",
    "risk_score", "risk_bucket", "status",
    "theme", "iso_control_candidate", "control_description", "owner_function",
    "recommendation", "due_date"
]

# Ensure all risk columns exist (some scanners omit a few)
for c in RISK_COLS:
    if c not in findings.columns:
        findings[c] = ""

# Avoid errors when sorting by severity (if it's free text)
risk_register = (
    findings[RISK_COLS + ["sev_rank"]]
    .sort_values(["risk_score", "sev_rank"], ascending=[False, False])
    .drop(columns=["sev_rank"])
)

risk_path = OUT_DIR / "risk_register.csv"
risk_register.to_csv(risk_path, index=False)

# ----------------------------
# Compliance Summary (ISO view)
# ----------------------------
summary = (
    findings.groupby(["theme", "iso_control_candidate"], dropna=False)
    .agg(
        total_findings=("finding_id", "count"),
        avg_status=("status_score", "mean"),
        open_items=("status", lambda x: (x.astype("string").str.lower() == "open").sum()),
    )
    .reset_index()
)

def comp_label(avg: float) -> str:
    try:
        a = float(avg)
    except Exception:
        a = 0.0
    if a >= 0.9: return "Compliant"
    if a >= 0.4: return "Partial"
    return "Non-Compliant"

summary["compliance_status"] = summary["avg_status"].apply(comp_label)
summary_path = OUT_DIR / "compliance_summary.csv"
summary.to_csv(summary_path, index=False)

# ----------------------------
# Done
# ----------------------------
print("✅ Generated outputs:")
print(f" - {risk_path}")
print(f" - {summary_path}")
