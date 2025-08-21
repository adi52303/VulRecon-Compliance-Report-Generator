#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from datetime import datetime, timedelta
import numpy as np
import pandas as pd

# Charts
import matplotlib
matplotlib.use("Agg")  # headless backend
import matplotlib.pyplot as plt

# ReportLab (Platypus)
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
)
from reportlab.pdfgen.canvas import Canvas

# ---------------------------
# Paths (module-local outputs; canonical findings in "Compliance and risk")
# ---------------------------
ROOT   = Path(__file__).resolve().parents[1]          # .../Cyber Risk & Compliance Dashboard (CRCD)
MOD    = Path(__file__).resolve().parent              # .../CRCD/pdfoutput
DATA   = ROOT / "Compliance and risk"                 # canonical findings live here
OUT    = MOD / "outputs"                              # PDF-specific outputs
ASSETS = MOD / "assets"                               # optional logo/images
OUT.mkdir(parents=True, exist_ok=True)

INFILE = DATA / "sample_findings.csv"
ts = datetime.now().strftime("%Y-%m-%d_%H%M")
PDF_PATH = OUT / f"Compliance_Risk_Report_{ts}.pdf"

# ---------------------------
# Load data
# ---------------------------
if not INFILE.exists():
    raise FileNotFoundError(f"Could not find: {INFILE}\n"
                            f"(Working dir: {Path.cwd()})")

df = pd.read_csv(INFILE)

# Ensure expected columns exist
need_cols_defaults = {
    "finding_id": np.nan, "asset_name": "", "severity": "", "cvss": 0.0,
    "likelihood": 0.0, "impact": 0.0, "risk_score": np.nan,
    "status": "", "theme": "Unmapped", "due_date": ""
}
for c, d in need_cols_defaults.items():
    if c not in df.columns:
        df[c] = d

for c in ["cvss", "likelihood", "impact", "risk_score"]:
    df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

df["due_date"] = pd.to_datetime(df["due_date"], errors="coerce")
df["severity"] = df["severity"].astype(str).str.title()
df["status_norm"] = df["status"].astype(str).str.strip().str.lower()
df["theme"] = df["theme"].astype(str).replace({"": "Unmapped"})

severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
df["severity_rank"] = df["severity"].map(severity_order).fillna(0).astype(int)

# ---------------------------
# SLA / Overdue logic
# ---------------------------
SLO = {"Critical":7, "High":30, "Medium":60, "Low":90, "Info":0}
now = pd.Timestamp.now()

df["sla_days"] = df["severity"].map(SLO).fillna(0).astype(int)

# add *timedelta* (not datetime) to due_date (fill NaT with now)
df["sla_target"] = np.where(
    df["sla_days"] > 0,
    df["due_date"].fillna(now) + pd.to_timedelta(df["sla_days"], unit="D"),
    df["due_date"]
)

df["overdue"] = (df["sla_days"] > 0) & (now > df["sla_target"])

# guard for NaT when computing “due soon”
delta = (df["sla_target"] - now)
due_soon_count = int((delta.dt.days <= 7).fillna(False).sum())
overdue_count   = int(df["overdue"].sum())

# ---------------------------
# Compliance scoring
# ---------------------------
def status_score(s: str) -> float:
    s = (s or "").strip().lower()
    if s.startswith("closed") or s.startswith("remediated"):
        return 1.0
    if s.startswith("in progress"):
        return 0.5
    return 0.0
df["status_score"] = df["status"].apply(status_score)

theme_grp = (
    df.groupby("theme", dropna=False)
      .agg(total_findings=("finding_id", "count"),
           open_items=("status_norm", lambda x: (x == "open").sum()),
           avg_status=("status_score", "mean"))
      .reset_index()
)

def comp_label(avg: float) -> str:
    if avg >= 0.9: return "Compliant"
    if avg >= 0.4: return "Partial"
    return "Non-Compliant"
theme_grp["compliance_status"] = theme_grp["avg_status"].apply(comp_label)

overall_total = int(theme_grp["total_findings"].sum())
overall_open  = int(theme_grp["open_items"].sum())
compliance_rate = round((1 - (overall_open / overall_total)) * 100, 1) if overall_total else 0.0

# ---------------------------
# Chart helpers
# ---------------------------
CHARTS_DIR = OUT / f"charts_{ts}"
CHARTS_DIR.mkdir(exist_ok=True)

def save_severity_bar(df):
    counts = df["severity"].astype(str).value_counts().reindex(
        ["Critical","High","Medium","Low","Info"], fill_value=0)
    fig, ax = plt.subplots(figsize=(5.0, 3.2))
    ax.bar(counts.index, counts.values, edgecolor="black",
           color=["#e53935","#fb8c00","#fdd835","#43a047","#546e7a"])
    ax.set_title("Findings by Severity")
    for i, v in enumerate(counts.values):
        ax.text(i, v + 0.3, str(int(v)), ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    p = CHARTS_DIR / "by_severity.png"
    fig.savefig(p, dpi=200); plt.close(fig)
    return p

def save_compliance_bar(theme_grp):
    comp_order = ["Compliant","Partial","Non-Compliant"]
    comp_colors = {"Compliant":"#4CAF50","Partial":"#FFC107","Non-Compliant":"#F44336"}
    counts = theme_grp["compliance_status"].value_counts().reindex(comp_order, fill_value=0)
    fig, ax = plt.subplots(figsize=(5.8,3.5))
    ax.bar(comp_order, counts.values, color=[comp_colors[c] for c in comp_order], edgecolor="black")
    for i, v in enumerate(counts.values):
        ax.text(i, v + 0.3, str(int(v)), ha="center", va="bottom", fontsize=9)
    ax.set_ylabel("Themes")
    ax.set_title("Theme Compliance Status")
    fig.tight_layout()
    p = CHARTS_DIR / "compliance_status.png"
    fig.savefig(p, dpi=200); plt.close(fig)
    return p

def save_risk_heatmap(df):
    lk = df["likelihood"].clip(0,1).to_numpy()
    im = df["impact"].clip(0,1).to_numpy()
    H, _, _ = np.histogram2d(lk, im, bins=6, range=[[0,1],[0,1]])
    fig, ax = plt.subplots(figsize=(5.2,4.2))
    img = ax.imshow(H.T, origin="lower", extent=[0,1,0,1], aspect="auto", cmap="Reds")
    fig.colorbar(img, ax=ax, shrink=0.8, label="Count")
    ax.set_xticks(np.linspace(0,1,6)); ax.set_yticks(np.linspace(0,1,6))
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.set_xlabel("Likelihood"); ax.set_ylabel("Impact")
    ax.set_title("Risk Density (Likelihood × Impact)")
    fig.tight_layout()
    p = CHARTS_DIR / "risk_heatmap.png"
    fig.savefig(p, dpi=200); plt.close(fig)
    return p

def save_theme_barchart(df):
    counts = df["theme"].astype(str).value_counts().sort_values(ascending=True)
    fig, ax = plt.subplots(figsize=(8.5,4.0))
    counts.plot.bar(ax=ax, color="skyblue", edgecolor="black")
    for i, v in enumerate(counts.values):
        ax.text(i, v + 0.5, str(int(v)), ha="center", va="bottom", fontsize=8)
    ax.set_title("Findings by Theme")
    plt.xticks(rotation=30, ha="right")
    fig.tight_layout()
    p = CHARTS_DIR / "findings_by_theme.png"
    fig.savefig(p, dpi=200); plt.close(fig)
    return p

sev_img   = save_severity_bar(df)
comp_img  = save_compliance_bar(theme_grp)
heat_img  = save_risk_heatmap(df)
theme_img = save_theme_barchart(df)

# ---------------------------
# Styles
# ---------------------------
styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="TitleBig", fontSize=28, alignment=TA_CENTER, leading=32, spaceAfter=20))
styles.add(ParagraphStyle(name="H2", parent=styles["Heading2"], spaceAfter=10, spaceBefore=16))
styles.add(ParagraphStyle(name="Body", parent=styles["BodyText"], fontSize=10.5, leading=14))
styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10))

# Footer
def on_page(canvas: Canvas, doc):
    canvas.saveState()
    footer = f"Compliance & Risk Report | Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} | Page {doc.page}"
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawRightString(doc.pagesize[0] - 15*mm, 12*mm, footer)
    canvas.restoreState()

# ---------------------------
# Build report
# ---------------------------
story = []

# --- Cover page ---
story.append(Spacer(1,60))
story.append(Paragraph("Compliance & Risk Report", styles["TitleBig"]))
story.append(Spacer(1,20))
story.append(Paragraph("Automated Report from VulRecon Findings", styles["Body"]))
story.append(Spacer(1,6))
story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Body"]))
story.append(Spacer(1,30))
story.append(Paragraph("Created by: Aditya Das", styles["Body"]))
story.append(PageBreak())

# --- Executive Summary ---
story.append(Paragraph("1. Executive Summary", styles["H2"]))
summary_text = (
    f"<b>Total Findings:</b> {overall_total}<br/>"
    f"<b>Open Items:</b> {overall_open}<br/>"
    f"<b>Overall Compliance Rate:</b> {compliance_rate}%<br/><br/>"
    f"• Highest volume themes: {', '.join(theme_grp.sort_values('total_findings', ascending=False)['theme'].head(3).tolist())}<br/>"
    f"• Overdue items: {overdue_count}, Due in next 7 days: {due_soon_count}<br/>"
    "• Prioritize Critical within 7d, High within 30d.<br/>"
    "• Remove insecure protocols (FTP/HTTP/Telnet).<br/>"
    "• Enforce TLS and strong authentication for remote access.<br/>"
)
story.append(Paragraph(summary_text, styles["Body"]))
story.append(Spacer(1,20))

# KPI tiles (with better numeric alignment)
kpi_data = [
    ["Total Findings", "Open Items", "Compliance Rate", "Overdue", "Due <7d"],
    [str(overall_total), str(overall_open), f"{compliance_rate}%", str(overdue_count), str(due_soon_count)],
]
kpi_tbl = Table(kpi_data, colWidths=[32*mm, 32*mm, 40*mm, 32*mm, 32*mm])
kpi_tbl.setStyle(TableStyle([
    ("GRID",         (0,0), (-1,-1), 0.5, colors.grey),
    ("BACKGROUND",   (0,0), (-1,0),  colors.lightgrey),
    ("FONTNAME",     (0,0), (-1,0),  "Helvetica-Bold"),
    ("FONTSIZE",     (0,0), (-1,0),  10),
    ("ALIGN",        (0,0), (-1,-1), "CENTER"),
    ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ("FONTSIZE",     (0,1), (-1,1),  18),
    ("TOPPADDING",   (0,1), (-1,1),  10),
    ("BOTTOMPADDING",(0,1), (-1,1),  10),
]))
story.append(kpi_tbl)

# --- Charts ---
story.append(Paragraph("2. Overview Charts", styles["H2"]))
story.append(Spacer(1,12))
story.append(Image(str(comp_img), width=150*mm, height=90*mm))
story.append(Spacer(1,12))
story.append(Image(str(sev_img), width=150*mm, height=80*mm))
story.append(Spacer(1,12))
story.append(Image(str(heat_img), width=150*mm, height=100*mm))
story.append(Spacer(1,12))
story.append(Image(str(theme_img), width=160*mm, height=90*mm))
story.append(PageBreak())

# --- Top 10 Risks ---
story.append(Paragraph("3. Top 10 Risks", styles["H2"]))

top10 = (
    df.sort_values(["risk_score", "severity_rank"], ascending=[False, False])
      .head(10)[["asset_name", "vuln_name", "severity", "cvss", "risk_score"]]
      .copy()
)
top10["vuln_name"] = top10["vuln_name"].astype(str).str.wrap(55).str.replace("\n", "<br/>")

sev_color = {
    "Critical": colors.HexColor("#e53935"),
    "High": colors.HexColor("#fb8c00"),
    "Medium": colors.HexColor("#fdd835"),
    "Low": colors.HexColor("#43a047"),
    "Info": colors.HexColor("#546e7a")
}

rows = [["Asset", "Vulnerability", "Severity", "CVSS", "Risk Score"]]
for _, r in top10.iterrows():
    rows.append([
        r["asset_name"],
        Paragraph(r["vuln_name"], styles["Body"]),
        r["severity"],
        f"{r['cvss']:.1f}",
        f"{r['risk_score']:.1f}"
    ])

tbl = Table(rows, colWidths=[45*mm, 95*mm, 25*mm, 20*mm, 25*mm], repeatRows=1)
ts = TableStyle([
    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("ALIGN", (3, 1), (-1, -1), "RIGHT"),
    ("VALIGN", (0, 0), (-1, -1), "TOP")
])
for i, row in enumerate(rows[1:], start=1):
    sev = row[2]
    ts.add("BACKGROUND", (2, i), (2, i), sev_color.get(sev, colors.whitesmoke))
    ts.add("TEXTCOLOR", (2, i), (2, i), colors.white)
    if i % 2 == 0:
        ts.add("BACKGROUND", (0, i), (-1, i), colors.whitesmoke)

tbl.setStyle(ts)
story.append(tbl)
story.append(PageBreak())

# --- Sample Risk Register ---
story.append(Paragraph("4. Sample Risk Register", styles["H2"]))
sample = df.head(15).copy()
sample["vuln_name"] = sample["vuln_name"].astype(str).str.wrap(50).str.replace("\n","<br/>")
cols = ["finding_id","asset_name","port","vuln_name","severity","risk_score","status"]
header = ["ID","Asset","Port","Vulnerability","Severity","Risk","Status"]
rows = [header]
for _, r in sample[cols].iterrows():
    rows.append([str(r["finding_id"]), r["asset_name"], str(r["port"]),
                 Paragraph(r["vuln_name"], styles["Body"]), r["severity"],
                 f"{r['risk_score']:.1f}", r["status"]])
reg_tbl = Table(rows, colWidths=[12*mm,35*mm,15*mm,95*mm,20*mm,20*mm,25*mm], repeatRows=1)
rs = TableStyle([
    ("GRID",(0,0),(-1,-1),0.25,colors.grey),
    ("BACKGROUND",(0,0),(-1,0),colors.lightgrey),
    ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
    ("VALIGN",(0,0),(-1,-1),"TOP")
])
for i in range(1,len(rows)):
    if i%2==0: rs.add("BACKGROUND",(0,i),(-1,i),colors.whitesmoke)
reg_tbl.setStyle(rs)
story.append(reg_tbl)

# ---------------------------
# Build PDF
# ---------------------------
doc = SimpleDocTemplate(
    str(PDF_PATH), pagesize=A4,
    rightMargin=16*mm, leftMargin=16*mm,
    topMargin=18*mm, bottomMargin=18*mm
)
doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

print(f"✅ PDF generated: {PDF_PATH}")
