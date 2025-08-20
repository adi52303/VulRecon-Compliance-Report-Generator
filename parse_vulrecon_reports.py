# file: parse_vulrecon_reports_with_theme.py
import re
import pandas as pd
from pathlib import Path

# Base folders
base = Path(__file__).resolve().parents[0]   # current folder
reports_dir = base / "reports"
outputs_dir = base / "outputs"
outputs_dir.mkdir(exist_ok=True)

findings = []

# ---- Control & Theme mapper (ISO-style buckets) ----
def map_to_control(port, service, vuln_name, category):
    name = (str(vuln_name) or "").lower()
    svc = (str(service) or "").lower()
    cat = (str(category) or "").lower()
    port_str = str(port)

    # Software CVEs → Vulnerability management
    if name.startswith("vulnerability cve-") or cat == "software":
        return ("Technological", "Vulnerability management",
                "Ensure timely patching and remediation of software vulnerabilities",
                "IT Security")

    # SSH → Access control
    if "ssh" in svc or "ssh" in name or port_str == "22":
        return ("Technological", "Access control",
                "Require strong authentication (keys not passwords) and restrict root login for SSH",
                "IT Security")

    # HTTPS/TLS/SSL → Strong cryptography
    if "https" in svc or "tls" in name or "ssl" in name or port_str == "443":
        return ("Technological", "Use of strong cryptography",
                "All web services must enforce HTTPS/TLS and disable plaintext HTTP; use modern ciphers",
                "IT Security")

    # HTTP (plaintext) → Strong cryptography
    if ("http" in svc and "https" not in svc) or (port_str == "80" and "https" not in name):
        return ("Technological", "Use of strong cryptography",
                "All web services must enforce HTTPS/TLS and disable plaintext HTTP",
                "IT Security")

    # Legacy protocols → Secure network services
    if "ftp" in svc or port_str == "21" or "telnet" in svc or port_str == "23":
        return ("Technological", "Secure network services",
                "Disable or restrict use of insecure protocols; enforce secure alternatives (SFTP/SSH)",
                "IT Security")

    # Common DB ports → Secure network services
    if port_str in {"1433","1521","27017","3306","5432"}:
        return ("Technological", "Secure network services",
                "Restrict direct database exposure; enforce segmentation and strong authentication",
                "IT Security")

    # Fallback
    return ("Technological", "General security hardening",
            "Apply least privilege, harden services, and monitor for misconfigurations",
            "IT Security")

def bucket_from_score(score):
    try:
        s = float(score)
    except:
        s = 0.0
    if s >= 15: return "Critical"
    if s >= 10: return "High"
    if s >= 6:  return "Medium"
    if s > 0:   return "Low"
    return "Info"

def parse_report(path, fid_start=1):
    fid = fid_start
    rows = []
    asset_id = path.stem.upper()
    ip = ""
    domain = ""

    text = Path(path).read_text(encoding="utf-8", errors="ignore")

    # Extract target/domain
    m = re.search(r"Target:\s*(\S+)", text)
    if m: domain = m.group(1)

    # Extract A record / IP
    m = re.search(r"A Record:\s*([0-9\.]+)", text)
    if m: ip = m.group(1)

    # ---------- Open ports (Info) ----------
    ports_section = re.findall(r"- (\d+) \(([^)]+)\)", text)
    for port, service in ports_section:
        category = "Network Service"
        theme, iso_ctrl, ctrl_desc, owner = map_to_control(port, service, f"{service.upper()} service detected", category)
        risk_score = 0.0
        rows.append([
            fid, asset_id, domain, "Production", ip, int(port), service,
            f"{service.upper()} service detected", category, "Info", 0.0, 0, 0,
            risk_score, bucket_from_score(risk_score), "Open",
            theme, iso_ctrl, ctrl_desc, owner,
            f"Check {service} service configuration", ""
        ])
        fid += 1

    # ---------- CVEs ----------
    for cve, sev, score in re.findall(r"(CVE-\d{4}-\d+)\s*\|\s*Sev:\s*(\w+)\s*\|\s*Score:\s*([0-9\.]+)", text):
        category = "Software"
        theme, iso_ctrl, ctrl_desc, owner = map_to_control("-", "-", f"Vulnerability {cve}", category)
        cvss = float(score)
        # For CVE-only rows, use CVSS as risk_score (you can customize later)
        risk_score = cvss
        rows.append([
            fid, asset_id, domain, "Production", ip, "-", "-",
            f"Vulnerability {cve}", category, sev.capitalize(), cvss, 0, 0,
            risk_score, bucket_from_score(risk_score), "Open",
            theme, iso_ctrl, ctrl_desc, owner,
            f"Review patching for {cve}", "Based on severity"
        ])
        fid += 1

    # ---------- Potential Risks (full enriched block) ----------
    risk_blocks = re.findall(
        r"- Port (\d+): (.*?)\n\s+Environment:\s*(.*?)\n\s+Category:\s*(.*?)\n\s+Severity:\s*(.*?)\n\s+CVSS:\s*([0-9\.]+)\n\s+Likelihood:\s*(\d+)\n\s+Impact:\s*(\d+)\n\s+Risk Score:\s*([0-9\.]+)\n\s+Status:\s*(.*?)\n\s+Recommendation:\s*(.*?)\n\s+Due Date:\s*(.*?)\n",
        text, re.S
    )
    for port, desc, env, cat, sev, cvss, like, impact, rscore, status, rec, due in risk_blocks:
        theme, iso_ctrl, ctrl_desc, owner = map_to_control(port, "-", desc, cat)
        risk_bucket = bucket_from_score(rscore)
        rows.append([
            fid, asset_id, domain, (env.strip() or "Production"), ip, int(port), "-",
            desc.strip(), cat.strip(), sev.strip(), float(cvss), int(like), int(impact),
            float(rscore), risk_bucket, status.strip(),
            theme, iso_ctrl, ctrl_desc, owner, rec.strip(), due.strip()
        ])
        fid += 1

    return rows, fid


# ---- Run parse for all reports ----
fid_counter = 1
for file in reports_dir.glob("*.txt"):
    rows, fid_counter = parse_report(file, fid_counter)
    findings.extend(rows)

if findings:
    df = pd.DataFrame(findings, columns=[
        "finding_id","asset_id","asset_name","environment","ip","port","service",
        "vuln_name","category","severity","cvss","likelihood","impact","risk_score",
        "risk_bucket","status","theme","iso_control_candidate","control_description",
        "owner_function","recommendation","due_date"
    ])
    out_path = outputs_dir / "parsed_findings.csv"
    df.to_csv(out_path, index=False)
    print(f"✅ Parsed {len(df)} findings with themes/controls -> {out_path}")
else:
    print("⚠️ No findings parsed. Place VulRecon .txt reports in reports/")
