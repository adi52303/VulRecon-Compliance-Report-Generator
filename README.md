### VulRecon Compliance Report Generator

End-to-end Vulnerability → Risk → Compliance pipeline
Transforms raw recon data into an ISO 27001–aligned Risk Register and Executive PDF Reports in minutes.

🌍 Project Overview

This project demonstrates how raw technical vulnerability data can be normalized, risk-bucketed, and mapped to compliance controls — all automatically.

It is built to integrate with my companion project:
🔗 VulRecon Scanner- https://github.com/adi52303/VulRecon-scanner

Together they form a modular ecosystem for cyber risk & compliance reporting:

Scan – collect raw recon data

Parse – normalize scanner findings

Enrich & Map – bucket risks, align to ISO 27001

Report – export Risk Register, Compliance Summary, and PDF dashboards

🛰️ Input Data — VulRecon Scanner

To use this tool, you first need outputs from the VulRecon Scanner
.

1. Run the Scanner:
git clone https://github.com/adi52303/VulRecon-scanner.git
cd VulRecon-scanner
python vulrecon_scanner.py --domain example.com

2. Scanner Outputs

The scanner generates:

whois.txt → WHOIS information

dns.txt → DNS records

subdomains.txt → enumerated subdomains

ports.txt → open ports & services

and much more! 

3. Provide to Parser

Copy these into:

VulRecon-Compliance-Report-Generator/
└── Parser/
    └── reports/
        report1.txt
        report2.txt

⚙️ Workflow
1️⃣ Parser (Parser/parse_vulrecon_reports.py)

Reads raw recon TXT files

Normalizes into a findings dataset (sample_findings.csv)

Stores output in:

Parser/outputs/sample_findings.csv

2️⃣ Compliance & Risk (Compliance and risk/generate_compliance_and_risk.py)

Takes sample_findings.csv

Maps vulnerabilities → ISO 27001 control scaffold

Generates two key outputs:

📄 risk_register.csv → prioritized list of risks

📄 compliance_summary.csv → ISO 27001 control coverage

Stored in:

Compliance and risk/outputs/

3️⃣ PDF Reporting (pdfoutput/pdf_report_generator.py)

Consumes the enriched CSVs

Builds an executive-friendly PDF report with charts, summaries, and SLA tracking

Output in:

pdfoutput/outputs/report.pdf

📂 Repository Structure
VulRecon-Compliance-Report-Generator/
├── Compliance and risk/
│   ├── generate_compliance_and_risk.py
│   ├── iso27001_mapping_scaffold.csv
│   └── outputs/
├── Parser/
│   ├── parse_vulrecon_reports.py
│   ├── reports/              ← place scanner output here
│   └── outputs/
├── pdfoutput/
│   ├── pdf_report_generator.py
│   └── outputs/
├── LICENSE
└── README.md

🚀 Features

✅ End-to-end vulnerability → compliance workflow
✅ Modular: Scanner, Parser, Compliance, Reporting are independent
✅ Auto ISO 27001 mapping with customizable scaffold
✅ Risk bucketing (Critical/High/Medium/Low/Info)
✅ SLA due-date tracking and compliance scoring
✅ PDF report for executives and auditors

🔧 Tech Stack

Python 3.10+

pandas – CSV/Excel data handling

pathlib – clean path management

matplotlib / reportlab – PDF visualization & reporting

🎯 Why This Project Matters

Shows ability to design full security reporting pipelines

Demonstrates data wrangling, compliance alignment, automation, and reporting

Recruiters can see both technical depth (regex parsing, dataframes) and business alignment (ISO 27001, executive reports)

📜 License

MIT License – free to use, modify, and share.

👉 Together with the VulRecon Scanner
, this project forms a complete Recon → Risk → Compliance → Report workflow.
