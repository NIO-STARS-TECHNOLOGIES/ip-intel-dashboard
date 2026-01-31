# IP Intel Dashboard

A Flask-based cyber security dashboard that analyzes scan results, enriches vulnerabilities using live NIST NVD data, and presents findings through an interactive web interface with real-time progress streaming.

---

##  Features

- Upload JSON scan files for analysis
- Automatic CVE validation and de-duplication
- Live enrichment from NIST NVD (CVSS scores & descriptions)
- Real-time progress updates using Server‑Sent Events (SSE)
- Risk classification (Critical, High, Medium, Low)
- Modern cyber-themed UI with interactive dashboard
- Export-ready reporting layout

---

##  Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Security Data:** NIST NVD (CVE & CVSS)
- **Parsing:** BeautifulSoup, regex
- **Streaming:** Server-Sent Events (SSE)

---
