# Automated Attack Surface & Secret Discovery Engine

A lightweight offensive security reconnaissance tool written in Python. It automates the initial phase of a penetration test by mapping an organization's external digital footprint using Certificate Transparency (CT) logs and analyzing active web nodes for exposed API keys and credentials.

## Features
- **Passive Subdomain Mapping:** Queries crt.sh architecture to bypass traditional brute-force noise.
- **Live-Host Pipeline:** Validates active HTTP/HTTPS targets dynamically.
- **Automated Signature Matching:** Uses high-confidence regex engines to flag leaked AWS and third-party secrets in source code.

## How to Run
1. clone the repository: `git clone <your-repo-link>`
2. Install requirements: `pip install -r requirements.txt`
3. Run the script: `python recon_engine.py`

## Real-world Application
This tool mimics the early reconnaissance methodologies used during bug bounty hunting and external corporate infrastructure audits to identify low-hanging, high-impact exposure risks before malicious actors exploit them.