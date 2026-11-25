# SSL-TLS-certificate-Analyzer-tool
SSL/TLS certificate and transport configuration analyzer featuring both CLI and Tkinter GUI interfaces. It inspects X.509 certificate details, validity dates, trust chains/hostnames, key/signature strength, and supported TLS versions and cipher suites, grading result
# CertCheck — SSL/TLS Certificate & Configuration Analyzer

**CertCheck** is a Python-based security diagnostic tool with both a **Command-Line Interface (CLI)** and a **Tkinter Graphical User Interface (GUI)** for inspecting X.509 SSL/TLS certificates and evaluating server transport configurations in controlled lab and authorized environments.

---

## Table of Contents
- [Overview & Key Features](#overview--key-features)
- [Project & Folder Structure](#project--folder-structure)
- [Installation & Setup](#installation--setup)
- [How to Run (GUI, CLI & Lab Server)](#how-to-run-gui-cli--lab-server)
- [Security Checks & Grading Logic](#security-checks--grading-logic)
- [Finding Write-Up (Weak Crypto & Deprecated TLS)](#finding-write-up-weak-crypto--deprecated-tls)
- [Ethical & Lab Scope Notice](#ethical--lab-scope-notice)

---

## Overview & Key Features
- **Certificate Retrieval & X.509 Parsing:** Connects to `host:port`, fetches peer certificates in DER format, and extracts Subject, Issuer, Subject Alternative Names (SANs), validity dates, public key type/length, and signature algorithm.
- **Validity & Expiration Check:** Compares certificate start and expiry dates against current UTC time to detect expired, not-yet-valid, or soon-to-expire (`<= 30 days`) certificates.
- **Trust Chain & Hostname Verification:** Validates certificate chains against trusted or custom lab CA bundles (`--cafile`) and checks SAN/CN hostname matching while handling self-signed or untrusted issuer errors cleanly.
- **Cryptographic Strength Check:** Flags weak signature hash algorithms (`MD5`, `SHA-1`) and short public keys (`RSA < 2048 bits`, `ECC < 224 bits`).
- **TLS Version & Cipher Suite Probing:** Probes supported TLS versions and cipher suites, flagging deprecated protocols (`SSLv3`, `TLS 1.0`, `TLS 1.1`) and weak, export, or anonymous ciphers (`NULL`, `RC4`, `3DES`, `DES`, `EXPORT`, `ANON`).
- **Grading & Report Export:** Assigns `PASS`, `WARN`, or `FAIL` verdicts to each check, computes an overall verdict (`FAIL` > `WARN` > `PASS`), and exports reports in `.txt` and `.json` formats.

---

## Project & Folder Structure

```text
CertCheck/
├── README.md
├── CertCheck_Scan_Results.xlsx
├── src/
│   ├── certcheck.py          # CLI entry point, grading logic & report output
│   ├── cert_checks.py        # DER fetch, X.509 parsing, chain & crypto checks
│   ├── tls_probe.py          # TLS version & cipher suite probing
│   └── gui_app.py            # Tkinter desktop GUI
├── lab/
│   └── lab_tls_server.py     # Local lab TLS test server (127.0.0.1:8443)
└── examples/
    ├── lab_report.txt        # Sample scan report from lab testing
    └── lab_report.json       # Sample structured JSON output
Installation & Setup
git clone [https://github.com/](https://github.com/)<your-username>/CertCheck.git
cd CertCheck
Install required dependency:
pip instal cryptography
How to Run (GUI, CLI & Lab Server)
1. Start Local Lab TLS Test Server (127.0.0.1:8443)
python lab/lab_tls_server.py
python src/gui_app.py

Enter Host (127.0.0.1), Port (8443), and optional CA File (certcheck_lab_ca.pem).
Click Run Scan, review the graded table and verdict, and export .txt or .json reports.
Run Command-Line Interface (CLI)
python src/certcheck.py 127.0.0.1 -p 8443 --cafile certcheck_lab_ca.pem -o examples/lab_report.txt --json examples/lab_report.json
Security Checks & Grading Logic
Check Category	                                   PASS                   	                     WARN	                                                    FAIL
Validity Dates	                              Valid UTC window (> 30 days left)	               Expires in <= 30 days	                         Expired or not yet valid
Chain & Hostname	                          Trusted CA + matching SAN/CN		                 ---                       Self-signed, untrusted CA, or hostname mimatch
Key & Signature	                              RSA >= 2048 / ECC >= 224 bits & SHA-256+	          —	                                   MD5/SHA-1 signature or short key
TLS Versions	                              Only TLS 1.2 and/or TLS 1.3	                      —	                             SSLv3, TLS 1.0, or TLS 1.1 accepted
TLS Versions	                              Only TLS 1.2 and/or TLS 1.3	                      —                            	SSLv3, TLS 1.0, or TLS 1.1 accepted

Finding Write-Up (Weak Crypto & Deprecated TLS)
What It Is: Certificates signed with weak hash algorithms (such as SHA-1 or MD5) or servers accepting deprecated TLS versions (SSLv3, TLS 1.0, TLS 1.1) and weak cipher suites.

Why It Is a Risk: Outdated algorithms and legacy TLS protocols have known weaknesses that increase exposure to collision, interception, or protocol downgrade risks.

How CertCheck Detects It: CertCheck inspects X.509 certificate metadata and probes TLS handshakes/ciphers in lab environments, surfacing issues as WARN or FAIL findings with remediation guidance.
Ethical & Lab Scope Notice
Use CertCheck strictly for educational purposes, cybersecurity coursework, and authorized testing on systems, virtual machines, or lab servers that you own or have explicit permission to test.
