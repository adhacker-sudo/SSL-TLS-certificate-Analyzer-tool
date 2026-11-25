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
