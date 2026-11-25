# CertCheck — SSL/TLS Certificate & Configuration Analyzer

CertCheck is a Python tool (with both a CLI and a Tkinter GUI) for inspecting TLS certificates, trust chains, cryptographic strength, and supported TLS versions/ciphers on authorized lab hosts.

## Setup
```bash
pip install cryptography
```

## Run CLI
```bash
python certcheck.py your-lab-host.local -p 443 -o report.txt --cafile lab-ca.pem
```

## Run GUI
```bash
python gui_app.py
```

## Lab Rule
Test only on systems and hosts you own or have explicit written authorization to test.
