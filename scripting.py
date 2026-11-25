#!/usr/bin/env python3
"""
CertCheck — All-in-One SSL/TLS Certificate & Configuration Analyzer (CLI + GUI)
Lab / Authorised Hosts Only.
"""

import argparse
import json
import socket
import ssl
import sys
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.hashes import MD5, SHA1
from cryptography.x509.oid import ExtensionOID, NameOID

DEPRECATED_VERSIONS = {"SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_TOKENS = (
    "NULL",
    "ANON",
    "ADH",
    "AECDH",
    "EXPORT",
    "EXP",
    "RC4",
    "DES",
    "3DES",
    "MD5",
)
VERDICT_RANK = {"PASS": 0, "WARN": 1, "FAIL": 2}


# ---------------------------------------------------------------------------
# 1. Certificate Retrieval & Parsing
# ---------------------------------------------------------------------------

def fetch_der_cert(host: str, port: int, timeout: float = 5.0) -> bytes:
    """Connect over TLS to retrieve the server certificate in DER binary form."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
            if not der_cert:
                raise RuntimeError("Server did not present a DER certificate.")
            return der_cert


def parse_certificate(der_bytes: bytes) -> dict[str, Any]:
    """Parse DER X.509 certificate and extract subject, issuer, SANs, dates, key, and signature."""
    cert = x509.load_der_x509_certificate(der_bytes)

    not_before = getattr(
        cert, "not_valid_before_utc", cert.not_valid_before.replace(tzinfo=timezone.utc)
    )
    not_after = getattr(
        cert, "not_valid_after_utc", cert.not_valid_after.replace(tzinfo=timezone.utc)
    )

    sig_hash = cert.signature_hash_algorithm
    sig_alg_name = (
        sig_hash.name.upper() if sig_hash else cert.signature_algorithm_oid.dotted_string
    )
    key_type, key_bits = _describe_public_key(cert.public_key())

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "subject_cn": _extract_common_name(cert.subject),
        "issuer_cn": _extract_common_name(cert.issuer),
        "sans": _extract_sans(cert),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "not_before_dt": not_before,
        "not_after_dt": not_after,
        "sig_hash_cls": type(sig_hash) if sig_hash else None,
        "sig_alg": sig_alg_name,
        "key_type": key_type,
        "key_bits": key_bits,
        "is_self_signed": cert.issuer == cert.subject,
    }


def _extract_common_name(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def _extract_sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_ext = ext.value
        if isinstance(san_ext, x509.SubjectAlternativeName):
            values: list[str] = []
            values.extend(san_ext.get_values_for_type(x509.DNSName))
            values.extend(str(ip) for ip in san_ext.get_values_for_type(x509.IPAddress))
            return values
    except x509.ExtensionNotFound:
        pass
    return []


def _describe_public_key(pub_key: Any) -> tuple[str, int | None]:
    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA", pub_key.key_size
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        return f"EC ({pub_key.curve.name})", pub_key.key_size
    return type(pub_key).__name__, getattr(pub_key, "key_size", None)


# ---------------------------------------------------------------------------
# 2. Certificate Checks (Dates, Trust Chain & Hostname, Crypto Strength)
# ---------------------------------------------------------------------------

def check_validity_dates(not_before: datetime, not_after: datetime) -> dict[str, Any]:
    """Check whether the certificate is valid, expired, or not yet valid, and days left."""
    now = datetime.now(timezone.utc)
    if now < not_before:
        delta = not_before - now
        return {
            "status": "not_yet_valid",
            "days_remaining": 0,
            "detail": f"Not yet valid until {not_before.isoformat()} ({delta.days}d remaining).",
        }
    if now > not_after:
        delta = now - not_after
        return {
            "status": "expired",
            "days_remaining": 0,
            "detail": f"Expired {delta.days}d ago on {not_after.isoformat()}.",
        }
    remaining = not_after - now
    return {
        "status": "valid",
        "days_remaining": remaining.days,
        "detail": f"Valid; {remaining.days} days remaining (expires {not_after.isoformat()}).",
    }


def check_chain_and_hostname(
    host: str,
    port: int,
    parsed_cert: dict[str, Any],
    cafile: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Verify certificate chain and hostname against trust store without crashing."""
    ctx = ssl.create_default_context(cafile=cafile or None)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return {
                    "verified": True,
                    "issue": None,
                    "detail": "Certificate chain and hostname verified against trust store.",
                }
    except ssl.SSLCertVerificationError as exc:
        reason = (exc.reason or str(exc)).lower()
        if parsed_cert.get("is_self_signed"):
            issue = "self_signed"
        elif "hostname" in reason or "ip address mismatch" in reason:
            issue = "hostname_mismatch"
        else:
            issue = "untrusted_issuer"
        return {
            "verified": False,
            "issue": issue,
            "detail": f"Verification failed ({issue}): {exc.reason or exc}",
        }
    except OSError as exc:
        return {
            "verified": False,
            "issue": "connection_error",
            "detail": f"Connection error during chain verification: {exc}",
        }


def check_crypto_strength(parsed_cert: dict[str, Any]) -> dict[str, Any]:
    """Flag MD5/SHA-1 signatures and short RSA (< 2048) or EC (< 224) keys."""
    weak_items: list[str] = []
    sig_hash_cls = parsed_cert.get("sig_hash_cls")
    sig_alg = str(parsed_cert.get("sig_alg", "")).upper()

    if sig_hash_cls in (MD5, SHA1) or sig_alg in ("MD5", "SHA1", "SHA-1"):
        weak_items.append(f"Weak signature algorithm: {sig_alg}")

    key_type = str(parsed_cert.get("key_type", ""))
    key_bits = parsed_cert.get("key_bits")
    if key_type == "RSA" and isinstance(key_bits, int) and key_bits < 2048:
        weak_items.append(f"Short RSA key: {key_bits} bits (< 2048)")
    elif key_type.startswith("EC") and isinstance(key_bits, int) and key_bits < 224:
        weak_items.append(f"Short EC key: {key_bits} bits (< 224)")

    return {
        "is_weak": len(weak_items) > 0,
        "weak_items": weak_items,
        "detail": (
            "; ".join(weak_items)
            if weak_items
            else f"Strong signature ({sig_alg}) and key ({key_type} {key_bits}-bit)."
        ),
    }


# ---------------------------------------------------------------------------
# 3. TLS Protocol Versions & Cipher Suite Enumeration
# ---------------------------------------------------------------------------

def _protocol_candidates() -> list[tuple[str, int]]:
    candidates: list[tuple[str, int]] = []
    proto_enum = getattr(ssl, "TLSVersion", None)
    if proto_enum is None:
        return candidates

    mapping = [
        ("SSLv3", "SSLv3"),
        ("TLSv1", "TLSv1"),
        ("TLSv1.1", "TLSv1_1"),
        ("TLSv1.2", "TLSv1_2"),
        ("TLSv1.3", "TLSv1_3"),
    ]
    for label, attr in mapping:
        val = getattr(proto_enum, attr, None)
        if val is not None:
            candidates.append((label, int(val)))
    return candidates


def probe_tls_versions(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    """Probe each TLS version from SSLv3 through TLS 1.3 with an individual handshake."""
    supported: list[str] = []
    deprecated: list[str] = []

    for label, version_val in _protocol_candidates():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion(version_val)
            ctx.maximum_version = ssl.TLSVersion(version_val)
        except (ValueError, ssl.SSLError):
            continue

        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    negotiated = tls_sock.version() or label
                    supported.append(negotiated)
                    if negotiated in DEPRECATED_VERSIONS or label in DEPRECATED_VERSIONS:
                        deprecated.append(negotiated)
        except (ssl.SSLError, OSError):
            continue

    return {
        "supported_versions": list(dict.fromkeys(supported)),
        "deprecated_versions": list(dict.fromkeys(deprecated)),
    }


def _is_weak_cipher(cipher_name: str) -> bool:
    upper = cipher_name.upper()
    return any(token in upper for token in WEAK_CIPHER_TOKENS)


def probe_ciphers(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    """Probe cipher suites one at a time and flag weak, anonymous, or export ciphers."""
    probe_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    probe_ctx.check_hostname = False
    probe_ctx.verify_mode = ssl.CERT_NONE
    try:
        probe_ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        try:
            probe_ctx.set_ciphers("ALL")
        except ssl.SSLError:
            pass

    cipher_names = [
        entry["name"] for entry in probe_ctx.get_ciphers() if entry.get("name")
    ]
    accepted: list[str] = []
    weak_accepted: list[str] = []

    for cipher_name in dict.fromkeys(cipher_names):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers(f"{cipher_name}:@SECLEVEL=0")
        except ssl.SSLError:
            try:
                ctx.set_ciphers(cipher_name)
            except ssl.SSLError:
                continue

        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    active = tls_sock.cipher()
                    if active and active[0]:
                        name = active[0]
                        accepted.append(name)
                        if _is_weak_cipher(name):
                            weak_accepted.append(name)
        except (ssl.SSLError, OSError):
            continue

    return {
        "accepted_ciphers": list(dict.fromkeys(accepted)),
        "weak_ciphers": list(dict.fromkeys(weak_accepted)),
    }


# ---------------------------------------------------------------------------
# 4. Grading Engine & Report Formatter
# ---------------------------------------------------------------------------

def grade_checks(
    validity: dict[str, Any],
    chain: dict[str, Any],
    crypto: dict[str, Any],
    tls_info: dict[str, Any],
    cipher_info: dict[str, Any],
) -> list[tuple[str, str, str]]:
    """Convert each check outcome into a (check_name, verdict, reason) tuple."""
    results: list[tuple[str, str, str]] = []

    status = validity["status"]
    days = validity["days_remaining"]
    if status in ("expired", "not_yet_valid"):
        results.append(("Validity Dates", "FAIL", validity["detail"]))
    elif days <= 30:
        results.append(("Validity Dates", "WARN", f"Expires soon ({days} days remaining)."))
    else:
        results.append(("Validity Dates", "PASS", validity["detail"]))

    if chain["verified"]:
        results.append(("Chain & Hostname", "PASS", chain["detail"]))
    elif chain["issue"] == "self_signed":
        results.append(("Chain & Hostname", "FAIL", "Self-signed certificate not trusted by store."))
    elif chain["issue"] == "hostname_mismatch":
        results.append(("Chain & Hostname", "FAIL", "Certificate hostname/SAN does not match host."))
    else:
        results.append(("Chain & Hostname", "FAIL", chain["detail"]))

    if crypto["is_weak"]:
        results.append(("Key & Signature Strength", "FAIL", crypto["detail"]))
    else:
        results.append(("Key & Signature Strength", "PASS", crypto["detail"]))

    supported_versions = tls_info["supported_versions"]
    deprecated_versions = tls_info["deprecated_versions"]
    if not supported_versions:
        results.append(("TLS Versions", "FAIL", "No TLS protocol versions accepted."))
    elif deprecated_versions:
        results.append(
            ("TLS Versions", "FAIL", f"Deprecated TLS version(s): {', '.join(deprecated_versions)}.")
        )
    else:
        results.append(("TLS Versions", "PASS", f"Modern TLS only: {', '.join(supported_versions)}."))

    weak_ciphers = cipher_info["weak_ciphers"]
    accepted_ciphers = cipher_info["accepted_ciphers"]
    if weak_ciphers:
        results.append(
            ("Cipher Suites", "FAIL", f"Weak/export/anon cipher(s): {', '.join(weak_ciphers)}.")
        )
    elif not accepted_ciphers:
        results.append(("Cipher Suites", "WARN", "Could not enumerate accepted ciphers."))
    else:
        results.append(
            ("Cipher Suites", "PASS", f"{len(accepted_ciphers)} cipher(s) accepted; none weak.")
        )

    return results


def overall_verdict(graded: list[tuple[str, str, str]]) -> str:
    worst = "PASS"
    for _, verdict, _ in graded:
        if VERDICT_RANK[verdict] > VERDICT_RANK[worst]:
            worst = verdict
    return worst


def format_report(
    host: str,
    port: int,
    parsed: dict[str, Any],
    tls_info: dict[str, Any],
    cipher_info: dict[str, Any],
    graded: list[tuple[str, str, str]],
    final_verdict: str,
) -> str:
    lines = [
        "=" * 74,
        f"CertCheck Report for {host}:{port}",
        "=" * 74,
        f"Subject  : {parsed['subject']}",
        f"Issuer   : {parsed['issuer']}",
        f"SANs     : {', '.join(parsed['sans']) if parsed['sans'] else 'None'}",
        f"Validity : {parsed['not_before']} -> {parsed['not_after']}",
        f"Key/Sig  : {parsed['key_type']} ({parsed['key_bits']} bits) | Sig: {parsed['sig_alg']}",
        f"TLS Vers : {', '.join(tls_info['supported_versions']) or 'None'}",
        f"Ciphers  : {', '.join(cipher_info['accepted_ciphers']) or 'None'}",
        "-" * 74,
        "Graded Checks:",
    ]
    for name, verdict, reason in graded:
        lines.append(f"  [{verdict:4s}] {name:<25s} -> {reason}")
    lines.extend([
        "-" * 74,
        f"Overall Verdict: {final_verdict}",
        "=" * 74,
    ])
    return "\n".join(lines)


def run_scan(host: str, port: int = 443, cafile: str | None = None) -> dict[str, Any]:
    """Execute end-to-end TLS and certificate checks for a single host."""
    der_cert = fetch_der_cert(host, port)
    parsed = parse_certificate(der_cert)
    validity = check_validity_dates(parsed["not_before_dt"], parsed["not_after_dt"])
    chain = check_chain_and_hostname(host, port, parsed, cafile=cafile)
    crypto = check_crypto_strength(parsed)
    tls_info = probe_tls_versions(host, port)
    cipher_info = probe_ciphers(host, port)

    graded = grade_checks(validity, chain, crypto, tls_info, cipher_info)
    final_verdict = overall_verdict(graded)
    report_text = format_report(
        host, port, parsed, tls_info, cipher_info, graded, final_verdict
    )

    return {
        "host": host,
        "port": port,
        "subject": parsed["subject"],
        "issuer": parsed["issuer"],
        "subject_cn": parsed["subject_cn"],
        "issuer_cn": parsed["issuer_cn"],
        "sans": parsed["sans"],
        "not_before": parsed["not_before"],
        "not_after": parsed["not_after"],
        "sig_alg": parsed["sig_alg"],
        "key_type": parsed["key_type"],
        "key_bits": parsed["key_bits"],
        "is_self_signed": parsed["is_self_signed"],
        "supported_versions": tls_info["supported_versions"],
        "deprecated_versions": tls_info["deprecated_versions"],
        "accepted_ciphers": cipher_info["accepted_ciphers"],
        "weak_ciphers": cipher_info["weak_ciphers"],
        "checks": [
            {"check": name, "verdict": verdict, "reason": reason}
            for name, verdict, reason in graded
        ],
        "overall_verdict": final_verdict,
        "report_text": report_text,
    }


# ---------------------------------------------------------------------------
# 5. Built-in Tkinter GUI (--gui or default when launched with no arguments)
# ---------------------------------------------------------------------------

class CertCheckGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("CertCheck — SSL/TLS Certificate & Configuration Analyzer")
        self.root.geometry("880x640")
        self.last_result: dict[str, Any] | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        top = ttk.LabelFrame(
            self.root, text="Target Host (Lab / Authorised Systems Only)", padding=10
        )
        top.pack(fill="x", padx=12, pady=(10, 6))

        ttk.Label(top, text="Host:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(top, textvariable=self.host_var, width=28).grid(row=0, column=1, padx=(0, 12))

        ttk.Label(top, text="Port:").grid(row=0, column=2, sticky="w", padx=(0, 6))
        self.port_var = tk.StringVar(value="443")
        ttk.Entry(top, textvariable=self.port_var, width=8).grid(row=0, column=3, padx=(0, 12))

        ttk.Label(top, text="CA File (optional):").grid(
            row=1, column=0, sticky="w", pady=(8, 0), padx=(0, 6)
        )
        self.cafile_var = tk.StringVar(value="")
        ttk.Entry(top, textvariable=self.cafile_var, width=44).grid(
            row=1, column=1, columnspan=2, sticky="we", pady=(8, 0)
        )
        ttk.Button(top, text="Browse...", command=self._browse_cafile).grid(
            row=1, column=3, pady=(8, 0), padx=(6, 0)
        )

        btn_row = ttk.Frame(self.root, padding=(12, 4))
        btn_row.pack(fill="x")

        self.scan_btn = ttk.Button(btn_row, text="Run Scan", command=self._on_scan)
        self.scan_btn.pack(side="left")

        ttk.Button(btn_row, text="Save Report (.txt)", command=self._save_txt).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(btn_row, text="Save JSON (.json)", command=self._save_json).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(btn_row, text="Clear", command=self._clear).pack(side="right")

        table_frame = ttk.LabelFrame(self.root, text="Graded Checks", padding=8)
        table_frame.pack(fill="x", padx=12, pady=6)

        columns = ("check", "verdict", "reason")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=6)
        self.tree.heading("check", text="Check")
        self.tree.heading("verdict", text="Verdict")
        self.tree.heading("reason", text="Details")
        self.tree.column("check", width=210, anchor="w")
        self.tree.column("verdict", width=90, anchor="center")
        self.tree.column("reason", width=530, anchor="w")
        self.tree.pack(fill="x")

        self.verdict_label = ttk.Label(
            self.root, text="Overall Verdict: -", font=("Segoe UI", 11, "bold")
        )
        self.verdict_label.pack(anchor="w", padx=14, pady=(2, 4))

        report_frame = ttk.LabelFrame(self.root, text="Full Report Output", padding=8)
        report_frame.pack(fill="both", expand=True, padx=12, pady=(2, 12))

        self.output_box = scrolledtext.ScrolledText(
            report_frame, wrap="word", font=("Consolas", 10)
        )
        self.output_box.pack(fill="both", expand=True)

    def _browse_cafile(self) -> None:
        path = filedialog.askopenfilename(
            title="Select CA Certificate PEM File",
            filetypes=[("PEM / CRT files", "*.pem *.crt *.cer"), ("All files", "*.*")],
        )
        if path:
            self.cafile_var.set(path)

    def _on_scan(self) -> None:
        host = self.host_var.get().strip()
        if not host:
            messagebox.showwarning("Missing Host", "Please enter a target host.")
            return
        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            messagebox.showwarning("Invalid Port", "Port must be a number (e.g., 443).")
            return

        cafile = self.cafile_var.get().strip() or None
        self.scan_btn.config(state="disabled")
        self.root.update_idletasks()

        try:
            result = run_scan(host, port, cafile=cafile)
            self.last_result = result
            self._render_result(result)
        except Exception as exc:
            messagebox.showerror("Scan Failed", str(exc))
        finally:
            self.scan_btn.config(state="normal")

    def _render_result(self, result: dict[str, Any]) -> None:
        for row_id in self.tree.get_children():
            self.tree.delete(row_id)
        for item in result["checks"]:
            self.tree.insert(
                "", "end", values=(item["check"], item["verdict"], item["reason"])
            )
        self.verdict_label.config(text=f"Overall Verdict: {result['overall_verdict']}")
        self.output_box.delete("1.0", "end")
        self.output_box.insert("1.0", result["report_text"])

    def _save_txt(self) -> None:
        if not self.last_result:
            messagebox.showinfo("No Report", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile="certcheck_report.txt",
            filetypes=[("Text files", "*.txt")],
        )
        if path:
            Path(path).write_text(self.last_result["report_text"] + "\n", encoding="utf-8")
            messagebox.showinfo("Saved", f"Report saved to {path}")

    def _save_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("No Report", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile="certcheck_report.json",
            filetypes=[("JSON files", "*.json")],
        )
        if path:
            serializable = {k: v for k, v in self.last_result.items() if k != "report_text"}
            Path(path).write_text(json.dumps(serializable, indent=2), encoding="utf-8")
            messagebox.showinfo("Saved", f"JSON saved to {path}")

    def _clear(self) -> None:
        self.last_result = None
        for row_id in self.tree.get_children():
            self.tree.delete(row_id)
        self.verdict_label.config(text="Overall Verdict: -")
        self.output_box.delete("1.0", "end")


def launch_gui() -> None:
    root = tk.Tk()
    CertCheckGUI(root)
    root.mainloop()


# ---------------------------------------------------------------------------
# 6. CLI Entry Point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CertCheck — All-in-One SSL/TLS Certificate & Configuration Analyzer"
    )
    parser.add_argument("host", nargs="?", help="Target hostname or IP address")
    parser.add_argument(
        "-p", "--port", type=int, default=443, help="Target TLS port (default: 443)"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("certcheck_report.txt"),
        help="Output report file (default: certcheck_report.txt)",
    )
    parser.add_argument(
        "--cafile", type=str, default=None, help="Optional custom CA bundle PEM file"
    )
    parser.add_argument(
        "--json", type=Path, default=None, help="Optional JSON report output file"
    )
    parser.add_argument(
        "--gui", action="store_true", help="Launch the graphical interface"
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.gui or not args.host:
        launch_gui()
        return

    result = run_scan(args.host, args.port, cafile=args.cafile)
    print(result["report_text"])
    args.output.write_text(result["report_text"] + "\n", encoding="utf-8")
    if args.json:
        serializable = {k: v for k, v in result.items() if k != "report_text"}
        args.json.write_text(json.dumps(serializable, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()