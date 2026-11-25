import argparse
from pathlib import Path
from typing import Any

from cert_checks import (
    check_chain_and_hostname,
    check_crypto_strength,
    check_validity_dates,
    fetch_der_cert,
    parse_certificate,
)
from tls_probe import probe_ciphers, probe_tls_versions

VERDICT_RANK = {"PASS": 0, "WARN": 1, "FAIL": 2}


def grade_checks(
    validity: dict[str, Any],
    chain: dict[str, Any],
    crypto: dict[str, Any],
    tls_info: dict[str, Any],
    cipher_info: dict[str, Any],
) -> list[tuple[str, str, str]]:
    """Turn every check result into a (check_name, verdict, reason) tuple."""
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


def run_scan(host: str, port: int = 443, cafile: str | None = None) -> dict[str, Any]:
    """Run all certificate and TLS checks and return structured data + report text."""
    der_cert = fetch_der_cert(host, port)
    parsed = parse_certificate(der_cert)
    validity = check_validity_dates(parsed["not_before_dt"], parsed["not_after_dt"])
    chain = check_chain_and_hostname(host, port, parsed, cafile=cafile)
    crypto = check_crypto_strength(parsed)
    tls_info = probe_tls_versions(host, port)
    cipher_info = probe_ciphers(host, port)

    graded = grade_checks(validity, chain, crypto, tls_info, cipher_info)
    final_verdict = overall_verdict(graded)
    report_text = format_report(host, port, parsed, graded, final_verdict)

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


def format_report(
    host: str,
    port: int,
    parsed: dict[str, Any],
    graded: list[tuple[str, str, str]],
    final_verdict: str,
) -> str:
    lines = [
        "=" * 72,
        f"CertCheck Report for {host}:{port}",
        "=" * 72,
        f"Subject : {parsed['subject']}",
        f"Issuer  : {parsed['issuer']}",
        f"SANs    : {', '.join(parsed['sans']) if parsed['sans'] else 'None'}",
        f"Key/Sig : {parsed['key_type']} ({parsed['key_bits']} bits) | Sig: {parsed['sig_alg']}",
        "-" * 72,
    ]
    for name, verdict, reason in graded:
        lines.append(f"  [{verdict:4s}] {name:<26s} -> {reason}")
    lines.extend([
        "-" * 72,
        f"Overall Verdict: {final_verdict}",
        "=" * 72,
    ])
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CertCheck - SSL/TLS Certificate & Configuration Analyzer"
    )
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target TLS port (default: 443)")
    parser.add_argument(
        "-o", "--output", type=Path, default=Path("certcheck_report.txt"), help="Output report file"
    )
    parser.add_argument(
        "--cafile", type=str, default=None, help="Optional custom CA PEM file path"
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    result = run_scan(args.host, args.port, cafile=args.cafile)
    print(result["report_text"])
    args.output.write_text(result["report_text"] + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
