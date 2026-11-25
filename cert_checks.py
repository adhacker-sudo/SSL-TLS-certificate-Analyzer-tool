import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.hashes import MD5, SHA1
from cryptography.x509.oid import ExtensionOID, NameOID


def fetch_der_cert(host: str, port: int, timeout: float = 5.0) -> bytes:
    """Connect over TLS to fetch the peer certificate in DER binary format."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
            if not der_cert:
                raise RuntimeError("Server did not return a DER certificate.")
            return der_cert


def parse_certificate(der_bytes: bytes) -> dict[str, Any]:
    """Parse DER X.509 certificate and extract key metadata."""
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


def check_validity_dates(not_before: datetime, not_after: datetime) -> dict[str, Any]:
    """Report whether certificate is valid, expired, or not yet valid, plus days remaining."""
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
    """Verify chain and hostname against trust store without crashing on verification failure."""
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
            "detail": f"Chain/hostname check failed ({issue}): {exc.reason or exc}",
        }
    except OSError as exc:
        return {
            "verified": False,
            "issue": "connection_error",
            "detail": f"Connection error during chain verification: {exc}",
        }


def check_crypto_strength(parsed_cert: dict[str, Any]) -> dict[str, Any]:
    """Flag MD5/SHA-1 signatures and RSA < 2048 or EC < 224 bit keys."""
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
