import socket
import ssl
from typing import Any

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


def _protocol_candidates() -> list[tuple[str, int]]:
    """Return supported TLSProtocolVersion candidates from SSLv3 through TLS 1.3."""
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
    """Probe each TLS version with an individual handshake."""
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


def probe_ciphers(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    """Probe cipher suites one by one and flag weak/anonymous/export ciphers."""
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


def _is_weak_cipher(cipher_name: str) -> bool:
    upper = cipher_name.upper()
    return any(token in upper for token in WEAK_CIPHER_TOKENS)
