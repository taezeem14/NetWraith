"""
NetWraith – SSL / TLS Certificate Inspector
=============================================

Connects to one or more ``ip:port`` targets, retrieves the TLS
certificate chain, and analyses each certificate for:

* **EXPIRED** – certificate validity has lapsed.
* **EXPIRING_SOON** – fewer than 30 days until expiration.
* **SELF_SIGNED** – issuer and subject are identical.
* **WEAK_SIGNATURE** – signature uses MD5 or SHA-1.
* **HOSTNAME_MISMATCH** – target hostname not in CN or SANs.
"""

import logging
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.hashes import MD5, SHA1
from cryptography.x509.oid import NameOID
from PyQt6.QtCore import QThread, pyqtSignal

logger = logging.getLogger(__name__)

_EXPIRING_SOON_DAYS = 30


class SSLInspectorThread(QThread):
    """
    QThread that inspects TLS certificates on a list of targets.

    Signals
    -------
    cert_result : dict
        Emitted per target with certificate details and security flags.
    error_signal : str
        Emitted on unrecoverable error.
    """

    cert_result = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(self, targets: list[str], parent=None) -> None:
        """
        Parameters
        ----------
        targets : list[str]
            Each entry is ``"host:port"`` (e.g. ``"192.168.1.1:443"``).
        """
        super().__init__(parent)
        self.targets = targets
        self._stop_flag = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Request the inspector to stop."""
        self._stop_flag = True

    # ------------------------------------------------------------------
    # QThread entry
    # ------------------------------------------------------------------
    def run(self) -> None:
        for target in self.targets:
            if self._stop_flag:
                break
            try:
                result = self._inspect(target)
                self.cert_result.emit(result)
            except Exception as exc:
                logger.warning("SSL inspection failed for %s: %s", target, exc)
                self.cert_result.emit(
                    {
                        "target": target,
                        "subject_cn": "",
                        "issuer": "",
                        "valid_from": "",
                        "valid_to": "",
                        "days_until_expiry": None,
                        "sans": [],
                        "key_algorithm": "",
                        "signature_algorithm": "",
                        "flags": [f"ERROR: {exc}"],
                    }
                )

    # ------------------------------------------------------------------
    # Per-target inspection
    # ------------------------------------------------------------------
    def _inspect(self, target: str) -> dict:
        """Connect to *target*, retrieve cert, and analyse."""
        host, port_str = self._parse_target(target)
        port = int(port_str)

        # Fetch raw DER certificate bytes
        der_cert = self._fetch_der_cert(host, port)

        # Parse with cryptography
        cert = x509.load_der_x509_certificate(der_cert)

        # Subject CN
        subject_cn = self._get_cn(cert.subject)
        # Issuer
        issuer_cn = self._get_cn(cert.issuer)
        issuer_org = self._get_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
        issuer_str = issuer_cn or issuer_org or "Unknown"

        # Validity
        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days_until_expiry = (valid_to - now).days

        # SANs
        sans: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        # Key algorithm
        pub_key = cert.public_key()
        key_algorithm = type(pub_key).__name__.replace("_", " ")

        # Signature algorithm
        sig_algo = cert.signature_algorithm_oid._name if cert.signature_algorithm_oid else "Unknown"

        # --- Flag detection ---
        flags: list[str] = []

        if days_until_expiry < 0:
            flags.append("EXPIRED")
        elif days_until_expiry < _EXPIRING_SOON_DAYS:
            flags.append("EXPIRING_SOON")

        if cert.issuer == cert.subject:
            flags.append("SELF_SIGNED")

        # Weak signature check
        sig_hash = cert.signature_hash_algorithm
        if sig_hash is not None and isinstance(sig_hash, (MD5, SHA1)):
            flags.append("WEAK_SIGNATURE")

        # Hostname mismatch
        all_names = set(sans)
        if subject_cn:
            all_names.add(subject_cn)
        if not self._hostname_matches(host, all_names):
            flags.append("HOSTNAME_MISMATCH")

        return {
            "target": target,
            "subject_cn": subject_cn,
            "issuer": issuer_str,
            "valid_from": valid_from.isoformat(),
            "valid_to": valid_to.isoformat(),
            "days_until_expiry": days_until_expiry,
            "sans": sans,
            "key_algorithm": key_algorithm,
            "signature_algorithm": sig_algo,
            "flags": flags,
        }

    # ------------------------------------------------------------------
    # TLS connection helper
    # ------------------------------------------------------------------
    @staticmethod
    def _fetch_der_cert(host: str, port: int) -> bytes:
        """Return the DER-encoded peer certificate bytes."""
        context = ssl.create_default_context()
        # We want to inspect even invalid certs
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                if der is None:
                    raise RuntimeError(f"No certificate received from {host}:{port}")
                return der

    # ------------------------------------------------------------------
    # Certificate attribute helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _get_cn(name: x509.Name) -> str:
        """Extract the Common Name from an x509 Name."""
        try:
            cn_attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            return cn_attrs[0].value if cn_attrs else ""
        except Exception:
            return ""

    @staticmethod
    def _get_attr(name: x509.Name, oid) -> str:
        try:
            attrs = name.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else ""
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Hostname matching (simplified RFC 6125)
    # ------------------------------------------------------------------
    @staticmethod
    def _hostname_matches(hostname: str, cert_names: set[str]) -> bool:
        """
        Check whether *hostname* matches any name in *cert_names*,
        supporting simple wildcard ``*.example.com`` patterns.
        """
        hostname = hostname.lower()
        for name in cert_names:
            name = name.lower()
            if name == hostname:
                return True
            # Wildcard match – only left-most label
            if name.startswith("*."):
                suffix = name[2:]
                # hostname must have at least one dot after the wildcard part
                if hostname.endswith(suffix) and hostname.count(".") >= name.count("."):
                    return True
        return False

    # ------------------------------------------------------------------
    # Target parsing
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_target(target: str) -> tuple[str, str]:
        """Split ``host:port`` into a tuple. Default port is 443."""
        if ":" in target:
            parts = target.rsplit(":", 1)
            return parts[0], parts[1]
        return target, "443"
