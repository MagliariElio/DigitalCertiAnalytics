from __future__ import annotations

import base64
import logging

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from utils.chain_utils import verify_signature

# Admin: Anuar Elio Magliari
# Politecnico di Torino


class Certificate:
    """X.509 certificate loaded from zgrab2's raw format (base64 DER, no PEM headers).

    Derived values are memoized per instance only when they are computed without errors, so a value that logs an
    error logs it again on every call, as an unmemoized lookup would.
    """

    def __init__(self, raw: str | None):
        self.raw = raw
        self.cert = self.load(raw)
        self._extensions: dict[x509.ObjectIdentifier, x509.Extension] | None = None
        self._self_signature: str | None = None

    @staticmethod
    def to_pem(raw: str | None) -> str | None:
        """Wrap a raw certificate in PEM headers."""
        if raw is None:
            return None
        return f"-----BEGIN CERTIFICATE-----\n{raw}\n-----END CERTIFICATE-----"

    @staticmethod
    def load(raw: str | None) -> x509.Certificate | None:
        """Parse the raw certificate; return None if missing or invalid."""
        if raw is None:
            return None
        try:
            # raw is base64 DER: decoding it directly avoids a PEM round-trip; line breaks are tolerated as by PEM
            return x509.load_der_x509_certificate(base64.b64decode("".join(raw.split()), validate=True))
        except Exception as e:
            logging.error(f"Invalid certificate, parsing error: {e}")
            return None

    def _extensions_by_oid(self) -> dict[x509.ObjectIdentifier, x509.Extension] | None:
        """Extensions by OID (first occurrence wins, as get_extension_for_oid); None if they cannot be parsed."""
        if self._extensions is None:
            try:
                extensions = self.cert.extensions
            except Exception:
                return None
            by_oid: dict[x509.ObjectIdentifier, x509.Extension] = {}
            for extension in extensions:
                by_oid.setdefault(extension.oid, extension)
            self._extensions = by_oid
        return self._extensions

    def extension_criticality(self, oid: x509.ObjectIdentifier) -> str:
        """Return 'Critical', 'Not Critical', 'Not Found' or 'Error' for the extension."""
        if self.cert is None:
            return "Not Found"
        by_oid = self._extensions_by_oid()
        if by_oid is not None:
            extension = by_oid.get(oid)
            if extension is None:
                return "Not Found"
            return "Critical" if extension.critical else "Not Critical"
        try:
            extension = self.cert.extensions.get_extension_for_oid(oid)
        except x509.ExtensionNotFound:
            return "Not Found"
        except Exception as e:
            logging.error(f"Unexpected error while checking the extension {oid.dotted_string}: {e}")
            return "Error"
        return "Critical" if extension.critical else "Not Critical"

    def ocsp_must_staple(self) -> str:
        """Return 'Enabled' if the TLS Feature (OCSP must-staple) extension is present, else 'Not Found' or 'Error'."""
        status = self.extension_criticality(ExtensionOID.TLS_FEATURE)
        return status if status in ("Not Found", "Error") else "Enabled"

    def certificate_policies(self) -> list[dict] | None:
        """Return the certificate policies, or None if absent or unreadable."""
        if self.cert is None:
            return None
        try:
            by_oid = self._extensions_by_oid()
            if by_oid is None:
                extension = self.cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            else:
                extension = by_oid.get(ExtensionOID.CERTIFICATE_POLICIES)
                if extension is None:
                    return None
            is_critical = "Critical" if extension.critical else "Not Critical"
            return [
                {
                    'policy_identifier': policy.policy_identifier.dotted_string,
                    'cps': policy.policy_qualifiers,
                    'policy_qualifiers': policy.policy_qualifiers,
                    'is_cp_critical': is_critical,
                }
                for policy in extension.value
            ]
        except x509.ExtensionNotFound:
            return None
        except Exception as e:
            logging.error(f"Unexpected error while reading the CERTIFICATE_POLICIES: {e}")
            return None

    def self_signature_validity(self) -> str:
        """Signature verified with the certificate's own public key (roots), as verify_signature(cert, cert)."""
        if self._self_signature is not None:
            return self._self_signature
        validity = verify_signature(self.cert, self.cert)
        # 'Error' is the only outcome that logs: it is not memoized so that it is logged on every call
        if validity != "Error":
            self._self_signature = validity
        return validity
