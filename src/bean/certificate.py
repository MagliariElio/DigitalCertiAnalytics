from __future__ import annotations

import base64
import logging

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

# Admin: Anuar Elio Magliari
# Politecnico di Torino


class Certificate:
    """X.509 certificate loaded from zgrab2's raw format (base64 DER, no PEM headers)."""

    def __init__(self, raw: str | None):
        self.raw = raw
        self.cert = self.load(raw)

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
            logging.error(f"Certificato non valido, errore nel parsing: {e}")
            return None

    def extension_criticality(self, oid: x509.ObjectIdentifier) -> str:
        """Return 'Critical', 'Not Critical', 'Not Found' or 'Error' for the extension."""
        if self.cert is None:
            return "Not Found"
        try:
            extension = self.cert.extensions.get_extension_for_oid(oid)
        except x509.ExtensionNotFound:
            return "Not Found"
        except Exception as e:
            logging.error(f"Errore imprevisto durante il controllo dell'estensione {oid.dotted_string}: {e}")
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
            extension = self.cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
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
            logging.error(f"Errore imprevisto nel recupero delle CERTIFICATE_POLICIES: {e}")
            return None
