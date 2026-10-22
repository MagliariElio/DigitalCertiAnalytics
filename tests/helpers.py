"""Real test certificates and synthetic rows in zgrab2 output format."""
import base64
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

NOW = datetime.datetime(2024, 10, 6, tzinfo=datetime.timezone.utc)
TIMESTAMP = "2024-10-06T00:44:30+02:00"
POLICY = x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"),
                                ["http://cps.example.test", x509.UserNotice(None, "notice")])


def make_name(common_name, organization="Test Org", country="IT"):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def distinguished_name(name):
    return ", ".join(f"{attribute.oid._name}={attribute.value}" for attribute in name)


def build_certificate(subject, issuer, public_key, signer_key, serial, is_ca, ocsp_url=None, sans=(), pss=False):
    """Build a certificate signed by `signer_key` with the extensions the analysis reads."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(public_key).serial_number(serial)
        .not_valid_before(NOW - datetime.timedelta(days=30))
        .not_valid_after(NOW + datetime.timedelta(days=3650 if is_ca else 365))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=not is_ca, data_encipherment=False,
            key_agreement=False, key_cert_sign=is_ca, crl_sign=is_ca, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.CertificatePolicies([POLICY]), critical=False)
    )
    if not is_ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san) for san in sans]), critical=False)
    if ocsp_url:
        builder = builder.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url)),
        ]), critical=False)
    if pss:
        pss_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        return builder.sign(signer_key, hashes.SHA256(), rsa_padding=pss_padding)
    return builder.sign(signer_key, hashes.SHA256())


def raw(certificate):
    return base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode()


def _names(name):
    keys = {"commonName": "common_name", "organizationName": "organization", "countryName": "country"}
    result = {}
    for attribute in name:
        result.setdefault(keys[attribute.oid._name], []).append(attribute.value)
    return result


def zgrab_certificate(certificate, self_signed=False, ocsp_url=None, with_ski=True, scts=0):
    """zgrab2 {"raw", "parsed"} representation of a certificate."""
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_info = {"key_algorithm": {"name": "RSA"}, "rsa_public_key": {"length": public_key.key_size}}
    else:
        key_info = {"key_algorithm": {"name": "ECDSA"}, "ecdsa_public_key": {"length": public_key.curve.key_size}}
    try:
        san_extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    extensions = {
        "authority_key_id": "aa" * 20,
        "basic_constraints": {"is_ca": basic_constraints.ca},
        "key_usage": {"digital_signature": True, "value": 1},
        "crl_distribution_points": [],
    }
    if basic_constraints.path_length is not None:
        extensions["basic_constraints"]["max_path_len"] = basic_constraints.path_length
    if with_ski:
        extensions["subject_key_id"] = format(certificate.serial_number, "x")
    if sans:
        extensions["subject_alt_name"] = {"dns_names": sans}
        extensions["extended_key_usage"] = {"server_auth": True}
    if ocsp_url:
        extensions["authority_info_access"] = {"ocsp_urls": [ocsp_url]}
    if scts:
        extensions["signed_certificate_timestamps"] = [
            {"log_id": f"log{i}==", "timestamp": 1727000000 + i, "version": 0, "signature": "AAAA"} for i in range(scts)]
    return {
        "raw": raw(certificate),
        "parsed": {
            "subject_dn": distinguished_name(certificate.subject), "issuer_dn": distinguished_name(certificate.issuer),
            "subject": _names(certificate.subject), "issuer": _names(certificate.issuer),
            "serial_number": str(certificate.serial_number), "version": 3,
            "signature_algorithm": {"name": "SHA256-RSA" if isinstance(public_key, rsa.RSAPublicKey) else "ECDSA-SHA256"},
            "subject_key_info": key_info,
            "validity": {"start": certificate.not_valid_before_utc.isoformat(),
                         "end": certificate.not_valid_after_utc.isoformat(),
                         "length": int((certificate.not_valid_after_utc - certificate.not_valid_before_utc).total_seconds())},
            "validation_level": "DV" if sans else "", "redacted": False, "names": sans,
            "signature": {"self_signed": self_signed, "valid": True},
            "extensions": extensions,
        },
    }


def success_row(domain, leaf, chain, stapling=False):
    server_certificates = {"certificate": leaf, "chain": chain, "validation": {"matches_domain": True}}
    handshake_log = {"server_hello": {"ocsp_stapling": stapling}, "server_certificates": server_certificates}
    tls = {"status": "success", "protocol": "tls", "timestamp": TIMESTAMP, "result": {"handshake_log": handshake_log}}
    return {"domain": domain, "data": {"tls": tls}}


def error_row(domain, status="connection-timeout"):
    return {"domain": domain, "data": {"tls": {"status": status, "protocol": "tls", "timestamp": TIMESTAMP, "error": "boom"}}}


class Pki:
    """Test PKI: RSA root -> EC intermediate -> EC leaf."""

    def __init__(self, ocsp_url=None):
        self.ocsp_url = ocsp_url
        self.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.root = build_certificate(make_name("Test Root CA"), make_name("Test Root CA"), self.root_key.public_key(),
                                      self.root_key, 1000, True)
        self.intermediate_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate = build_certificate(make_name("Test Intermediate CA"), self.root.subject,
                                              self.intermediate_key.public_key(), self.root_key, 1001, True, ocsp_url=ocsp_url)

    def leaf(self, domain, serial):
        key = ec.generate_private_key(ec.SECP256R1())
        return build_certificate(make_name(domain, "Leaf Org"), self.intermediate.subject, key.public_key(),
                                 self.intermediate_key, serial, False, ocsp_url=self.ocsp_url, sans=[domain])

    def rows(self, count):
        """`count` success rows (root in the chain only on even rows) plus two error rows."""
        rows = []
        for i in range(count):
            chain = [zgrab_certificate(self.intermediate, ocsp_url=self.ocsp_url)]
            if i % 2 == 0:
                chain.append(zgrab_certificate(self.root, self_signed=True))
            leaf = zgrab_certificate(self.leaf(f"site{i}.example.test", 5000 + i), ocsp_url=self.ocsp_url, scts=2)
            rows.append(success_row(f"site{i}.example.test", leaf, chain, stapling=i % 3 == 0))
        rows.append(error_row("down.example.test"))
        rows.append(error_row("broken.example.test", "unknown-error"))
        return rows
