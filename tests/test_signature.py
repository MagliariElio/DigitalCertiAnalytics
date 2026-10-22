import base64
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from bean.certificate import Certificate
from utils.chain_utils import verify_signature


def self_signed(key, algorithm, rsa_padding=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)))
    if rsa_padding is not None:
        return builder.sign(key, algorithm, rsa_padding=rsa_padding)
    return builder.sign(key, algorithm)


RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_rsa_pkcs1v15_and_pss():
    pkcs = self_signed(RSA_KEY, hashes.SHA256())
    pss = self_signed(RSA_KEY, hashes.SHA256(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32))
    assert verify_signature(pkcs, pkcs) == "Valid"
    assert verify_signature(pss, pss) == "Valid"


def test_ec_and_eddsa():
    ec_cert = self_signed(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
    ed_cert = self_signed(ed25519.Ed25519PrivateKey.generate(), None)
    assert verify_signature(ec_cert, ec_cert) == "Valid"
    assert verify_signature(ed_cert, ed_cert) == "Valid"


def test_wrong_issuer_and_missing_certificates():
    cert = self_signed(RSA_KEY, hashes.SHA256())
    other = self_signed(rsa.generate_private_key(public_exponent=65537, key_size=2048), hashes.SHA256())
    assert verify_signature(cert, other) == "Not Valid"
    assert verify_signature(None, cert) == "Error"
    assert verify_signature(cert, None) == "Error"


def test_certificate_bean():
    cert = self_signed(RSA_KEY, hashes.SHA256())
    raw = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    bean = Certificate(raw)
    assert bean.cert == cert
    assert Certificate.to_pem(raw).startswith("-----BEGIN CERTIFICATE-----\n")
    assert bean.extension_criticality(x509.oid.ExtensionOID.KEY_USAGE) == "Not Found"
    assert bean.ocsp_must_staple() == "Not Found"
    assert Certificate("\n".join(raw[i:i + 64] for i in range(0, len(raw), 64))).cert == cert
    assert Certificate("not a certificate").cert is None
    assert Certificate(None).extension_criticality(x509.oid.ExtensionOID.KEY_USAGE) == "Not Found"
