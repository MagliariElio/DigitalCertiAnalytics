from utils.chain_utils import (count_intermediates_up_to_root, find_raw_cert_issuer, find_root_certificate,
                               intermediate_certificates, is_root_certificate, reorder_signature_algorithm, walk_chain)


def cert(subject, issuer, serial="1", self_signed=False):
    parsed = {"subject_dn": subject, "issuer_dn": issuer, "serial_number": serial, "signature": {"self_signed": self_signed}}
    return {"raw": f"raw-{subject}-{serial}", "parsed": parsed}


LEAF = cert("CN=leaf", "CN=I1")
I1 = cert("CN=I1", "CN=I2")
I2 = cert("CN=I2", "CN=R")
ROOT = cert("CN=R", "CN=R", serial="9", self_signed=True)


def test_root_detection():
    assert is_root_certificate(ROOT)
    assert not is_root_certificate(I1)
    assert not is_root_certificate(cert("CN=X", "CN=X", self_signed=False))


def test_walk_chain_follows_issuers_and_stops_at_root():
    chain = [ROOT, I2, I1]
    steps = list(walk_chain(chain, LEAF))
    assert [found for found, _ in steps] == [I1, I2, ROOT]
    assert steps[0][1] == [ROOT, I2]
    assert chain == [ROOT, I2, I1], "la catena originale non deve essere modificata"


def test_duplicate_serial_numbers_do_not_break_the_walk():
    chain = [I1, I2, ROOT]       # I1 and I2 share the same serial number
    assert find_root_certificate(chain, LEAF) == (ROOT, 2)
    assert count_intermediates_up_to_root(chain, LEAF) == (2, True)
    assert [found for found, _ in intermediate_certificates(chain, LEAF)] == [I1, I2]


def test_incomplete_chain():
    assert find_root_certificate([I1], LEAF) == (None, 0)
    assert count_intermediates_up_to_root([I1], LEAF) == (1, False)
    assert count_intermediates_up_to_root([], LEAF) == (0, False)
    assert list(intermediate_certificates([], LEAF)) == []


def test_intermediates_of_a_self_signed_leaf():
    self_signed = cert("CN=dev", "CN=dev", self_signed=True)
    assert list(intermediate_certificates([cert("CN=dev", "CN=other")], self_signed)) == []


def test_cycles_terminate():
    a = cert("CN=A", "CN=B")
    b = cert("CN=B", "CN=A")
    assert count_intermediates_up_to_root([a, b], cert("CN=leaf", "CN=A")) == (2, False)


def test_find_raw_cert_issuer():
    assert find_raw_cert_issuer([I1, I2], "CN=I2") == I2["raw"]
    assert find_raw_cert_issuer([I1], "CN=missing") is None


def test_reorder_signature_algorithm():
    assert reorder_signature_algorithm("SHA256-RSA") == "RSA-SHA256"
    assert reorder_signature_algorithm("SHA256-RSAPSS") == "RSAPSS-SHA256"
    assert reorder_signature_algorithm("ECDSA-SHA256") == "ECDSA-SHA256"
