"""Storage of the raw certificates: zstd-compressed DER with a dictionary shared by the database.

A raw value is canonical when it is a non-empty base64 text that encodes back to itself: it is stored as
zstd(DER) in RawCertificates.der_zstd and decoded back to the same text. Any other value (empty, wrapped, invalid
base64, not a text) is kept verbatim in RawCertificates.raw, with its SQLite storage class.
"""
from __future__ import annotations

import base64
import binascii
import sqlite3

try:
    import zstandard
except ImportError:          # reported by Database.connect() with a clear message
    zstandard = None

# Admin: Anuar Elio Magliari
# Politecnico di Torino

COMPRESSION_LEVEL = 9
DICTIONARY_SIZE = 65536
# Distinct canonical raws used to train the dictionary, and the minimum needed to train one
DICTIONARY_SAMPLES = 4096
MIN_DICTIONARY_SAMPLES = 64
# Identifier of the dictionary row (a database has at most one)
DICTIONARY_ID = 1


def canonical_der(value: object) -> bytes | None:
    """DER of a canonical raw value (non-empty base64 text that encodes back to itself), else None."""
    if type(value) is not str or not value:
        return None
    try:
        der = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return der if base64.b64encode(der).decode("ascii") == value else None


def train_dictionary(samples: list[bytes]) -> bytes | None:
    """zstd dictionary of the DER samples; None with too few samples or if training fails."""
    if len(samples) < MIN_DICTIONARY_SAMPLES:
        return None
    try:
        dictionary = zstandard.train_dictionary(DICTIONARY_SIZE, samples, k=200, d=8, threads=1)
    except zstandard.ZstdError:
        return None
    return dictionary.as_bytes()


class RawCodec:
    """Encodes raw certificate values for RawCertificates and decodes them back (one instance per thread)."""

    def __init__(self, dictionary: bytes | None) -> None:
        self.dictionary = dictionary
        if dictionary is not None:
            data = zstandard.ZstdCompressionDict(dictionary)
            self._compressor = zstandard.ZstdCompressor(level=COMPRESSION_LEVEL, dict_data=data, write_checksum=False,
                                                        write_content_size=True, write_dict_id=False)
            self._decompressor = zstandard.ZstdDecompressor(dict_data=data)
        else:
            self._compressor = zstandard.ZstdCompressor(level=COMPRESSION_LEVEL, write_checksum=False,
                                                        write_content_size=True, write_dict_id=False)
            self._decompressor = zstandard.ZstdDecompressor()

    @classmethod
    def for_connection(cls, conn: sqlite3.Connection) -> RawCodec:
        """Codec of the dictionary of the database (SchemaInfo.raw_dictionary_id)."""
        row = conn.execute("SELECT d.zstd_dictionary FROM SchemaInfo AS s JOIN RawDictionaries AS d "
                           "ON d.dictionary_id = s.value WHERE s.key = 'raw_dictionary_id'").fetchone()
        return cls(bytes(row[0]) if row is not None else None)

    def encode(self, value: object) -> tuple[bytes | None, object]:
        """(der_zstd, raw) of a value that is not None."""
        der = canonical_der(value)
        if der is None:
            return None, value
        return self._compressor.compress(der), None

    def decode(self, der_zstd: bytes | None, raw: object) -> object:
        """The original value."""
        if der_zstd is None:
            return raw
        return base64.b64encode(self._decompressor.decompress(der_zstd)).decode("ascii")

    def der(self, der_zstd: bytes | None, raw: object) -> bytes | None:
        """DER of a canonical value (no base64 round trip), None for the values kept verbatim."""
        if der_zstd is None:
            return None
        return self._decompressor.decompress(der_zstd)


def register_sql_functions(conn: sqlite3.Connection) -> None:
    """Make dca_raw(der_zstd, raw) available on the connection: the original raw value of a RawCertificates row."""
    codec = RawCodec.for_connection(conn)
    conn.create_function("dca_raw", 2, codec.decode, deterministic=True)
