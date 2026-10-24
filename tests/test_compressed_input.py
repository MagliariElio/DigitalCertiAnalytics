"""Compressed input files: detection, the line-indexed zstd format, the stream reader and --compress_input."""
import bz2
import gzip
import json
import logging
import lzma
import multiprocessing
import os
import shutil
import struct
import subprocess
import sys
import threading

import pytest
import zstandard
from helpers import Pki
from test_pipeline import _engine, _reference, count, project  # noqa: F401 (project: fixture)

from analysis import ingestion, input_file
from analysis.input_file import (INPUT_NAMES, BlockSpec, InputFileError, compress_file, compress_input, detect_format,
                                 find_input, iter_line_blocks, open_source, read_block, verify_file)

FORMATS = {
    "gz": lambda data: gzip.compress(data, 6),
    "bz2": lambda data: bz2.compress(data, 9),
    "xz": lzma.compress,
    "zst": lambda data: zstandard.ZstdCompressor(level=3).compress(data),
}


@pytest.fixture(scope="module")
def plain_file(tmp_path_factory):
    """Valid, error and invalid lines; the last line has no newline."""
    rows = Pki().rows(20)
    lines = [json.dumps(row).encode() + b"\n" for row in rows]
    lines[5:5] = [b"not json\n", b"\n"]
    path = tmp_path_factory.mktemp("plain") / "certs_polito.json"
    path.write_bytes(b"".join(lines) + json.dumps(rows[3]).encode())
    return path


def _compressed(path, tmp_path, file_format):
    target = tmp_path / f"certs_polito.json.{file_format}"
    if file_format == "zst-indexed":
        target = tmp_path / "certs_polito.json.zst"
        compress_file(path, target, chunk_size=4096, threads=3)
    else:
        target.write_bytes(FORMATS[file_format](path.read_bytes()))
    return target


def _block_texts(source, chunk_size, staging_dir):
    try:
        return [source.read(block) for block in source.blocks(chunk_size, str(staging_dir))]
    finally:
        source.close()


# ---------------------------------------------------------------- detection

def test_find_input_prefers_the_plain_file_and_ignores_partial_files(tmp_path, caplog):
    assert find_input(tmp_path) is None
    (tmp_path / "certs_polito.json.zst.part").write_bytes(b"x")
    assert find_input(tmp_path) is None
    (tmp_path / "certs_polito.json.gz").write_bytes(b"x")
    assert find_input(tmp_path) == tmp_path / "certs_polito.json.gz"
    (tmp_path / "certs_polito.json").write_bytes(b"x")
    with caplog.at_level(logging.INFO):
        assert find_input(tmp_path) == tmp_path / "certs_polito.json"
    assert "Using 'certs_polito.json' (also found: certs_polito.json.gz)" in caplog.text
    assert not [record for record in caplog.records if record.levelno >= logging.WARNING]
    assert INPUT_NAMES[0] == "certs_polito.json"


@pytest.mark.parametrize("file_format", ["gz", "bz2", "xz", "zst", "zst-indexed"])
def test_the_format_comes_from_the_first_bytes(plain_file, tmp_path, file_format):
    path = _compressed(plain_file, tmp_path, file_format)
    assert detect_format(path) == file_format
    misnamed = tmp_path / "certs_polito.json"
    misnamed.write_bytes(path.read_bytes())
    assert detect_format(misnamed) == file_format
    assert detect_format(plain_file) == "plain"


@pytest.mark.parametrize("cut", ["last byte", "seek table", "half"])
def test_a_truncated_line_indexed_file_is_refused(plain_file, tmp_path, cut):
    data = _compressed(plain_file, tmp_path, "zst-indexed").read_bytes()
    damaged = tmp_path / "res" / "certs_polito.json.zst"
    damaged.parent.mkdir()
    damaged.write_bytes({"last byte": data[:-1], "seek table": data[:-(4 + 1 + 4)], "half": data[:len(data) // 2]}[cut])
    message = f"The input file '{damaged}' is incomplete or damaged"
    with pytest.raises(InputFileError, match="incomplete or damaged"):
        detect_format(damaged)
    with pytest.raises(InputFileError, match="incomplete or damaged"):
        open_source(damaged)
    with pytest.raises(InputFileError) as error:
        _engine(tmp_path / "db", damaged)
    assert str(error.value).startswith(message)
    # --compress_input refuses it too and leaves it as it is
    assert not compress_input(damaged.parent)
    assert sorted(path.name for path in damaged.parent.iterdir()) == ["certs_polito.json.zst"]


def test_a_foreign_file_starting_with_a_skippable_frame_is_a_stream(plain_file, tmp_path):
    path = tmp_path / "certs_polito.json.zst"
    text = plain_file.read_bytes()
    path.write_bytes(struct.pack("<II", 0x184D2A50, 3) + b"abc" + FORMATS["zst"](text))
    assert detect_format(path) == "zst"
    assert b"".join(_block_texts(open_source(path), 4096, tmp_path)) == text


def test_an_empty_file_with_a_compressed_name_is_refused(tmp_path):
    for name in INPUT_NAMES[1:]:
        path = tmp_path / name
        path.write_bytes(b"")
        with pytest.raises(InputFileError, match="is empty"):
            detect_format(path)
    (tmp_path / "certs_polito.json").write_bytes(b"")
    assert detect_format(tmp_path / "certs_polito.json") == "plain"


def _foreign_zstd_frames(text, frame_size):
    """zstd frames of frame_size bytes of text each (not on line ends), with a skippable frame among them."""
    compressor = zstandard.ZstdCompressor(level=1, write_checksum=True)
    frames = [compressor.compress(text[start:start + frame_size]) for start in range(0, len(text), frame_size)]
    frames.insert(1, struct.pack("<II", 0x184D2A5A, 5) + b"12345")
    return frames


def test_a_zstd_stream_cut_anywhere_is_an_error_unless_cut_between_frames(plain_file, tmp_path):
    text = plain_file.read_bytes()
    frames = _foreign_zstd_frames(text, 3000)
    data = b"".join(frames)
    boundaries = {sum(len(frame) for frame in frames[:index]) for index in range(len(frames) + 1)}
    path = tmp_path / "certs_polito.json.zst"
    for cut in sorted({*boundaries, *range(4, len(data), 97)} - {0}):          # 1-3 bytes: no magic, plain text
        path.write_bytes(data[:cut])
        source = open_source(path)
        texts = _block_texts(source, 4096, tmp_path)
        assert text.startswith(b"".join(texts)), cut
        if cut in boundaries:
            assert source.error is None, cut
        else:
            assert isinstance(source.error, (InputFileError, zstandard.ZstdError)), cut


@pytest.mark.parametrize("file_format", ["gz", "zst", "zst frames"])
def test_a_truncated_stream_stores_the_lines_before_the_error(plain_file, tmp_path, monkeypatch, caplog, file_format):
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 4096)
    if file_format == "zst frames":
        data = b"".join(_foreign_zstd_frames(plain_file.read_bytes(), 3000))
    else:
        data = FORMATS[file_format](plain_file.read_bytes())
    path = tmp_path / f"certs_polito.json.{file_format.split()[0]}"
    path.write_bytes(data[:len(data) * 2 // 3])
    dump = _engine(tmp_path / "db", path)
    stored = len(dump["leaf.Occurrences"][1])
    # One small zstd frame is a single block: nothing of it can be decompressed before its end
    assert stored < 20 and (stored > 0 or file_format == "zst")
    assert f"Error reading the input file '{path}'" in caplog.text
    if file_format != "gz":
        assert "the file ends inside a zstd frame (it is truncated)" in caplog.text
    assert "The lines read before the error were stored." in caplog.text


@pytest.mark.parametrize("content", [b"\x28\xb5\x2f\xfd" + bytes(200), b"\x28\xb5\x2f\xfd" + b"not zstd" * 20])
def test_a_garbage_zstd_file_is_an_error(tmp_path, caplog, content):
    path = tmp_path / "certs_polito.json.zst"
    path.write_bytes(content)
    dump = _engine(tmp_path / "db", path)
    assert not dump["leaf.Occurrences"][1]
    assert f"Error reading the input file '{path}'" in caplog.text


def test_compress_input_refuses_a_truncated_foreign_zstd_file(plain_file, tmp_path, caplog):
    res = tmp_path / "res"
    res.mkdir()
    data = FORMATS["zst"](plain_file.read_bytes())
    (res / "certs_polito.json.zst").write_bytes(data[:len(data) // 2])
    assert not compress_input(res)
    assert "Error compressing the input file 'certs_polito.json.zst': the file ends inside a zstd frame" in caplog.text
    assert sorted(path.name for path in res.iterdir()) == ["certs_polito.json.zst"]
    assert (res / "certs_polito.json.zst").read_bytes() == data[:len(data) // 2]


@pytest.mark.parametrize("workers", [None, 2])
def test_a_damaged_frame_is_reported_as_a_damaged_file(plain_file, tmp_path, monkeypatch, workers):
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 4096)
    monkeypatch.setattr(ingestion, "MAX_WORKERS", workers)
    path = _compressed(plain_file, tmp_path, "zst-indexed")
    frames = input_file._frame_table(path).frames
    assert len(frames) > 3
    offset, compressed, _ = frames[len(frames) // 2]
    data = bytearray(path.read_bytes())
    data[offset + compressed // 2] ^= 0xFF
    path.write_bytes(bytes(data))
    assert detect_format(path) == "zst-indexed"
    with pytest.raises(InputFileError, match="The file is damaged, so the databases hold only part of it"):
        _engine(tmp_path / "db", path)
    assert multiprocessing.active_children() == []


# ---------------------------------------------------------------- line-indexed format

def test_compress_file_writes_line_aligned_frames_that_zstd_reads(plain_file, tmp_path):
    path = tmp_path / "certs_polito.json.zst"
    digest, length = compress_file(plain_file, path, chunk_size=4096, threads=2)
    assert length == plain_file.stat().st_size
    assert verify_file(path) == (digest, length)
    data = path.read_bytes()
    magic, size = struct.unpack_from("<II", data)
    assert magic == input_file.HEADER_MAGIC and data[8:8 + size] == input_file.HEADER_PAYLOAD
    assert struct.unpack_from("<I", data, len(data) - 4)[0] == input_file.SEEKABLE_FOOTER_MAGIC
    # Standard zstd decoders skip the header and the seek table
    assert zstandard.ZstdDecompressor().stream_reader(data, read_across_frames=True).read() == plain_file.read_bytes()

    source = open_source(path)
    assert source.parallel and source.uncompressed_size == length
    blocks = list(source.blocks(4096, str(tmp_path)))
    assert len(blocks) > 3 and all(block.kind == "frame" for block in blocks)
    texts = [read_block(block) for block in blocks]
    assert all(text.endswith(b"\n") for text in texts[:-1]) and not texts[-1].endswith(b"\n")
    assert sum(block.progress_bytes for block in blocks) == path.stat().st_size
    # The same blocks as the plain file
    assert texts == _block_texts(open_source(plain_file), 4096, tmp_path)


def test_compress_file_accepts_compressed_sources_and_odd_lines(tmp_path):
    long_line = b"x" * 10_000 + b"\n"
    text = b"a\n" + long_line + b"b\n" * 3000 + b"last"
    source = tmp_path / "source.json.xz"
    source.write_bytes(lzma.compress(text))
    target = tmp_path / "target.zst"
    compress_file(source, target, chunk_size=4096, threads=4)
    texts = _block_texts(open_source(target), 4096, tmp_path)
    assert b"".join(texts) == text and texts[0] == b"a\n" + long_line

    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")
    assert compress_file(empty, tmp_path / "empty.zst")[1] == 0
    assert detect_format(tmp_path / "empty.zst") == "zst-indexed"
    assert _block_texts(open_source(tmp_path / "empty.zst"), 4096, tmp_path) == []


@pytest.mark.parametrize("chunk_size", [1, 100, 4096, 1 << 20])
def test_stream_blocks_are_the_blocks_of_the_plain_file(plain_file, tmp_path, chunk_size):
    reader_text = plain_file.read_bytes()
    with open(plain_file, "rb") as raw:
        texts = [text for text, _ in iter_line_blocks(raw, raw, chunk_size, len(reader_text))]
    assert texts == _block_texts(open_source(plain_file), chunk_size, tmp_path)
    gz = _compressed(plain_file, tmp_path, "gz")
    assert _block_texts(open_source(gz), chunk_size, tmp_path) == texts


# ---------------------------------------------------------------- ingestion of every format

@pytest.fixture(scope="module")
def plain_reference(plain_file, tmp_path_factory):
    return _reference(tmp_path_factory.mktemp("reference") / "db", plain_file)


@pytest.mark.parametrize("file_format", ["gz", "bz2", "xz", "zst", "zst-indexed"])
@pytest.mark.parametrize("workers", [None, 2])
def test_every_format_stores_the_same_rows_and_logs(plain_file, plain_reference, tmp_path, monkeypatch, caplog,
                                                    file_format, workers):
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 4096)
    monkeypatch.setattr(ingestion, "MAX_WORKERS", workers)
    caplog.set_level(logging.WARNING)
    _engine(tmp_path / "plain", plain_file)
    plain_messages = [record.getMessage() for record in caplog.records]
    caplog.clear()
    path = _compressed(plain_file, tmp_path, file_format)
    progress = []
    assert _engine(tmp_path / "db", path, progress.append) == plain_reference
    assert [record.getMessage() for record in caplog.records] == plain_messages
    assert sum(progress) == path.stat().st_size
    assert not list((tmp_path / "db").glob("ingestion_staging_*")), "spool and staging files removed"
    assert multiprocessing.active_children() == []


def test_interrupt_stops_the_stream_reader(plain_file, tmp_path, monkeypatch):
    monkeypatch.setattr(ingestion, "CHUNK_SIZE", 2048)
    monkeypatch.setattr(ingestion, "MAX_WORKERS", 2)
    path = _compressed(plain_file, tmp_path, "bz2")
    stored = []

    def progress(size):
        stored.append(size)
        if len(stored) == 2:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        _engine(tmp_path / "db", path, progress)
    assert not [thread for thread in threading.enumerate() if thread.name == "input-reader"]
    assert multiprocessing.active_children() == []
    assert not list((tmp_path / "db").glob("ingestion_staging_*"))


# ---------------------------------------------------------------- --compress_input

class _Progress:
    def __init__(self, total):
        self.total, self.done = total, 0

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def update(self, size):
        self.done += size


def _res_dir(plain_file, tmp_path):
    res = tmp_path / "res"
    res.mkdir()
    (res / "certs_polito.json").write_bytes(plain_file.read_bytes())
    return res


def test_compress_input_keeps_the_original_unless_confirmed(plain_file, tmp_path, monkeypatch, caplog):
    res = _res_dir(plain_file, tmp_path)
    bars = []
    monkeypatch.setattr(input_file.sys.stdin, "isatty", lambda: False, raising=False)
    with caplog.at_level(logging.INFO):
        assert compress_input(res, lambda total: bars.append(_Progress(total)) or bars[-1])
    target = res / "certs_polito.json.zst"
    assert detect_format(target) == "zst-indexed" and (res / "certs_polito.json").exists()
    assert not (res / "certs_polito.json.zst.part").exists()
    assert bars[0].done == bars[0].total == plain_file.stat().st_size
    assert "The original file 'res/certs_polito.json' was kept" in caplog.text
    assert _block_texts(open_source(target), 1 << 20, tmp_path) == [plain_file.read_bytes()]

    # Already in the parallel format: nothing to do once the plain file is gone
    (res / "certs_polito.json").unlink()
    with caplog.at_level(logging.INFO):
        assert compress_input(res)
    assert "already in the compressed format" in caplog.text


def test_compress_input_deletes_the_original_when_confirmed(plain_file, tmp_path, monkeypatch):
    res = _res_dir(plain_file, tmp_path)
    questions = []
    monkeypatch.setattr(input_file.sys.stdin, "isatty", lambda: True, raising=False)
    assert compress_input(res, ask=lambda question: questions.append(question) or "y")
    assert questions == [f"Delete the original file 'res/certs_polito.json' "
                         f"({plain_file.stat().st_size / 2 ** 30:.1f} GiB) now? [y/N] "]
    assert not (res / "certs_polito.json").exists() and (res / "certs_polito.json.zst").exists()


def test_compress_input_converts_a_foreign_zstd_file_in_place(plain_file, tmp_path):
    res = tmp_path / "res"
    res.mkdir()
    (res / "certs_polito.json.zst").write_bytes(FORMATS["zst"](plain_file.read_bytes()))
    assert compress_input(res)
    assert detect_format(res / "certs_polito.json.zst") == "zst-indexed"
    assert b"".join(_block_texts(open_source(res / "certs_polito.json.zst"), 4096, tmp_path)) == plain_file.read_bytes()


def test_compress_input_checks_the_free_space(plain_file, tmp_path, monkeypatch, caplog):
    res = _res_dir(plain_file, tmp_path)
    monkeypatch.setattr(input_file.shutil, "disk_usage", lambda path: shutil._ntuple_diskusage(100, 90, 10))
    assert not compress_input(res)
    assert "Not enough free disk space to compress 'certs_polito.json'" in caplog.text
    assert sorted(path.name for path in res.iterdir()) == ["certs_polito.json"]
    (tmp_path / "empty").mkdir()
    assert not compress_input(tmp_path / "empty")
    assert "No input file to compress" in caplog.text


@pytest.mark.parametrize("error", [KeyboardInterrupt, OSError])
def test_interrupted_or_failed_compression_removes_the_partial_file(plain_file, tmp_path, monkeypatch, caplog, error):
    res = _res_dir(plain_file, tmp_path)
    original = compress_file

    def failing(src, dest, **kwargs):
        original(src, dest, **kwargs)
        raise error("stopped")

    monkeypatch.setattr(input_file, "compress_file", failing)
    if error is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            compress_input(res)
    else:
        assert not compress_input(res)
        assert "Error compressing the input file 'certs_polito.json': stopped" in caplog.text
    assert sorted(path.name for path in res.iterdir()) == ["certs_polito.json"]


def test_read_block_of_a_frame(tmp_path):
    path = tmp_path / "frames.zst"
    text = b"one\ntwo\n"
    source = tmp_path / "source.json"
    source.write_bytes(text)
    compress_file(source, path)
    (offset, compressed, _), = input_file._frame_table(path).frames
    assert read_block(BlockSpec(0, "frame", str(path), offset, compressed, compressed)) == text


def test_cli_compresses_the_input_and_analyses_the_compressed_file(project):  # noqa: F811
    res = project / "res"
    original = (res / "certs_polito.json").read_bytes()

    def run(*flags):
        return subprocess.run([sys.executable, "-m", "analysis.main", *flags], cwd=project / "src", capture_output=True,
                              text=True, timeout=600, stdin=subprocess.DEVNULL, env={**os.environ, "COLUMNS": "160"})

    result = run("--compress_input", "--leaf_analysis")
    assert result.returncode == 0, result.stderr
    log = (project / "src" / "app.log").read_text()
    assert "Input file compressed: 'certs_polito.json.zst'" in log and "was kept" in log
    leaf = project / "src" / "analysis" / "leaf" / "leaf_certificates.db"
    assert count(leaf, "Occurrences") == 8
    (res / "certs_polito.json").unlink()
    try:
        result = run("--leaf_analysis")
        assert result.returncode == 0, result.stderr
        assert count(leaf, "Occurrences") == 8 and count(leaf, "Errors") == 2
        # A truncated copy is refused before the database is recreated
        compressed = (res / "certs_polito.json.zst").read_bytes()
        (res / "certs_polito.json.zst").write_bytes(compressed[:len(compressed) // 2])
        result = run("--leaf_analysis")
        assert result.returncode == 1, result.stderr
        assert "is incomplete or damaged" in (project / "src" / "app.log").read_text()
        assert count(leaf, "Occurrences") == 8
    finally:
        (res / "certs_polito.json").write_bytes(original)
        (res / "certs_polito.json.zst").unlink()
