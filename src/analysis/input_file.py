"""The ZGrab2 input file: detection, compressed formats, blocks of whole lines and the --compress_input conversion.

Accepted names (res/): certs_polito.json, .json.zst, .json.gz, .json.xz, .json.bz2. The name only finds the file:
the format is chosen by its first bytes. The line-indexed zstd format written by --compress_input is read in parallel
(each worker decompresses its own frames); the other compressed formats are decompressed by a reader thread of the
main process into spool files of whole lines, which the workers then read as plain blocks.

Line-indexed zstd: [skippable frame 0x184D2A5D with HEADER_PAYLOAD] [zstd frames of whole lines, about CHUNK_SIZE of
text each, content size and checksum on] [seek table of the zstd seekable format: skippable frame 0x184D2A5E with
(compressed, decompressed) u32 pairs and the footer (frames u32, descriptor u8 = 0, 0x8F92EAB1 u32)]. 'zstd -d'
restores the original file.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import logging
import lzma
import os
import queue
import shutil
import signal
import struct
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, NamedTuple

try:
    import zstandard
except ImportError:          # reported by Database.connect() before any input is read
    zstandard = None

# Admin: Anuar Elio Magliari
# Politecnico di Torino

INPUT_NAMES = ("certs_polito.json", "certs_polito.json.zst", "certs_polito.json.gz", "certs_polito.json.xz",
               "certs_polito.json.bz2")
COMPRESSED_NAME = "certs_polito.json.zst"

# Bytes of text per block (and per frame of the line-indexed format)
CHUNK_SIZE = 8 << 20
# Bytes decompressed per read of a stream
READ_SIZE = 1 << 20
# Compressed bytes given to the zstd decompressor at a time (zstd streams)
ZSTD_INPUT_SIZE = 256 << 10
# Blocks a stream reader decompresses ahead of the ingestion (spool files waiting in the queue)
STREAM_QUEUE_BLOCKS = 2
# zstd level of the line-indexed format
COMPRESSION_LEVEL = 9
# Free space needed by --compress_input, as a fraction of the uncompressed size, and the expansion assumed for a
# compressed input of unknown uncompressed size
FREE_SPACE_FRACTION = 0.3
UNKNOWN_EXPANSION = 5

HEADER_MAGIC = 0x184D2A5D
HEADER_PAYLOAD = b"DigitalCertiAnalytics line-indexed zstd v1\n"
SEEK_TABLE_MAGIC = 0x184D2A5E
SEEKABLE_FOOTER_MAGIC = 0x8F92EAB1
_SKIPPABLE_FIRST, _SKIPPABLE_LAST = 0x184D2A50, 0x184D2A5F
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_MAGICS = ((b"\x1f\x8b", "gz"), (b"\xfd7zXZ\x00", "xz"), (b"BZh", "bz2"), (_ZSTD_MAGIC, "zst"))
_COMPRESSED_SUFFIXES = (".zst", ".gz", ".xz", ".bz2")
_FOOTER = struct.Struct("<IBI")      # frames, descriptor, magic
_FRAME_HEADER = struct.Struct("<II")  # skippable frame magic, payload size
_ENTRY = struct.Struct("<II")         # compressed, decompressed


class InputFileError(Exception):
    """The input file cannot be read (corrupt or truncated compressed data, read error)."""


class BlockSpec(NamedTuple):
    """A block of whole lines (picklable): 'file' = bytes [offset, offset + length) of path, 'frame' = the zstd frame
    stored there; progress_bytes = bytes of the input file it accounts for."""
    index: int
    kind: str
    path: str
    offset: int
    length: int
    progress_bytes: int


def find_input(res_dir: Path) -> Path | None:
    """The first existing INPUT_NAMES file (plain first: the fastest), None if there is none."""
    found = [res_dir / name for name in INPUT_NAMES if (res_dir / name).is_file()]
    if not found:
        return None
    if len(found) > 1:
        logging.info(f"Using '{found[0].name}' (also found: {', '.join(path.name for path in found[1:])})")
    return found[0]


def read_block(block: BlockSpec, file: BinaryIO | None = None) -> bytes:
    """Text of a block; file may be the already open block.path."""
    if file is None:
        with open(block.path, "rb") as opened:
            return read_block(block, opened)
    file.seek(block.offset)
    data = file.read(block.length)
    if block.kind == "frame":
        return zstandard.ZstdDecompressor().decompress(data)
    return data


# ---------------------------------------------------------------------------------------------- formats

def detect_format(path: Path) -> str:
    """'plain', 'zst-indexed' (line-indexed zstd), 'zst', 'gz', 'xz' or 'bz2', from the first bytes.

    InputFileError for a line-indexed file whose frames do not add up to its size (truncated or damaged: reading it
    as a stream could store part of it without notice) and for an empty file with a compressed name.
    """
    path = Path(path)
    with open(path, "rb") as file:
        head = file.read(_FRAME_HEADER.size + len(HEADER_PAYLOAD))
    if len(head) >= 4 and _SKIPPABLE_FIRST <= struct.unpack("<I", head[:4])[0] <= _SKIPPABLE_LAST:
        if _frame_table(path) is not None:
            return "zst-indexed"
        if _is_header(head):
            raise InputFileError(f"The input file '{path}' is incomplete or damaged (its frames do not match its "
                                 "index): copy it again, or compress the original file again with --compress_input.")
        return "zst"
    for magic, name in _MAGICS:
        if head.startswith(magic):
            return name
    if not head and path.name.endswith(_COMPRESSED_SUFFIXES):
        raise InputFileError(f"The input file '{path}' is empty: it is not a valid compressed file.")
    return "plain"


def _is_header(head: bytes) -> bool:
    """Whether the bytes start with the header frame of the line-indexed format."""
    if len(head) < _FRAME_HEADER.size + len(HEADER_PAYLOAD):
        return False
    magic, payload_size = _FRAME_HEADER.unpack_from(head)
    return magic == HEADER_MAGIC and payload_size == len(HEADER_PAYLOAD) and \
        head[_FRAME_HEADER.size:_FRAME_HEADER.size + len(HEADER_PAYLOAD)] == HEADER_PAYLOAD


@dataclass(frozen=True)
class _FrameTable:
    header_size: int
    table_size: int
    frames: tuple[tuple[int, int, int], ...]    # (offset, compressed, decompressed)

    @property
    def uncompressed_size(self) -> int:
        return sum(frame[2] for frame in self.frames)


def _frame_table(path: Path) -> _FrameTable | None:
    """Frames of a line-indexed zstd file; None unless header, frames and seek table add up to the file size."""
    size = os.path.getsize(path)
    with open(path, "rb") as file:
        head = file.read(_FRAME_HEADER.size + len(HEADER_PAYLOAD))
        if not _is_header(head) or size < len(head) + _FOOTER.size:
            return None
        file.seek(size - _FOOTER.size)
        count, descriptor, footer_magic = _FOOTER.unpack(file.read(_FOOTER.size))
        table_size = _FRAME_HEADER.size + count * _ENTRY.size + _FOOTER.size
        if footer_magic != SEEKABLE_FOOTER_MAGIC or descriptor != 0 or table_size > size - len(head):
            return None
        file.seek(size - table_size)
        table = file.read(table_size)
    magic, payload_size = _FRAME_HEADER.unpack_from(table)
    if magic != SEEK_TABLE_MAGIC or payload_size != table_size - _FRAME_HEADER.size:
        return None
    frames, offset = [], len(head)
    for compressed, decompressed in _ENTRY.iter_unpack(table[_FRAME_HEADER.size:-_FOOTER.size]):
        frames.append((offset, compressed, decompressed))
        offset += compressed
    if offset != size - table_size:
        return None
    return _FrameTable(len(head), table_size, tuple(frames))


def _open_stream(path: Path, file_format: str, raw: BinaryIO) -> BinaryIO:
    """Decompressed reader of a compressed file opened as raw."""
    if file_format == "gz":
        return gzip.GzipFile(fileobj=raw, mode="rb")
    if file_format == "bz2":
        return bz2.BZ2File(raw)
    if file_format == "xz":
        return lzma.LZMAFile(raw)
    if file_format in ("zst", "zst-indexed"):
        return _ZstdStream(raw)
    return raw


class _ZstdStream(io.RawIOBase):
    """Text of consecutive zstd frames (skippable frames included), one frame decompressor after another.

    zstandard's stream_reader ends quietly when the input stops inside a frame; here a truncated input (or one that
    is not zstd past its first bytes) raises InputFileError, after the text decompressed before it was returned.
    Closing the stream leaves raw open.
    """

    def __init__(self, raw: BinaryIO):
        super().__init__()
        self._raw = raw
        self._decompressor = zstandard.ZstdDecompressor()
        self._frame = None                  # decompressor of the frame being read, None between frames
        self._input = b""                   # compressed bytes after the end of the last frame, not decompressed yet
        self._output = memoryview(b"")      # decompressed bytes not returned yet
        self._ended = False

    def readable(self) -> bool:
        return True

    def readinto(self, view) -> int:
        while not self._output:
            if self._ended:
                return 0
            self._decompress_more()
        count = min(len(view), len(self._output))
        view[:count] = self._output[:count]
        self._output = self._output[count:]
        return count

    def _decompress_more(self) -> None:
        data = self._input or self._raw.read(ZSTD_INPUT_SIZE)
        self._input = b""
        if not data:
            self._ended = True
            if self._frame is not None:
                raise InputFileError("the file ends inside a zstd frame (it is truncated)")
            return
        if self._frame is None:
            self._frame = self._decompressor.decompressobj()
        try:
            self._output = memoryview(self._frame.decompress(data))
        except zstandard.ZstdError:
            self._ended = True
            raise
        if self._frame.eof:
            self._input = self._frame.unused_data
            self._frame = None


def _read_into(reader: BinaryIO, view: memoryview) -> int:
    """Read into the view (one decompression step when possible, so an error loses little); 0 at the end."""
    readinto = getattr(reader, "readinto1", None) or getattr(reader, "readinto", None)
    if readinto is not None:
        return readinto(view) or 0
    data = getattr(reader, "read1", reader.read)(len(view))
    view[:len(data)] = data
    return len(data)


def iter_line_blocks(reader: BinaryIO, raw: BinaryIO, chunk_size: int, total: int) -> Iterator[tuple[bytes, int]]:
    """(text, input bytes consumed) of consecutive blocks of whole lines of about chunk_size bytes.

    A block ends at the first newline at or after chunk_size - 1 bytes, as the blocks of a plain file; the last block
    accounts for the rest of the total input bytes. A read error (e.g. truncated compressed data) ends the blocks: the
    text decompressed before it is still produced, then the error is raised. The text is read into one buffer, reused
    for every block (growing a buffer per block would leave the memory allocator holding hundreds of MiB).
    """
    buffer = bytearray(max(chunk_size, 1) + READ_SIZE)
    filled = 0
    reported = 0
    eof = False
    failure: Exception | None = None
    search_from = chunk_size - 1        # bytes before it hold no block end
    while not eof or filled:
        newline = buffer.find(b"\n", search_from, filled) if filled >= chunk_size else -1
        if newline < 0 and not eof:
            search_from = max(chunk_size - 1, filled)
            if len(buffer) - filled < READ_SIZE:
                buffer.extend(bytes(len(buffer)))           # a line longer than the buffer
            try:
                count = _read_into(reader, memoryview(buffer)[filled:filled + READ_SIZE])
            except Exception as e:
                failure, count = e, 0
            eof = count == 0
            filled += count
            continue
        search_from = chunk_size - 1
        end = filled if newline < 0 else newline + 1
        data = bytes(memoryview(buffer)[:end])
        buffer[:filled - end] = buffer[end:filled]
        filled -= end
        consumed = total if eof and not filled else min(raw.tell(), total)
        yield data, max(0, consumed - reported)
        reported = max(reported, consumed)
    if failure is not None:
        raise failure


# ---------------------------------------------------------------------------------------------- sources

class InputSource:
    """The input file as blocks of whole lines."""

    def __init__(self, path: Path, file_format: str):
        self.path = Path(path)
        self.format = file_format
        self.size = os.path.getsize(path)           # bytes on disk: the progress total
        self.parallel = True                        # every block can be read by a worker on its own
        self.uncompressed_size: int | None = self.size
        self.error: BaseException | None = None     # read error that ended the blocks early

    def blocks(self, chunk_size: int, staging_dir: str) -> Iterator[BlockSpec]:
        """Plain file: (offset, length) of consecutive blocks of whole lines."""
        with open(self.path, "rb") as reader:
            start, index = 0, 0
            while start < self.size:
                reader.seek(min(start + chunk_size, self.size) - 1)
                reader.readline()
                end = min(max(reader.tell(), start + 1), self.size)
                yield BlockSpec(index, "file", str(self.path), start, end - start, end - start)
                start, index = end, index + 1

    def read(self, block: BlockSpec) -> bytes:
        """Text of a block (main process: fallbacks and single-row path)."""
        try:
            return read_block(block)
        except Exception as e:
            raise InputFileError(f"Error reading the input file '{self.path}': {e}") from e

    def release(self, block: BlockSpec) -> None:
        """The block is stored: its spool file, if any, can go."""

    def ended_in_first_block(self) -> bool:
        """True when the whole input fits in the first block (known once it was produced)."""
        return self.size <= CHUNK_SIZE

    def close(self) -> None:
        """Stop reading and release the files."""


class _FrameSource(InputSource):
    """Line-indexed zstd: one block per frame, decompressed by the worker that processes it."""

    def __init__(self, path: Path, table: _FrameTable):
        super().__init__(path, "zst-indexed")
        self._table = table
        self.uncompressed_size = table.uncompressed_size

    def blocks(self, chunk_size: int, staging_dir: str) -> Iterator[BlockSpec]:
        frames = self._table.frames
        for index, (offset, compressed, _) in enumerate(frames):
            progress = compressed
            if index == 0:
                progress += self._table.header_size
            if index == len(frames) - 1:
                progress += self._table.table_size
            yield BlockSpec(index, "frame", str(self.path), offset, compressed, progress)

    def ended_in_first_block(self) -> bool:
        return len(self._table.frames) <= 1

    def read(self, block: BlockSpec) -> bytes:
        try:
            return read_block(block)
        except Exception as e:
            raise InputFileError(f"Error reading the input file '{self.path}': {e}. The file is damaged, so the "
                                 "databases hold only part of it: copy the file again, or compress the original "
                                 "file again with --compress_input, then run the analysis again.") from e


_END = object()


class _StreamSource(InputSource):
    """gzip, bzip2, xz or zstd stream: a reader thread decompresses blocks of whole lines into spool files."""

    def __init__(self, path: Path, file_format: str):
        super().__init__(path, file_format)
        self.parallel = False
        self.uncompressed_size = None
        self._stop = threading.Event()
        self._queue: queue.Queue = queue.Queue(maxsize=STREAM_QUEUE_BLOCKS)
        self._thread: threading.Thread | None = None
        self._spools: set[str] = set()
        self._first_is_last = True

    def blocks(self, chunk_size: int, staging_dir: str) -> Iterator[BlockSpec]:
        self._thread = threading.Thread(target=self._read_loop, args=(chunk_size, staging_dir), name="input-reader",
                                        daemon=True)
        self._thread.start()
        while True:
            try:
                # A timeout keeps Ctrl+C responsive where a blocking get() is not interruptible (Windows)
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if item is _END:
                return
            yield item

    def _read_loop(self, chunk_size: int, staging_dir: str) -> None:
        if hasattr(signal, "pthread_sigmask"):
            # Ctrl+C goes to the main thread, which stops this one
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        try:
            with open(self.path, "rb") as raw, _open_stream(self.path, self.format, raw) as reader:
                for index, (data, consumed) in enumerate(iter_line_blocks(reader, raw, chunk_size, self.size)):
                    if self._stop.is_set():
                        return
                    spool = os.path.join(staging_dir, f"input_{index}.json")
                    with open(spool, "wb") as target:
                        target.write(data)
                    self._spools.add(spool)
                    if index == 0:
                        self._first_is_last = len(data) < chunk_size
                    if not self._put(BlockSpec(index, "file", spool, 0, len(data), consumed)):
                        return
        except Exception as e:
            # The blocks read so far are still stored; the ingestion logs the error at the end
            self.error = e
        self._put(_END)

    def _put(self, item: object) -> bool:
        while not self._stop.is_set():
            try:
                self._queue.put(item, timeout=0.2)
                return True
            except queue.Full:
                continue
        return False

    def release(self, block: BlockSpec) -> None:
        if block.path in self._spools:
            self._spools.discard(block.path)
            _remove(block.path)

    def ended_in_first_block(self) -> bool:
        return self._first_is_last

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
            self._thread = None
        for spool in list(self._spools):
            _remove(spool)
        self._spools.clear()


def open_source(path: Path) -> InputSource:
    """The source of any accepted input file (format from the first bytes)."""
    path = Path(path)
    file_format = detect_format(path)
    if file_format == "plain":
        return InputSource(path, file_format)
    if zstandard is None and file_format in ("zst", "zst-indexed"):
        raise InputFileError("The Python package 'zstandard' is not installed: run the installer again.")
    if file_format == "zst-indexed":
        return _FrameSource(path, _frame_table(path))
    return _StreamSource(path, file_format)


def _remove(path: str | os.PathLike) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------------------------- compression

class _ThreadCompressor:
    """One ZstdCompressor per thread (they are not thread-safe)."""

    def __init__(self) -> None:
        self._local = threading.local()

    def __call__(self, data: bytes) -> tuple[bytes, bytes]:
        compressor = getattr(self._local, "compressor", None)
        if compressor is None:
            compressor = self._local.compressor = zstandard.ZstdCompressor(
                level=COMPRESSION_LEVEL, write_checksum=True, write_content_size=True)
        return compressor.compress(data), hashlib.blake2b(data).digest()


def _skippable_frame(magic: int, payload: bytes) -> bytes:
    return _FRAME_HEADER.pack(magic, len(payload)) + payload


def _seek_table(frames: list[tuple[int, int]]) -> bytes:
    entries = b"".join(_ENTRY.pack(compressed, decompressed) for compressed, decompressed in frames)
    return _skippable_frame(SEEK_TABLE_MAGIC, entries + _FOOTER.pack(len(frames), 0, SEEKABLE_FOOTER_MAGIC))


def _combined_digest(frame_digests: list[bytes]) -> bytes:
    return hashlib.blake2b(b"".join(frame_digests)).digest()


def compress_file(src: Path, dest: Path, chunk_size: int = CHUNK_SIZE, threads: int | None = None,
                  on_progress: Callable[[int], None] | None = None) -> tuple[bytes, int]:
    """Write src (plain or any accepted compressed format) to dest in the line-indexed zstd format.

    Returns the BLAKE2b digest of the per-frame BLAKE2b digests of the text and its length, as verify_file() does.
    """
    src, dest = Path(src), Path(dest)
    file_format = detect_format(src)
    threads = threads or os.cpu_count() or 1
    compress = _ThreadCompressor()
    digests: list[bytes] = []
    frames: list[tuple[int, int]] = []
    length = 0
    with open(src, "rb") as raw, _open_stream(src, file_format, raw) as reader, open(dest, "wb") as target, \
            ThreadPoolExecutor(threads, thread_name_prefix="compress") as executor:
        target.write(_skippable_frame(HEADER_MAGIC, HEADER_PAYLOAD))
        pending = []

        def write_next() -> None:
            future, size, consumed = pending.pop(0)
            compressed, digest = future.result()
            target.write(compressed)
            frames.append((len(compressed), size))
            digests.append(digest)
            if on_progress is not None:
                on_progress(consumed)

        try:
            for data, consumed in iter_line_blocks(reader, raw, chunk_size, os.path.getsize(src)):
                pending.append((executor.submit(compress, data), len(data), consumed))
                length += len(data)
                if len(pending) >= 2 * threads:
                    write_next()
            while pending:
                write_next()
        except BaseException:
            for future, _, _ in pending:
                future.cancel()
            raise
        target.write(_seek_table(frames))
    return _combined_digest(digests), length


def verify_file(path: Path, threads: int | None = None) -> tuple[bytes, int] | None:
    """Digest and length of the text of a line-indexed zstd file (as compress_file), None if it is not one."""
    table = _frame_table(Path(path))
    if table is None:
        return None
    threads = threads or os.cpu_count() or 1
    local = threading.local()
    files: list[BinaryIO] = []

    def check(frame: tuple[int, int, int]) -> tuple[bytes, int]:
        file = getattr(local, "file", None)
        if file is None:
            file = local.file = open(path, "rb")
            files.append(file)
        offset, compressed, decompressed = frame
        data = read_block(BlockSpec(0, "frame", str(path), offset, compressed, 0), file)
        if len(data) != decompressed:
            raise InputFileError(f"frame at offset {offset}: {len(data)} bytes instead of {decompressed}")
        return hashlib.blake2b(data).digest(), len(data)

    try:
        with ThreadPoolExecutor(threads, thread_name_prefix="verify") as executor:
            results = list(executor.map(check, table.frames))
    finally:
        for file in files:
            file.close()
    return _combined_digest([digest for digest, _ in results]), sum(size for _, size in results)


def _gib(size: float) -> str:
    return f"{size / 2 ** 30:.1f} GiB"


def _display(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def compress_input(res_dir: Path, progress: Callable[[int], object] | None = None,
                   ask: Callable[[str], str] = input) -> bool:
    """--compress_input: convert the input file into res/certs_polito.json.zst (line-indexed zstd), safely.

    The new file is written as a '.part', verified frame by frame, then renamed; the original is deleted only if the
    user confirms on a terminal. progress(total) returns a context manager with update(bytes). False on error.
    """
    source = find_input(res_dir)
    if source is None:
        logging.error(f"No input file to compress in '{res_dir}': expected one of {', '.join(INPUT_NAMES)}.")
        return False
    file_format = _source_format(source)
    if file_format is None:
        return False
    if file_format == "zst-indexed":
        logging.info(f"The input file '{source.name}' is already in the compressed format read in parallel.")
        return True
    size = source.stat().st_size
    needed = FREE_SPACE_FRACTION * (size if file_format == "plain" else size * UNKNOWN_EXPANSION)
    free = shutil.disk_usage(res_dir).free
    if free < needed:
        logging.error(f"Not enough free disk space to compress '{source.name}': about {_gib(needed)} are needed, "
                      f"{_gib(free)} are free.")
        return False

    dest = res_dir / COMPRESSED_NAME
    part = dest.with_name(dest.name + ".part")
    logging.info(f"Compressing '{source.name}' ({_gib(size)}) into '{dest.name}'...")
    try:
        digest, length = _compress_with_progress(source, part, size, progress)
        logging.info("Verifying the compressed file...")
        if verify_file(part) != (digest, length):
            raise InputFileError("the compressed file does not match the original")
        os.replace(part, dest)
    except Exception as e:
        _remove(part)
        logging.error(f"Error compressing the input file '{source.name}': {e}")
        return False
    except BaseException:
        _remove(part)
        raise
    compressed = dest.stat().st_size
    logging.info(f"Input file compressed: '{dest.name}' ({_gib(compressed)}, {compressed / max(size, 1):.0%} of "
                 f"'{source.name}'), verified.")
    if source != dest:
        _offer_deletion(source, res_dir.parent, ask)
    return True


def _source_format(source: Path) -> str | None:
    """detect_format(), None (logged) for a file that cannot be read."""
    try:
        return detect_format(source)
    except InputFileError as e:
        logging.error(str(e))
        return None


def _compress_with_progress(source: Path, part: Path, size: int, progress) -> tuple[bytes, int]:
    if progress is None:
        return compress_file(source, part)
    with progress(size) as bar:
        return compress_file(source, part, on_progress=bar.update)


def _offer_deletion(source: Path, root: Path, ask: Callable[[str], str]) -> None:
    name = _display(source, root)
    answer = ""
    if sys.stdin is not None and sys.stdin.isatty():
        try:
            answer = ask(f"Delete the original file '{name}' ({_gib(source.stat().st_size)}) now? [y/N] ")
        except EOFError:
            answer = ""
    if answer.strip().lower() in ("y", "yes"):
        source.unlink()
        logging.info(f"Original file '{name}' deleted.")
    else:
        logging.info(f"The original file '{name}' was kept: it is no longer needed and can be deleted.")
