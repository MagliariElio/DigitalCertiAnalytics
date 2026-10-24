from __future__ import annotations

import contextlib
import functools
import json
import logging
import multiprocessing
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
from collections import deque
from concurrent.futures import Executor, Future, ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path
from typing import Iterator, NamedTuple

from bean.certificate import Certificate
from dao.certificate_dao import CertificateDAO
from db.raw_codec import RawCodec
from db.zlint_store import LintResult, ZlintStore, body_digest, encode_body, timestamp
from utils.process_utils import init_worker_process, sigint_blocked, stop_requested, stop_signals_as_ctrl_c
from utils.utils import progress_bar

# Admin: Anuar Elio Magliari
# Politecnico di Torino

PROJECT_DIR = Path(__file__).resolve().parents[2]
_EXE_SUFFIX = ".exe" if os.name == "nt" else ""
# Path of the ZLint executable to use, checked before the others
ZLINT_ENV_VARIABLE = "DCA_ZLINT_PATH"
# Where the installer puts ZLint, then where earlier versions of the README had it built
ZLINT_LOCATIONS = (PROJECT_DIR / ".tools" / "zlint" / f"zlint{_EXE_SUFFIX}",
                   PROJECT_DIR / "zlint" / "v3" / f"zlint{_EXE_SUFFIX}")
# When set, this executable is used and nothing else is looked for (see find_zlint)
ZLINT_PATH: Path | None = None

# On Windows a process pool has at most 61 workers
_WINDOWS_MAX_WORKERS = 61
ZLINT_WORKERS = min(os.cpu_count() or 4, _WINDOWS_MAX_WORKERS) if os.name == "nt" else os.cpu_count() or 4
ZLINT_TIMEOUT = 60      # Seconds per zlint process (a single certificate or a chunk)
VERSION_TIMEOUT = 10    # Seconds for `zlint -version`, recorded with the results
BATCH_SIZE = 1000       # Certificates read from the DB and saved per transaction
ZLINT_CHUNK_SIZE = 100  # Certificates linted by one zlint process, so its start-up is paid once per chunk

# From this many certificates the chunks are linted in worker processes instead of threads: threads of one process
# contend for the GIL (writing the PEM files, parsing zlint's JSON), while starting the processes takes ~0.5-1 s
ZLINT_PROCESSES_FROM = 10000

# Temporary directory of a run, named after its main process so that a later run can remove it if that process was killed.
# The '-' is never in the random part of a name, so the directories of earlier versions ('zlint_<random>') never match
_RUN_DIRECTORY_PREFIX = "zlint_{pid}-"
_RUN_DIRECTORY_NAME = re.compile(r"zlint_(\d+)-[a-z0-9_]+")

# In a worker process, held while it writes its PEM files (see _remove_worker_files)
_pem_files_lock: threading.Lock | None = None


class _Settings(NamedTuple):
    """Settings of a lint worker, passed explicitly since worker processes do not see changes to this module."""
    zlint_path: str
    timeout: float
    directory: str  # Temporary directory of the run


class _ZLintError(Exception):
    """ZLint failure (non-zero exit or invalid output); the message is saved with the results."""


def _run_zlint(raw: str | None, settings: _Settings) -> object:
    """Run ZLint with the PEM certificate on stdin (no temp file) and return the parsed JSON."""
    result = subprocess.run([settings.zlint_path], input=Certificate.to_pem(raw).encode(), capture_output=True,
                            timeout=settings.timeout)
    if result.returncode != 0:
        raise _ZLintError(f"Error running ZLint: {result.stderr.decode(errors='replace')}")
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise _ZLintError("Error decoding the ZLint JSON output.") from None


def _lint_result(raw_id: int, zlint_result: object) -> LintResult:
    """The stored form of a ZLint output, computed in the worker so that the main process only saves it."""
    body = encode_body(zlint_result)
    return LintResult(raw_id, body_digest(body), body, None, None)


def _lint_certificate(row: tuple[int, object], settings: _Settings) -> LintResult:
    """Lint a certificate, a (raw_id, raw) pair, with its own zlint process."""
    try:
        zlint_result = _run_zlint(row[1], settings)
    except _ZLintError as e:
        error_message = str(e)
    except Exception as e:
        # A NULL raw fails here, before zlint is started
        error_message = f"Unexpected error during processing: {e}"
    else:
        return _lint_result(row[0], zlint_result)
    return LintResult(row[0], None, None, error_message, timestamp())


def _lint_files(paths: list[str], settings: _Settings) -> list[object] | None:
    """Lint the files with one zlint process and return the parsed results of the leading files it completed.

    zlint prints one JSON line per file, in order, and exits at the first file it cannot lint.
    None means that zlint could not be started or its output cannot be matched to the files.
    """
    try:
        stdout = subprocess.run([settings.zlint_path, *paths], capture_output=True, timeout=settings.timeout).stdout
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout or b""
    except Exception:
        return None

    # The last element is empty or a line cut short
    lines = stdout.split(b"\n")[:-1]
    if len(lines) > len(paths):
        return None
    results = []
    for line in lines:
        try:
            results.append(json.loads(line))
        except ValueError:
            break
    return results


def _write_pem_files(rows: list, settings: _Settings) -> list[tuple[int, str]]:
    """Write each certificate with a raw to its own PEM file; return (row index, path) pairs.

    Each worker overwrites the same file names chunk after chunk: creating and deleting
    a file per certificate costs about as much as linting it.
    """
    directory = os.path.join(settings.directory, f"{os.getpid()}-{threading.get_ident()}")
    files = []
    with _pem_files_lock or contextlib.nullcontext():
        os.makedirs(directory, exist_ok=True)
        for index, row in enumerate(rows):
            if row[1] is not None:
                path = os.path.join(directory, f"{index}.pem")
                with open(path, "wb") as file:
                    file.write(Certificate.to_pem(row[1]).encode())
                files.append((index, path))
    return files


def _lint_chunk(rows: list[tuple[int, object]], settings: _Settings) -> list[LintResult]:
    """Lint a chunk of (raw_id, raw) certificates with as few zlint processes as possible; results keep the order.

    When a process stops early, the certificates it printed keep their results, the one it stopped at is linted
    alone (giving exactly the single-certificate result) and the rest are retried together.
    """
    # A NULL raw gets its error without starting zlint
    results = [None if row[1] is not None else _lint_certificate(row, settings) for row in rows]
    try:
        queue = _write_pem_files(rows, settings)
    except OSError:
        # e.g. no space left for the temporary files: one zlint process per certificate, as before
        return [result or _lint_certificate(row, settings) for row, result in zip(rows, results)]

    together = True
    while queue:
        outputs = _lint_files([path for _, path in queue], settings) if together and len(queue) > 1 else []
        if outputs is None:
            together, outputs = False, []

        for (index, _), zlint_result in zip(queue, outputs):
            results[index] = _lint_result(rows[index][0], zlint_result)
        if len(outputs) < len(queue):
            index = queue[len(outputs)][0]
            results[index] = _lint_certificate(rows[index], settings)
        queue = queue[len(outputs) + 1:]
    return results


def _remove_worker_files(directory: str) -> None:
    """Remove the PEM files of a worker process whose main process was killed, and the run directory once empty."""
    # Wait for the files being written, and keep the lock so that the worker writes no more before it exits
    if _pem_files_lock is not None:
        _pem_files_lock.acquire(timeout=ZLINT_TIMEOUT)
    # Worker processes lint their chunks in their main thread
    shutil.rmtree(os.path.join(directory, f"{os.getpid()}-{threading.main_thread().ident}"), ignore_errors=True)
    try:
        # Succeeds only for the last worker, when no other worker's files are left
        os.rmdir(directory)
    except OSError:
        pass


def _init_worker(parent_pid: int, directory: str) -> None:
    global _pem_files_lock
    _pem_files_lock = threading.Lock()
    init_worker_process(parent_pid, functools.partial(_remove_worker_files, directory))
    if hasattr(signal, "SIGHUP"):
        # Closing the terminal window reaches the workers too: like Ctrl+C, it is left to the main process (see
        # run_zlint_check), which lets them finish their current chunk
        signal.signal(signal.SIGHUP, signal.SIG_IGN)


def _start_executor(total: int, directory: str) -> Executor:
    if total >= ZLINT_PROCESSES_FROM:
        executor = None
        try:
            # Workers leave Ctrl+C to the main process, which lets them finish their current chunk, and exit by
            # themselves, removing their files, if the main process is killed
            with sigint_blocked():
                # spawn on every platform: forking a process that runs threads (progress bar, executors) is unsafe
                executor = ProcessPoolExecutor(max_workers=ZLINT_WORKERS, mp_context=multiprocessing.get_context("spawn"),
                                               initializer=_init_worker, initargs=(os.getpid(), directory))
                # Start a worker now: if processes cannot be started, the chunks are linted in threads
                started = executor.submit(os.getpid)
            started.result()
            return executor
        except Exception as e:
            logging.warning(f"Could not start the ZLint worker processes ({e}): linting with threads instead.")
            if executor is not None:
                executor.shutdown(wait=False, cancel_futures=True)
    return ThreadPoolExecutor(max_workers=ZLINT_WORKERS)


def _submit(executor: Executor, rows: list, settings: _Settings) -> Future:
    if isinstance(executor, ThreadPoolExecutor):
        return executor.submit(_lint_chunk, rows, settings)
    # submit() starts the worker processes on demand: Ctrl+C must not interrupt their start-up
    with sigint_blocked():
        return executor.submit(_lint_chunk, rows, settings)


def _save_results(store: ZlintStore, results: list[LintResult]) -> None:
    try:
        store.save(results)
    except Exception as e:
        logging.error(f"Error saving the ZLint results to the database: {e}")


def _chunks(store: ZlintStore, codec: RawCodec) -> Iterator[tuple[list, bool]]:
    """Yield chunks of (raw_id, raw) certificates, flagging the last chunk of each DB batch."""
    for batch in store.iter_units(BATCH_SIZE):
        rows = [(raw_id, codec.decode(der_zstd, raw)) for raw_id, der_zstd, raw in batch]
        for start in range(0, len(rows), ZLINT_CHUNK_SIZE):
            yield rows[start:start + ZLINT_CHUNK_SIZE], start + ZLINT_CHUNK_SIZE >= len(rows)


def _collect(results: list[LintResult], chunk_results: list[LintResult]) -> None:
    results.extend(chunk_results)


def _log_errors(store: ZlintStore) -> None:
    """Log the error of every certificate occurrence that could not be linted (each distinct raw is linted once)."""
    try:
        for certificate_id, error_message in store.error_occurrences():
            logging.error(f"Error processing certificate ID {certificate_id}: {error_message}")
    except Exception as e:
        logging.error(f"Error reading the ZLint errors from the database: {e}")


def _lint_certificates(dao: CertificateDAO, store: ZlintStore, directory: str, zlint_path: str) -> None:
    """Lint each distinct certificate in parallel chunks, saving the results one DB batch at a time.

    On interruption (Ctrl+C) or error, the results already collected are saved too, and the errors of the saved
    results are logged once per certificate occurrence.
    """
    total = store.prepare_units()
    logging.info(f"{total} distinct certificates to check ({dao.get_certificates_count()} in the database).")
    settings = _Settings(zlint_path, ZLINT_TIMEOUT, directory)
    executor = _start_executor(total, directory)
    chunks = _chunks(store, RawCodec.for_connection(dao.connection))
    in_flight: deque[tuple[Future, bool]] = deque()
    results: list[LintResult] = []
    try:
        with progress_bar(total, " 🔍  [magenta bold]Processing Certificates[/magenta bold]", "magenta") as pbar:
            while True:
                # Two chunks per worker keep every process busy while the oldest chunk is awaited
                while len(in_flight) < 2 * ZLINT_WORKERS and (item := next(chunks, None)) is not None:
                    in_flight.append((_submit(executor, item[0], settings), item[1]))
                if not in_flight:
                    break

                # Chunks are consumed in submission order, so results are saved by raw_id
                future, batch_end = in_flight.popleft()
                chunk_results = future.result()
                _collect(results, chunk_results)
                pbar.update(len(chunk_results))
                if batch_end:
                    # A Ctrl+C waits for the end of the save, so that the batch is neither lost nor, taken out first,
                    # saved twice
                    batch, results = results, []
                    with sigint_blocked():
                        _save_results(store, batch)
    finally:
        # On interruption, drop the queued chunks and wait for the running ones (a chunk takes a fraction of a second).
        # A second Ctrl+C is deferred to the end of the wait: interrupting it hangs the interpreter at exit on Python < 3.13
        with sigint_blocked():
            executor.shutdown(wait=True, cancel_futures=True)
            # The chunks consumed since the last save; the running ones may hold errors of zlint processes stopped by
            # the Ctrl+C
            _save_results(store, results)
            store.drop_units()
        _log_errors(store)


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except (OSError, OverflowError):
        # e.g. a process of another user
        return True
    return True


def _remove_killed_runs_directories() -> None:
    """Remove the temporary directories left by runs whose main process was killed (in thread mode no worker process
    survives it to remove them).

    Only on POSIX, where signal 0 checks that a process exists: on Windows os.kill would stop it.
    """
    if os.name != "posix":
        return
    try:
        entries = list(os.scandir(tempfile.gettempdir()))
    except OSError:
        return
    for entry in entries:
        match = _RUN_DIRECTORY_NAME.fullmatch(entry.name)
        try:
            killed = (match is not None and entry.is_dir(follow_symlinks=False)
                      and entry.stat(follow_symlinks=False).st_uid == os.getuid() and not _process_exists(int(match[1])))
        except OSError:
            continue
        if killed:
            shutil.rmtree(entry.path, ignore_errors=True)


def _is_executable(path: Path) -> bool:
    # On Windows every existing file passes os.X_OK
    return path.is_file() and os.access(path, os.X_OK)


def find_zlint() -> Path | None:
    """The ZLint executable, None if there is none.

    ZLINT_PATH when set; otherwise the first executable among DCA_ZLINT_PATH, .tools/zlint/zlint (where the installer
    puts it), zlint/v3/zlint (where earlier versions of the README had it built) and the PATH. On Windows the files are
    zlint.exe.
    """
    if ZLINT_PATH is not None:
        return Path(ZLINT_PATH)
    configured = os.environ.get(ZLINT_ENV_VARIABLE)
    if configured:
        if _is_executable(Path(configured)):
            return Path(configured)
        logging.warning(f"{ZLINT_ENV_VARIABLE} is '{configured}', which is not an executable file: looking for ZLint in "
                        "the project folder and on the PATH instead.")
    for location in ZLINT_LOCATIONS:
        if _is_executable(location):
            return location
    found = shutil.which("zlint")
    return None if found is None else Path(found)


def _zlint_executable() -> str | None:
    """Path of the ZLint executable to run; None, after logging what to do, if it is missing."""
    zlint = find_zlint()
    if zlint is not None and _is_executable(zlint):
        return os.fspath(zlint)
    problem = "ZLint is not installed" if zlint is None else f"The ZLint executable '{zlint}' is missing or cannot run"
    logging.error(f"{problem}, so the certificates cannot be checked with ZLint. Run the installer again (install.sh "
                  "on macOS and Linux, install.bat on Windows): it installs ZLint in the project folder.")
    return None


def _zlint_version(zlint_path: str) -> str | None:
    """The version line printed by `zlint -version`, recorded with the results; None if it prints none."""
    try:
        result = subprocess.run([zlint_path, "-version"], capture_output=True, timeout=VERSION_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return None
    lines = result.stdout.decode(errors="replace").strip().splitlines()
    return lines[0].strip() if result.returncode == 0 and lines else None


def run_zlint_check(dao: CertificateDAO) -> None:
    """Run ZLint on the database certificates and save the results in the same database (see db.zlint_store).

    Each distinct certificate is linted once; its result belongs to all its occurrences. Closing the terminal window
    (or SIGTERM) meanwhile works like Ctrl+C: the results collected are saved and the temporary files removed.
    """
    zlint_path = _zlint_executable()
    if zlint_path is None:
        return
    with stop_signals_as_ctrl_c():
        _check_and_save(dao, zlint_path)


def _record_end(store: ZlintStore, state: str) -> None:
    if not store.started:
        return
    with sigint_blocked():
        try:
            store.finish(state)
        except Exception as e:
            logging.error(f"Error saving the state of the ZLint run: {e}")


def _check_and_save(dao: CertificateDAO, zlint_path: str) -> None:
    store = ZlintStore(dao.connection)
    state = "failed"
    try:
        _remove_killed_runs_directories()
        store.start(_zlint_version(zlint_path))
        logging.info(f"Previous ZLint results removed from the {dao.certificate_type.value} database.")
        with tempfile.TemporaryDirectory(prefix=_RUN_DIRECTORY_PREFIX.format(pid=os.getpid()),
                                         ignore_cleanup_errors=True) as directory:
            _lint_certificates(dao, store, directory, zlint_path)
        state = "finished"
    except Exception as e:
        if stop_requested():
            # Raised while stopping after the terminal window was closed (e.g. a write to it): still a stop
            state = "interrupted"
            logging.info(f"Error while stopping the ZLint check: {e}")
            raise KeyboardInterrupt from e
        logging.error(f"Error running run_zlint_check: {e}")
    except KeyboardInterrupt:
        state = "interrupted"
        logging.info("Interrupt signal (SIGINT) received: shutting down...")
        raise   # Stop the app instead of moving on to the next analyses
    finally:
        _record_end(store, state)
