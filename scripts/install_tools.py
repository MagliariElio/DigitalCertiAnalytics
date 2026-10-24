#!/usr/bin/env python3
"""Install and check the external tools of DigitalCertiAnalytics.

install.sh (macOS, Linux) and install.ps1 (Windows) set up uv, Python 3.12 and the project's .venv, then run this
script with the .venv Python. It installs, inside the project folder only:

- zlint:     ZLint, the exact commit the analysis uses (.tools/zlint): the ready-made program of the project's
             GitHub release when its SHA-256 equals the pinned reproducible build, otherwise built from source with Go;
- log_list:  the Certificate Transparency log list res/log_list.json, only when the file is missing or damaged
             (a valid list is kept, also with --force, unless log_list is named with --only).

Every download is pinned to an exact version and verified with SHA-256 (the log list with Google's signature).
Afterwards it removes from the project's own Python what the program never uses, and the leftovers of older
versions (the bundled MongoDB server, which is no longer needed). Running the script again is safe: what is
installed is skipped and what is broken is repaired.

    install_tools.py                  install everything
    install_tools.py --check          show the status of every component
    install_tools.py --only zlint     install only ZLint

It uses the Python standard library only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import importlib.metadata
import json
import os
import platform
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import traceback
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

# Admin: Anuar Elio Magliari
# Politecnico di Torino

PROJECT_DIR = Path(__file__).resolve().parents[1]
REQUIRED_PYTHON = (3, 12)

# ---------------------------------------------------------------------------------------------------------------------
# Pinned versions and checksums
# ---------------------------------------------------------------------------------------------------------------------

# ZLint has no official release for the commit the analysis uses. The project's GitHub workflow zlint-binaries.yml
# builds it for every platform below, reproducibly, and publishes the programs in the release ZLINT_RELEASE_TAG; a
# program is used only when its SHA-256 equals ZLINT_BUILD_SHA256. Otherwise it is built here with Go, then removed.
ZLINT_COMMIT = "989baefda32f5d50969ceafacc6d54215e28cc7b"
ZLINT_VERSION = "v3.6.5-0.20241104164204-989baefda32f"  # Go pseudo-version of the commit, printed by `zlint -version`
ZLINT_PACKAGE = "github.com/zmap/zlint/v3/cmd/zlint"
ZLINT_RELEASE_TAG = f"zlint-{ZLINT_VERSION}"
ZLINT_RELEASE_URL = f"https://github.com/MagliariElio/DigitalCertiAnalytics/releases/download/{ZLINT_RELEASE_TAG}/"

GO_VERSION = "1.27.2"
GO_MIRRORS = ("https://dl.google.com/go/", "https://go.dev/dl/")
GO_ARCHIVES = {
    ("macos", "arm64"): ("go1.27.2.darwin-arm64.tar.gz",
                         "76812b213b1b2302c978d28fa52fa92d541704b9e7d9d5db8002c50e4018c4c5"),
    ("macos", "x86_64"): ("go1.27.2.darwin-amd64.tar.gz",
                          "587b59182488b23aa6e5fc25110405a3e0e5b38ed2f5b2f46ed13c32aee356fe"),
    ("linux", "x86_64"): ("go1.27.2.linux-amd64.tar.gz",
                          "ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5"),
    ("linux", "arm64"): ("go1.27.2.linux-arm64.tar.gz",
                         "94f3e30b8e374bc285e7dadc11e0865726b9bc6e85b841ccceaabc0214c6b7c8"),
    ("windows", "x86_64"): ("go1.27.2.windows-amd64.zip",
                            "1314008898bd40df77af4b014f777f08873dbdfbcd3d92308728ee03304fe04f"),
    ("windows", "arm64"): ("go1.27.2.windows-arm64.zip",
                           "5c4b294f23b558619ae8a4aa94d023e3bca03f52c8398bb41b9026002b0013de"),
}
# Go 1.27 needs macOS 13: on macOS 11 and 12 ZLint is built with Go 1.24, the last release for them. It builds the same
# ZLint commit (its go.mod needs Go 1.18), so only the binary differs from the reference build below.
GO_MINIMUM_MACOS = (13,)
GO_OLD_MACOS_VERSION = "1.24.13"
GO_OLD_MACOS_MINIMUM = (11,)
GO_OLD_MACOS_ARCHIVES = {
    "arm64": ("go1.24.13.darwin-arm64.tar.gz", "f282d882c3353485e2fc6c634606d85caf36e855167d59b996dbeae19fa7629a"),
    "x86_64": ("go1.24.13.darwin-amd64.tar.gz", "6cc6549b06725220b342b740497ffd24e0ebdcef75781a77931ca199f46ad781"),
}
# The build is reproducible: Go 1.27.2 with the flags of build_zlint gives these programs, on any computer (also
# cross-compiled by zlint-binaries.yml). A local build that differs is only a warning; a downloaded one is refused.
ZLINT_BUILD_SHA256 = {
    ("macos", "arm64"): "1e66ee37906c05ad14599ada424fcd796df78a94124a36341ce89c9781b2bf2d",
    ("macos", "x86_64"): "c9fbdccd5797f23f3576ca87601450444b044147a3cbfe68df245c9533531242",
    ("linux", "x86_64"): "355e6cde3dcf11739cdf028ec9afd7fdcdf2b4244a176f3da37fdc4775a0f12a",
    ("linux", "arm64"): "fafd01cf3a4fa6711b4af802fc4f86ae6d81351ba1c6aa4fe534c3440468dc8a",
    ("windows", "x86_64"): "b949e5268f3f0e7a21ff00edd7f25fb1608e0fd1e8916ab146bc5a8f852866a0",
    ("windows", "arm64"): "0c55396debcec54eb0733ecf3b87f46c51b465635d26631b4d08b03e0c3f44b9",
}
# Used only when the build fails: the closest official release (x86_64 only, so an Apple Silicon Mac needs Rosetta;
# it has 3 lints fewer than the commit)
ZLINT_PREBUILT_VERSION = "3.6.4"
ZLINT_PREBUILT = {
    "macos": ("Darwin", "7f9f06d1de235b7bda8bc060448c768374c9f311aeac688567331549c08de752"),
    "linux": ("Linux", "0703f74ef7156b353f58969ffa50a6a12ad6ecd9ab194231c98c81743c830a02"),
    "windows": ("Windows", "90eb0e3dfbc05420ef1e67b5333b8a2aa899263299236c23bab7f3d52fd02100"),
}

# Google's list of all the CT logs, including the retired ones, signed with this key (sha256 of the PEM file:
# a284e4ad744211a6636a03c59aca9446ecd5ff2c14d7cb6edd69f7ba2108bf95, from www.gstatic.com/ct/log_list/v3/)
LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
LOG_LIST_SIGNATURE_URL = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.sig"
LOG_LIST_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsu0BHGnQ++W2CTdyZyxv
HHRALOZPlnu/VMVgo2m+JZ8MNbAOH2cgXb8mvOj8flsX/qPMuKIaauO+PwROMjiq
fUpcFm80Kl7i97ZQyBDYKm3MkEYYpGN+skAR2OebX9G2DfDqFY8+jUpOOWtBNr3L
rmVcwx+FcFdMjGDlrZ5JRmoJ/SeGKiORkbbu9eY1Wd0uVhz/xI5bQb0OgII7hEj+
i/IPbJqOHgB8xQ5zWAJJ0DmG+FM6o7gk403v6W3S8qRYiR84c50KppGwe4YqSMkF
bLDleGQWLoaDSpEWtESisb4JiLaY4H+Kk0EyAhPSb+49JfUozYl+lf7iFN3qRq/S
IXXTh6z0S7Qa8EYDhKGCrpI03/+qprwy+my6fpWHi6aUIk4holUCmWvFxZDfixox
K0RlqbFDl2JXMBquwlQpm8u5wrsic1ksIv9z8x9zh4PJqNpCah0ciemI3YGRQqSe
/mRRXBiSn9YQBUPcaeqCYan+snGADFwHuXCd9xIAdFBolw9R9HTedHGUfVXPJDiF
4VusfX6BRR/qaadB+bqEArF/TzuDUr6FvOR4o8lUUxgLuZ/7HO+bHnaPFKYHHSm+
+z1lVDhhYuSZ8ax3T0C3FZpb7HMjZtpEorSV5ElKJEJwrhrBCMOD8L01EoSPrGlS
1w22i9uGHMn/uGQKo28u7AsCAwEAAQ==
-----END PUBLIC KEY-----
"""

# ---------------------------------------------------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------------------------------------------------

USER_AGENT = "DigitalCertiAnalytics-installer/1.0"
NETWORK_TIMEOUT = 60                # Seconds without data before a download attempt is abandoned
RETRY_DELAYS = (3, 10, 30)          # Pauses between download attempts
CHUNK_SIZE = 1 << 16
GO_BUILD_TIMEOUT = 1800
GB = 1 << 30
MB = 1 << 20
SPACE_FOR_GO_BUILD = int(1.3 * GB)  # Go toolchain, modules and build cache, removed after the build
# The scan file compressed with --compress_input (about 16 GB for 80 GB of JSON) and its SQLite databases (under
# 10 GB for 10 million lines)
RECOMMENDED_FREE_SPACE = 30 * GB

NETWORK_ERRORS = (urllib.error.URLError, http.client.HTTPException, OSError, ValueError)
PROCESS_TIMED_OUT = -1001
PROCESS_NOT_STARTED = -1002

COMPONENT_NAMES = ("zlint", "log_list")
COMPONENT_ALIASES = {"log-list": "log_list", "loglist": "log_list"}
OBSOLETE_COMPONENTS = ("mongodb", "mongo", "mongod")  # MongoDB is no longer used: naming it changes nothing

RUN_AGAIN = "Run the installer again: it continues where it stopped."
NETWORK_HINT = ("Check your internet connection, then run the installer again: it continues where it stopped. "
                "Behind a proxy, set HTTPS_PROXY (for example HTTPS_PROXY=http://proxy.example.org:8080).")
CERTIFICATE_HINT = ("The secure connection could not be verified. On a company or university network that inspects "
                    "traffic, set SSL_CERT_FILE to the file of your organisation's certificates and run the installer "
                    "again.")


# ---------------------------------------------------------------------------------------------------------------------
# Errors and output
# ---------------------------------------------------------------------------------------------------------------------

class InstallError(Exception):
    """A step failed: `message` says what happened, `hint` what the user can do about it."""

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.message = message
        self.hint = hint


def _enable_windows_colors() -> bool:
    """Turn on ANSI escape codes in the Windows console (Windows 10 and newer)."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError, ImportError):
        return False


def _supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if not (hasattr(stream, "isatty") and stream.isatty()):
        return False
    return _enable_windows_colors() if os.name == "nt" else True


class Ui:
    """Plain, friendly console output, also copied (without colors) to a log file."""

    STYLES = {"ok": "32", "warn": "33", "fail": "31", "info": "36", "skip": "36", "bold": "1"}
    TAGS = {"ok": " OK ", "warn": "WARN", "fail": "FAIL", "info": "INFO", "skip": "SKIP"}

    def __init__(self, stream=None, color: bool | None = None):
        self.stream = stream if stream is not None else sys.stdout
        self.color = _supports_color(self.stream) if color is None else color
        self.interactive = hasattr(self.stream, "isatty") and self.stream.isatty()
        self.log = None

    def open_log(self, path: Path) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.log = open(path, "w", encoding="utf-8")
        except OSError:
            self.log = None

    def close_log(self) -> None:
        if self.log is not None:
            self.log.close()
            self.log = None

    def paint(self, text: str, style: str) -> str:
        return f"\033[{self.STYLES[style]}m{text}\033[0m" if self.color else text

    def line(self, text: str = "", plain: str | None = None) -> None:
        try:
            print(text, file=self.stream, flush=True)
        except UnicodeEncodeError:
            print(text.encode("ascii", "replace").decode("ascii"), file=self.stream, flush=True)
        if self.log is not None:
            self.log.write((text if plain is None else plain) + "\n")
            self.log.flush()

    def log_only(self, text: str) -> None:
        if self.log is not None:
            self.log.write(text + "\n")
            self.log.flush()

    def raw(self, text: str) -> None:
        """Progress output: on the console only."""
        self.stream.write(text)
        self.stream.flush()

    def step(self, title: str) -> None:
        self.line()
        self.line(self.paint(f"==> {title}", "bold"), f"==> {title}")

    def _tagged(self, style: str, message: str, hint: str = "") -> None:
        tag = f"[{self.TAGS[style]}]"
        self.line(f"    {self.paint(tag, style)} {message}", f"    {tag} {message}")
        if hint:
            self.line(f"           What to do: {hint}")

    def ok(self, message: str) -> None:
        self._tagged("ok", message)

    def warn(self, message: str, hint: str = "") -> None:
        self._tagged("warn", message, hint)

    def fail(self, message: str, hint: str = "") -> None:
        self._tagged("fail", message, hint)

    def detail(self, message: str) -> None:
        self.line(f"           {message}")

    def confirm(self, question: str) -> bool:
        """Ask a yes/no question on a terminal; without one (e.g. under "curl | bash") the answer is no."""
        stdin = sys.stdin
        if not (self.interactive and stdin is not None and hasattr(stdin, "isatty") and stdin.isatty()):
            return False
        prompt = f"           {question} [y/N] "
        try:
            answer = input(prompt)
        except EOFError:
            answer = ""
        self.log_only(prompt + answer)
        return answer.strip().lower() in ("y", "yes")


class Progress:
    """Download progress: one updating line on a terminal, a few lines in a log."""

    def __init__(self, ui: Ui, label: str, total: int | None):
        self.ui = ui
        self.label = label
        self.total = total if total and total > 0 else None
        self.last_time = 0.0
        self.last_decile = -1

    def _text(self, done: int) -> str:
        if self.total:
            return f"           {self.label}: {100 * done // self.total:3d}%  ({done / MB:.1f} of {self.total / MB:.1f} MB)"
        return f"           {self.label}: {done / MB:.1f} MB"

    def update(self, done: int) -> None:
        if self.ui.interactive:
            now = time.monotonic()
            if now - self.last_time >= 0.2:
                self.last_time = now
                self.ui.raw("\r" + self._text(done) + "  ")
        elif self.total:
            decile = 10 * done // self.total
            if decile > self.last_decile and decile % 5 == 0:
                self.last_decile = decile
                self.ui.line(self._text(done))

    def finish(self, done: int) -> None:
        if self.ui.interactive:
            self.ui.raw("\r" + self._text(done) + "  \n")
            self.ui.log_only(self._text(done))
        elif self.last_decile < 10:
            self.ui.line(self._text(done))


# ---------------------------------------------------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class PlatformInfo:
    """The computer the tools are installed for."""
    system: str                          # 'macos', 'linux', 'windows' or another sys.platform value
    arch: str                            # 'x86_64', 'arm64' or the raw machine name
    libc: str = ""                       # 'glibc' or 'musl' on Linux
    os_release: dict = field(default_factory=dict)
    mac_version: tuple = ()
    windows_build: int = 0

    @property
    def windows(self) -> bool:
        return self.system == "windows"

    def exe(self, name: str) -> str:
        return name + ".exe" if self.windows else name

    def describe(self) -> str:
        if self.system == "macos":
            return f"macOS {'.'.join(map(str, self.mac_version))} ({self.arch})"
        if self.system == "windows":
            return f"Windows build {self.windows_build} ({self.arch})"
        name = self.os_release.get("PRETTY_NAME") or self.os_release.get("ID") or "Linux"
        return f"{name} ({self.arch}, {self.libc or 'unknown libc'})"


def normalize_arch(machine: str) -> str:
    machine = machine.lower()
    if machine in ("x86_64", "amd64", "x64"):
        return "x86_64"
    if machine in ("arm64", "aarch64", "armv8", "armv8l"):
        return "arm64"
    return machine


def parse_version(text: str) -> tuple:
    """'14.6.1' -> (14, 6, 1); the leading numeric fields only."""
    numbers = []
    for part in text.split("."):
        if not part.isdigit():
            break
        numbers.append(int(part))
    return tuple(numbers)


def parse_os_release(text: str) -> dict:
    """Parse the KEY=value lines of /etc/os-release."""
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as reader:
            return reader.read()
    except OSError:
        return ""


def _sysctl(name: str) -> str:
    result = run(["sysctl", "-n", name], timeout=10)
    return result.stdout.strip() if result.returncode == 0 else ""


def _windows_native_arch() -> str | None:
    """The processor's own architecture, also when this Python runs emulated (x64 Python on ARM64 Windows)."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        process_machine, native_machine = ctypes.c_ushort(), ctypes.c_ushort()
        if kernel32.IsWow64Process2(kernel32.GetCurrentProcess(), ctypes.byref(process_machine),
                                    ctypes.byref(native_machine)):
            return {0x8664: "x86_64", 0xAA64: "arm64"}.get(native_machine.value)
    except (AttributeError, OSError, ImportError):
        pass
    return None


def _linux_libc() -> str:
    if platform.libc_ver()[0] == "glibc":
        return "glibc"
    if any(name.startswith("ld-musl") for name in _list_dir("/lib")):
        return "musl"
    return "glibc" if os.path.exists("/lib64/ld-linux-x86-64.so.2") else ""


def _list_dir(path: str) -> list:
    try:
        return os.listdir(path)
    except OSError:
        return []


def detect_platform() -> PlatformInfo:
    arch = normalize_arch(platform.machine())
    if sys.platform == "darwin":
        # A Terminal running under Rosetta reports x86_64 on an Apple Silicon Mac: use the native builds
        if _sysctl("hw.optional.arm64") == "1":
            arch = "arm64"
        return PlatformInfo("macos", arch, mac_version=parse_version(platform.mac_ver()[0]))
    if sys.platform == "win32":
        return PlatformInfo("windows", _windows_native_arch() or arch, windows_build=sys.getwindowsversion().build)
    if sys.platform.startswith("linux"):
        text = _read_text("/etc/os-release") or _read_text("/usr/lib/os-release")
        return PlatformInfo("linux", arch, libc=_linux_libc(), os_release=parse_os_release(text))
    return PlatformInfo(sys.platform, arch)


# ---------------------------------------------------------------------------------------------------------------------
# Project layout and manifest
# ---------------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Layout:
    """Where everything lives inside the project folder."""
    root: Path
    windows: bool = os.name == "nt"

    def exe(self, name: str) -> str:
        return name + ".exe" if self.windows else name

    @property
    def tools(self) -> Path:
        return self.root / ".tools"

    @property
    def cache(self) -> Path:
        return self.tools / "cache"

    @property
    def downloads(self) -> Path:
        return self.cache / "downloads"

    @property
    def go_dir(self) -> Path:
        return self.cache / "go"

    @property
    def zlint(self) -> Path:
        return self.tools / "zlint" / self.exe("zlint")

    @property
    def legacy_zlint(self) -> Path:
        return self.root / "zlint" / "v3" / self.exe("zlint")

    @property
    def python_dir(self) -> Path:
        return self.tools / "python"

    @property
    def pycache(self) -> Path:
        return self.cache / "pycache"

    @property
    def legacy_mongodb(self) -> Path:
        """The MongoDB server bundled by older versions (the ZLint results are now in the SQLite databases)."""
        return self.tools / "mongodb"

    @property
    def legacy_mongodb_data(self) -> Path:
        """The ZLint results that older versions stored in MongoDB: deleted only when the user confirms."""
        return self.root / "data" / "mongodb"

    @property
    def manifest(self) -> Path:
        return self.tools / "manifest.json"

    @property
    def venv(self) -> Path:
        return self.root / ".venv"

    @property
    def venv_python(self) -> Path:
        return self.venv / ("Scripts/python.exe" if self.windows else "bin/python")

    @property
    def log_list(self) -> Path:
        return self.root / "res" / "log_list.json"

    @property
    def scan_file(self) -> Path:
        return self.root / "res" / "certs_polito.json"

    @property
    def launcher(self) -> Path:
        return self.root / ("dca.bat" if self.windows else "dca")


@dataclass
class Context:
    layout: Layout
    platform: PlatformInfo
    ui: Ui
    manifest: dict = field(default_factory=dict)
    forced: frozenset = frozenset()     # Components reinstalled even if they are installed (--force)


def load_manifest(layout: Layout) -> dict:
    try:
        data = json.loads(layout.manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_manifest(ctx: Context) -> None:
    plat = ctx.platform
    ctx.manifest.update({
        "schema": 1,
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": {"system": plat.system, "arch": plat.arch, "description": plat.describe()},
        "python": platform.python_version(),
    })
    if os.environ.get("DCA_UV_VERSION"):
        ctx.manifest["uv"] = os.environ["DCA_UV_VERSION"]
    path = ctx.layout.manifest
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(ctx.manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def component_entry(ctx: Context, name: str) -> dict:
    entry = ctx.manifest.get("components", {}).get(name)
    return entry if isinstance(entry, dict) else {}


def set_component(ctx: Context, name: str, entry: dict) -> None:
    ctx.manifest.setdefault("components", {})[name] = entry
    save_manifest(ctx)


def relative_to_tools(layout: Layout, path: Path) -> str:
    return path.relative_to(layout.tools).as_posix()


# ---------------------------------------------------------------------------------------------------------------------
# Files, processes and downloads
# ---------------------------------------------------------------------------------------------------------------------

def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as reader:
        for block in iter(lambda: reader.read(MB), b""):
            digest.update(block)
    return digest.hexdigest()


def _make_writable_and_retry(function, path, _error) -> None:
    """Read-only files (the Go module cache, Windows attributes) are made writable, then deleted."""
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
        parent = os.path.dirname(path)
        if parent:
            os.chmod(parent, stat.S_IRWXU)
        function(path)
    except OSError:
        pass


def remove_tree(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=_make_writable_and_retry)
        else:
            shutil.rmtree(path, onerror=_make_writable_and_retry)


def free_space(path: Path) -> int:
    for candidate in (path, *path.parents):
        if candidate.exists():
            return shutil.disk_usage(candidate).free
    return 0


def ensure_free_space(path: Path, needed: int, what: str) -> None:
    available = free_space(path)
    if available < needed:
        raise InstallError(
            f"Not enough free disk space for {what}: {needed / GB:.1f} GB are needed, only {available / GB:.1f} GB "
            f"are free on the disk of {path}.",
            "Free some disk space (or move the project folder to a disk with more space) and run the installer again.")


def run(command: list, timeout: float, env: dict | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run a program and capture its output; never raises for a program that fails, hangs or cannot start."""
    command = [str(part) for part in command]
    try:
        return subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=timeout, env=env,
                              cwd=cwd, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, PROCESS_TIMED_OUT, "", f"it did not finish within {timeout} s")
    except OSError as error:
        return subprocess.CompletedProcess(command, PROCESS_NOT_STARTED, "", str(error))


def tail(text: str, lines: int = 15) -> str:
    kept = [line for line in text.strip().splitlines() if line.strip()][-lines:]
    return "\n".join("           | " + line for line in kept)


def _urlopen(url: str, headers: dict | None = None):
    """Open a URL; proxies come from HTTPS_PROXY/HTTP_PROXY/NO_PROXY or the system settings."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    return urllib.request.urlopen(request, timeout=NETWORK_TIMEOUT)


def _describe_error(error: BaseException) -> str:
    if isinstance(error, urllib.error.HTTPError):
        return f"HTTP error {error.code} {error.reason}"
    if isinstance(error, urllib.error.URLError):
        return str(error.reason)
    return str(error) or type(error).__name__


def _network_hint(errors: list) -> str:
    return CERTIFICATE_HINT if any("CERTIFICATE_VERIFY_FAILED" in text for text in errors) else NETWORK_HINT


def _response_status(response) -> int:
    return getattr(response, "status", None) or 200


def _fetch(ui: Ui, url: str, part: Path, label: str) -> None:
    """Download url into part, resuming a partial file when the server allows it."""
    have = part.stat().st_size if part.exists() else 0
    try:
        response = _urlopen(url, {"Range": f"bytes={have}-"} if have else None)
    except urllib.error.HTTPError as error:
        if error.code == 416 and have:  # The partial file is already complete
            return
        raise
    with response:
        resumed = bool(have) and _response_status(response) == 206
        done = have if resumed else 0
        length = response.headers.get("Content-Length")
        total = done + int(length) if length and length.isdigit() else None
        progress = Progress(ui, label, total)
        with open(part, "ab" if resumed else "wb") as writer:
            for block in iter(lambda: response.read(CHUNK_SIZE), b""):
                writer.write(block)
                done += len(block)
                progress.update(done)
        progress.finish(done)
    if total and done < total:
        raise OSError(f"the connection was closed after {done} of {total} bytes")


def _pause_before_retry(attempt: int) -> None:
    if attempt < len(RETRY_DELAYS):
        time.sleep(RETRY_DELAYS[attempt])


def download(ui: Ui, urls: list, dest: Path, sha256: str, label: str) -> Path:
    """Download a file, verify its SHA-256 and return its path.

    A verified file from an earlier run is reused, a partial one is resumed, and every attempt tries the next mirror.
    """
    if dest.is_file() and file_sha256(dest) == sha256:
        ui.detail(f"{label}: already downloaded")
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    errors, mismatches = [], 0
    for attempt in range(len(RETRY_DELAYS) + 1):
        url = urls[attempt % len(urls)]
        try:
            _fetch(ui, url, part, label)
        except NETWORK_ERRORS as error:
            errors.append(f"{url}: {_describe_error(error)}")
            _pause_before_retry(attempt)
            continue
        actual = file_sha256(part)
        if actual == sha256:
            os.replace(part, dest)
            return dest
        part.unlink()
        mismatches += 1
        errors.append(f"{url}: the file has SHA-256 {actual}, expected {sha256}")
    if mismatches:
        raise InstallError(
            f"The download of {label} did not match its expected SHA-256 checksum, so it was deleted "
            f"({errors[-1]}).",
            "The file was damaged or changed on the way (a proxy or antivirus can do this). Run the installer again; "
            "if it keeps failing, try another network.")
    raise InstallError(f"Could not download {label}: {errors[-1] if errors else 'unknown error'}.", _network_hint(errors))


def fetch_bytes(url: str, label: str, limit: int = 32 * MB) -> bytes:
    """Download a small file into memory, retrying on network errors."""
    errors = []
    for attempt in range(len(RETRY_DELAYS) + 1):
        try:
            with _urlopen(url) as response:
                data = response.read(limit + 1)
            if len(data) > limit:
                raise InstallError(f"The file {url} is unexpectedly large.", RUN_AGAIN)
            return data
        except NETWORK_ERRORS as error:
            errors.append(f"{url}: {_describe_error(error)}")
            _pause_before_retry(attempt)
    raise InstallError(f"Could not download {label}: {errors[-1]}.", _network_hint(errors))


# ---------------------------------------------------------------------------------------------------------------------
# Archive extraction (safe against "zip slip": nothing is written outside the destination)
# ---------------------------------------------------------------------------------------------------------------------

def safe_member_path(dest: Path, name: str) -> Path:
    """The path where an archive member goes, refusing absolute paths and '..' components."""
    normalized = name.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if (normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized) or ".." in parts or not parts
            or any(":" in part for part in parts)):
        raise InstallError(f"The archive contains an unsafe path ({name!r}), so it was not extracted.",
                           "The download may have been tampered with. Run the installer again.")
    target = dest.joinpath(*parts)
    root = dest.resolve()
    if os.path.commonpath([str(root), str(target.resolve())]) != str(root):
        raise InstallError(f"The archive member {name!r} points outside the destination folder, so it was not "
                           "extracted.", "The download may have been tampered with. Run the installer again.")
    return target


def _write_member(source, target: Path, mode: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "wb") as writer:
        shutil.copyfileobj(source, writer, CHUNK_SIZE * 16)
    if os.name != "nt":
        os.chmod(target, 0o755 if mode & 0o111 else 0o644)


Selector = Callable[[str], "str | None"]


def _keep_all(name: str) -> str:
    return name


def _extract_tar(archive: Path, dest: Path, select: Selector) -> list:
    written = []
    with tarfile.open(archive, "r:*") as tar:
        for member in tar:
            relative = select(member.name)
            if relative is None:
                continue
            target = safe_member_path(dest, relative)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                _write_member(tar.extractfile(member), target, member.mode)
                written.append(target)
            elif member.issym() or member.islnk():
                # Links are not needed by any of the archives used here: they are skipped, but one that would point
                # outside the folder means the archive is not what it should be
                _check_link(relative, member.linkname, member.issym())
    return written


def _check_link(relative: str, linkname: str, symbolic: bool) -> None:
    linkname = linkname.replace("\\", "/")
    base = posixpath.dirname(relative) if symbolic else ""
    joined = posixpath.normpath(posixpath.join(base, linkname))
    if linkname.startswith("/") or re.match(r"^[A-Za-z]:", linkname) or joined == ".." or joined.startswith("../"):
        raise InstallError(f"The archive contains a link that points outside the folder ({relative!r} -> "
                           f"{linkname!r}), so it was not extracted.",
                           "The download may have been tampered with. Run the installer again.")


def _zip_mode(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0o777 if info.create_system == 3 else 0o644


def _extract_zip(archive, dest: Path, select: Selector) -> list:
    written = []
    with zipfile.ZipFile(archive) as zipped:
        for info in zipped.infolist():
            relative = select(info.filename)
            if relative is None:
                continue
            target = safe_member_path(dest, relative)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            elif not stat.S_ISLNK(info.external_attr >> 16):
                with zipped.open(info) as source:
                    _write_member(source, target, _zip_mode(info))
                written.append(target)
    return written


def extract_archive(archive: Path, dest: Path, select: Selector = _keep_all) -> list:
    """Extract a .tar.gz or .zip archive into dest and return the files written.

    `select` maps a member name to its path inside dest, or to None to skip the member.
    """
    dest.mkdir(parents=True, exist_ok=True)
    try:
        if zipfile.is_zipfile(archive):
            return _extract_zip(archive, dest, select)
        return _extract_tar(archive, dest, select)
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError) as error:
        raise InstallError(f"Could not extract {Path(archive).name}: {error}.",
                           "The file may be damaged or the disk full. Run the installer again.") from error


def select_basename(*names: str) -> Selector:
    """Selector keeping only the members with one of these file names, placed directly in the destination."""
    def select(member: str) -> str | None:
        base = member.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        return base if base in names else None
    return select


# ---------------------------------------------------------------------------------------------------------------------
# ZLint
# ---------------------------------------------------------------------------------------------------------------------

GO_USER_SETTINGS = ("GOPROXY", "GOSUMDB", "GONOSUMDB", "GONOPROXY", "GOPRIVATE", "GOINSECURE", "GOAUTH")
GO_BUILD_HINT = ("Go downloads the ZLint source code from proxy.golang.org and checks it with sum.golang.org: make sure "
                 "these sites are reachable (on a company network you may need to set GOPROXY), then run the installer "
                 "again.")


def go_toolchain_for(plat: PlatformInfo) -> tuple:
    """(Go version, archive name, its SHA-256) of the Go that builds ZLint on this computer."""
    if plat.system == "macos" and plat.mac_version and plat.mac_version < GO_MINIMUM_MACOS:
        if plat.mac_version < GO_OLD_MACOS_MINIMUM or plat.arch not in GO_OLD_MACOS_ARCHIVES:
            raise InstallError(f"ZLint cannot be built on {plat.describe()}: Go needs macOS 11 or newer.",
                               "Update macOS to version 11 or newer, then run the installer again.")
        return (GO_OLD_MACOS_VERSION, *GO_OLD_MACOS_ARCHIVES[plat.arch])
    try:
        return (GO_VERSION, *GO_ARCHIVES[(plat.system, plat.arch)])
    except KeyError:
        raise InstallError(f"ZLint cannot be built on {plat.describe()}.",
                           "A 64-bit Intel/AMD or ARM computer with macOS, Linux or Windows is needed.") from None


def go_environment(layout: Layout, goroot: Path, base: dict) -> dict:
    """Environment for the Go build: everything it writes stays in .tools (also its telemetry counters)."""
    env = {key: value for key, value in base.items() if not key.upper().startswith("GO") or key in GO_USER_SETTINGS}
    work = layout.go_dir
    home = work / "home"
    env.update({
        "GOROOT": str(goroot), "GOPATH": str(work / "path"), "GOMODCACHE": str(work / "path" / "pkg" / "mod"),
        "GOCACHE": str(work / "build"), "GOTMPDIR": str(work / "tmp"), "GOBIN": str(layout.zlint.parent),
        "GOENV": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "-modcacherw", "GOWORK": "off", "CGO_ENABLED": "0",
        "GOAMD64": "v1", "GOARM64": "v8.0", "GOTELEMETRY": "off",
        "HOME": str(home), "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"),
        "APPDATA": str(home / "AppData" / "Roaming"), "LOCALAPPDATA": str(home / "AppData" / "Local"),
    })
    for key in ("GOTMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "APPDATA", "LOCALAPPDATA"):
        Path(env[key]).mkdir(parents=True, exist_ok=True)
    return env


def zlint_version(binary: Path) -> str | None:
    """The version printed by `zlint -version`, or None if the program does not run."""
    if not binary.is_file():
        return None
    result = run([binary, "-version"], timeout=30)
    match = re.search(r"ZLint version (\S+)", result.stdout + result.stderr)
    return match.group(1) if result.returncode == 0 and match else None


def zlint_current(ctx: Context) -> str | None:
    custom = os.environ.get("DCA_ZLINT_PATH")
    if custom and Path(custom).is_file():
        return f"the ZLint set in DCA_ZLINT_PATH ({custom}) is used"
    entry, binary = component_entry(ctx, "zlint"), ctx.layout.zlint
    if entry.get("version") != ZLINT_VERSION or not binary.is_file() or entry.get("sha256") != file_sha256(binary):
        return None
    return f"ZLint {ZLINT_VERSION}" if zlint_version(binary) == ZLINT_VERSION else None


def _unpack_go(ctx: Context, archive: Path) -> Path:
    toolchain = ctx.layout.go_dir / "toolchain"
    remove_tree(toolchain)
    ctx.ui.detail("Unpacking Go...")
    extract_archive(archive, toolchain)
    go = toolchain / "go" / "bin" / ctx.platform.exe("go")
    if not go.is_file():
        raise InstallError("The Go archive does not contain the go program.", RUN_AGAIN)
    return go


def _clean_go(ctx: Context, go: Path | None, env: dict | None, archive: Path | None) -> None:
    """Remove the toolchain, the module and build caches, and the archive unless it is None (about 0.6 GB)."""
    if go is not None and env is not None and go.is_file():
        run([go, "clean", "-modcache"], timeout=600, env=env, cwd=ctx.layout.go_dir)
    try:
        remove_tree(ctx.layout.go_dir)
        if archive is not None:
            archive.unlink(missing_ok=True)
    except OSError as error:
        ctx.ui.warn(f"Could not remove the temporary Go files in {ctx.layout.go_dir}: {error}",
                    "You can delete that folder by hand.")


def _record_zlint(ctx: Context, expected: str, source: str, go_version: str = GO_VERSION) -> None:
    binary = ctx.layout.zlint
    version = zlint_version(binary)
    if version != expected:
        raise InstallError(f"ZLint was installed but does not run correctly (it reports version {version!r}, expected "
                           f"{expected!r}).", explain_not_runnable(binary))
    digest = file_sha256(binary)
    reference = None
    if source in ("go-build", "release") and go_version == GO_VERSION:
        reference = ZLINT_BUILD_SHA256.get((ctx.platform.system, ctx.platform.arch))
    if reference and digest != reference:
        ctx.ui.warn("The ZLint program differs from the reference build (it can happen with another Go setup); its "
                    "version is the right one, so it is used.")
    entry = {"status": "installed", "version": version, "source": source, "path": relative_to_tools(ctx.layout, binary),
             "sha256": digest}
    if source in ("go-build", "release"):
        entry.update(commit=ZLINT_COMMIT, go=go_version, reference_build=digest == reference)
    set_component(ctx, "zlint", entry)
    ctx.ui.ok(f"ZLint {version} installed in {binary}")


def build_zlint(ctx: Context) -> None:
    layout, ui = ctx.layout, ctx.ui
    go_version, name, digest = go_toolchain_for(ctx.platform)
    ensure_free_space(layout.tools, SPACE_FOR_GO_BUILD, "building ZLint")
    ui.detail("ZLint is built from its source code with Go, which is removed afterwards (about 170 MB to download and "
              "1.2 GB of temporary files).")
    archive = download(ui, [mirror + name for mirror in GO_MIRRORS], layout.downloads / name, digest,
                       f"Go {go_version}")
    go = env = None
    built = False
    try:
        go = _unpack_go(ctx, archive)
        env = go_environment(layout, go.parent.parent, dict(os.environ))
        ui.detail(f"Building ZLint {ZLINT_VERSION} with Go {go_version} (about a minute)...")
        result = run([go, "install", "-trimpath", f"-ldflags=-s -w -X main.version={ZLINT_VERSION}",
                      f"{ZLINT_PACKAGE}@{ZLINT_COMMIT}"], timeout=GO_BUILD_TIMEOUT, env=env, cwd=layout.go_dir)
        if result.returncode != 0:
            raise InstallError("Building ZLint failed:\n" + tail(result.stderr or result.stdout), GO_BUILD_HINT)
        built = True
    finally:
        # After a failed build the verified Go archive is kept, so that the next run does not download it again
        _clean_go(ctx, go, env, archive if built else None)
    _record_zlint(ctx, ZLINT_VERSION, "go-build", go_version)


ROSETTA_HINT = ("The ready-made ZLint is an Intel program, which an Apple Silicon Mac runs with Apple's Rosetta. Install "
                "Rosetta with this Terminal command (it asks for your password): softwareupdate --install-rosetta "
                "--agree-to-license, then run the installer again.")


def rosetta_installed() -> bool:
    """Whether this Mac can run Intel programs (always true on an Intel Mac)."""
    return run(["/usr/bin/arch", "-x86_64", "/usr/bin/true"], timeout=30).returncode == 0


def prebuilt_zlint_available(plat: PlatformInfo) -> bool:
    """The official releases are x86_64 only: they also run emulated on ARM Macs (with Rosetta) and on Windows 11 on
    ARM."""
    if plat.system not in ZLINT_PREBUILT or plat.arch not in ("x86_64", "arm64"):
        return False
    if plat.arch == "arm64" and plat.system == "macos":
        return rosetta_installed()
    return plat.arch == "x86_64" or plat.system == "windows"


def install_prebuilt_zlint(ctx: Context) -> None:
    layout = ctx.layout
    os_name, digest = ZLINT_PREBUILT[ctx.platform.system]
    name = f"zlint_{ZLINT_PREBUILT_VERSION}_{os_name}_x86_64.tar.gz"
    url = f"https://github.com/zmap/zlint/releases/download/v{ZLINT_PREBUILT_VERSION}/{name}"
    archive = download(ctx.ui, [url], layout.downloads / name, digest, f"ZLint {ZLINT_PREBUILT_VERSION}")
    staging = layout.tools / "zlint.new"
    remove_tree(staging)
    extract_archive(archive, staging, select_basename(layout.exe("zlint")))
    layout.zlint.parent.mkdir(parents=True, exist_ok=True)
    os.replace(staging / layout.exe("zlint"), layout.zlint)
    remove_tree(staging)
    archive.unlink(missing_ok=True)
    _record_zlint(ctx, ZLINT_PREBUILT_VERSION, "prebuilt")


def zlint_release_asset(plat: PlatformInfo) -> str | None:
    """The name of this computer's program in the release ZLINT_RELEASE_TAG, or None when there is none for it."""
    if (plat.system, plat.arch) not in ZLINT_BUILD_SHA256:
        return None
    if plat.system == "macos" and plat.mac_version and plat.mac_version < GO_MINIMUM_MACOS:
        return None  # Programs built with Go 1.27 need macOS 13: older Macs build it with an older Go
    return f"zlint-{plat.system}-{plat.arch}" + (".exe" if plat.system == "windows" else "")


def install_release_zlint(ctx: Context) -> bool:
    """Install the ready-made program of the project's release; False (with the reason shown) when it cannot be used.

    It is accepted only if its SHA-256 equals the pinned reproducible build, the same check as a local build."""
    layout, ui, plat = ctx.layout, ctx.ui, ctx.platform
    asset = zlint_release_asset(plat)
    if asset is None:
        return False
    expected = ZLINT_BUILD_SHA256[(plat.system, plat.arch)]
    staging = layout.tools / "zlint.new"
    remove_tree(staging)
    staging.mkdir(parents=True)
    part = staging / layout.exe("zlint")
    reason = ""
    try:
        try:
            _fetch(ui, ZLINT_RELEASE_URL + asset, part, f"ZLint {ZLINT_VERSION} (ready-made)")
        except urllib.error.HTTPError as error:
            reason = "it is not published yet" if error.code == 404 else _describe_error(error)
        except NETWORK_ERRORS as error:
            reason = _describe_error(error)
        if not reason and file_sha256(part) != expected:
            reason = "its SHA-256 differs from the pinned build"
        if not reason:
            part.chmod(0o755)
            layout.zlint.parent.mkdir(parents=True, exist_ok=True)
            os.replace(part, layout.zlint)
            try:
                _record_zlint(ctx, ZLINT_VERSION, "release")
                return True
            except InstallError as error:
                layout.zlint.unlink(missing_ok=True)
                reason = error.message
    finally:
        remove_tree(staging)
    ui.detail(f"The ready-made ZLint cannot be used ({reason.rstrip('.')}): it is built from its source code instead.")
    return False


def install_zlint(ctx: Context) -> None:
    if install_release_zlint(ctx):
        return
    try:
        build_zlint(ctx)
    except InstallError as error:
        if not prebuilt_zlint_available(ctx.platform):
            if ctx.platform.system == "macos" and ctx.platform.arch == "arm64":
                error.hint = f"{error.hint} {ROSETTA_HINT}".strip()
            raise
        ctx.ui.warn(error.message)
        ctx.ui.detail(f"Installing the official prebuilt ZLint {ZLINT_PREBUILT_VERSION} instead. It is a slightly older "
                      f"version (3 lints fewer); run the installer again later to build the exact one.")
        install_prebuilt_zlint(ctx)


def explain_not_runnable(path: Path | None) -> str:
    where = f" ({path})" if path else ""
    return ("The program could not run" + where + ". The disk or folder may not allow running programs (a USB stick, a "
            "network share or a folder mounted with 'noexec'), or an antivirus blocked it. Move the project folder to "
            "your home folder and run the installer again.")


def find_zlint(layout: Layout) -> tuple:
    """The ZLint the program uses, in its search order: (path or None, where it was found)."""
    custom = os.environ.get("DCA_ZLINT_PATH")
    if custom:
        return Path(custom), "DCA_ZLINT_PATH"
    for path, origin in ((layout.zlint, "bundled"), (layout.legacy_zlint, "zlint/v3")):
        if path.is_file():
            return path, origin
    found = shutil.which("zlint")
    return (Path(found), "PATH") if found else (None, "")


# ---------------------------------------------------------------------------------------------------------------------
# Footprint: the unused parts of the project's Python, and the leftovers of older versions
# ---------------------------------------------------------------------------------------------------------------------

# Never imported by the program (it draws its charts with matplotlib's Agg backend, without Tk)
PYTHON_UNUSED_STDLIB = ("ensurepip", "idlelib", "tkinter", "turtledemo", "turtle.py")
PYTHON_UNUSED_LIBS = ("tcl[0-9]*", "tk[0-9]*", "libtcl*", "libtk*", "itcl*", "thread[0-9]*")
PYTHON_UNUSED_SCRIPTS = ("pip*", "idle*", "2to3*")
# Run after the removal: if it fails, everything is put back
PYTHON_SMOKE_TEST = ("import ssl, sqlite3, lzma, bz2, zlib, ctypes, asyncio, multiprocessing, sysconfig, json, csv, "
                     "numpy, zstandard, aiohttp, aiosqlite, cryptography.x509, rich, tqdm, sslyze, matplotlib; "
                     "matplotlib.use('Agg'); import matplotlib.pyplot; sysconfig.get_paths()")
PRUNE_FOLDER = "python-unused"
PRUNE_RECORD = "moved.json"


def tree_size(path: Path) -> int:
    """Bytes of the files under path; a file linked several times is counted once, symbolic links not at all."""
    if path.is_symlink() or not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    seen, total = set(), 0
    for folder, _folders, files in os.walk(path):
        for name in files:
            try:
                info = os.lstat(os.path.join(folder, name))
            except OSError:
                continue
            if stat.S_ISLNK(info.st_mode):
                continue
            if (info.st_dev, info.st_ino) not in seen or not info.st_ino:
                seen.add((info.st_dev, info.st_ino))
                total += info.st_size
    return total


def size_text(size: int) -> str:
    return f"{size / GB:.1f} GB" if size >= GB else f"{size / MB:.0f} MB"


def bundled_python(layout: Layout) -> Path | None:
    """The installation folder of the Python that runs this script, when it is the project's own (.tools/python)."""
    try:
        base, tools = Path(sys.base_prefix).resolve(), layout.python_dir.resolve()
    except OSError:
        return None
    return base if tools in base.parents else None


def _links_libpython(binary: Path) -> bool:
    """Whether the interpreter needs the shared libpython: the name is then in its list of libraries (Mach-O load
    commands, ELF NEEDED). When in doubt (the file cannot be read) the answer is yes, so the library is kept."""
    try:
        with open(binary, "rb") as reader:
            return b"libpython" in reader.read()
    except OSError:
        return True


def python_unused_files(base: Path, windows: bool, version: tuple = sys.version_info[:2]) -> list:
    """The files and folders of the Python installation in base that the program never uses (only existing ones)."""
    found = []

    def add(paths) -> None:
        found.extend(path for path in paths if path.exists() or path.is_symlink())

    if windows:
        stdlib, dynload = base / "Lib", base / "DLLs"
        add(stdlib / name for name in PYTHON_UNUSED_STDLIB)
        add(sorted(dynload.glob("_tkinter*")) + sorted(dynload.glob("tcl*.dll")) + sorted(dynload.glob("tk*.dll")))
        add((base / "tcl", base / "include", base / "libs"))
        add(sorted((stdlib / "site-packages").glob("pip*")))
        add(sorted((base / "Scripts").glob("pip*")) + sorted((base / "Scripts").glob("idle*")))
        return found
    name = f"python{version[0]}.{version[1]}"
    lib = base / "lib"
    stdlib = lib / name
    add(stdlib / item for item in PYTHON_UNUSED_STDLIB)
    add(sorted((stdlib / "lib-dynload").glob("_tkinter*")))
    for pattern in PYTHON_UNUSED_LIBS:
        add(sorted(lib.glob(pattern)))
    add(sorted((stdlib / "site-packages").glob("pip*")))
    add((base / "include", base / "share"))
    for pattern in PYTHON_UNUSED_SCRIPTS:
        add(sorted((base / "bin").glob(pattern)))
    if not _links_libpython(base / "bin" / name):
        add(sorted(lib.glob(f"libpython{version[0]}.{version[1]}*")))
    return found


def _restore_moved(folder: Path) -> None:
    """Put back what an interrupted or failed removal moved away (listed in its record)."""
    try:
        moved = json.loads((folder / PRUNE_RECORD).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        moved = []
    for original, kept in reversed(moved):
        if Path(kept).exists() or Path(kept).is_symlink():
            os.replace(kept, original)
    remove_tree(folder)


def python_works(ctx: Context) -> subprocess.CompletedProcess:
    env = dict(os.environ, MPLCONFIGDIR=str(ctx.layout.cache / "matplotlib"), MPLBACKEND="Agg",
               PYTHONPYCACHEPREFIX=str(ctx.layout.pycache))
    return run([ctx.layout.venv_python, "-c", PYTHON_SMOKE_TEST], timeout=600, env=env)


def prune_python(ctx: Context, base: Path | None = None, version: tuple = sys.version_info[:2]) -> None:
    """Remove the parts of the project's Python that the program never uses (about 30 MB).

    Everything is first moved aside, then the program's modules are imported: only if that works is it deleted,
    otherwise everything is put back. The record of the moves lets the next run put back what an interrupted run
    moved."""
    layout, ui = ctx.layout, ctx.ui
    folder = layout.tools / PRUNE_FOLDER
    if folder.exists():
        _restore_moved(folder)
    base = bundled_python(layout) if base is None else base
    if base is None:
        return
    unused = python_unused_files(base, layout.windows, version)
    if not unused:
        return
    size = sum(tree_size(path) for path in unused)
    folder.mkdir(parents=True)
    moved = []
    passed = False
    try:
        for index, path in enumerate(unused):
            kept = folder / f"{index}-{path.name}"
            moved.append((str(path), str(kept)))
            (folder / PRUNE_RECORD).write_text(json.dumps(moved), encoding="utf-8")
            os.replace(path, kept)
        result = python_works(ctx)
        passed = result.returncode == 0
        if not passed:
            ui.warn("Python does not work without its unused parts, so they are kept:\n" + tail(result.stderr, 6))
    except OSError as error:
        ui.warn(f"The unused parts of Python could not be removed ({error}), so they are kept.")
    finally:
        if passed:
            remove_tree(folder)
        else:
            _restore_moved(folder)
    if passed:
        ui.ok(f"Removed {size_text(size)} of Python that the program never uses (Tk, IDLE, pip, C headers)")


def stale_bytecode(layout: Layout) -> list:
    """The folders of .tools/cache/pycache that belong to an older location of the project.

    Python keeps the bytecode cache (PYTHONPYCACHEPREFIX) under the full path of every source file, so after the
    project folder is moved the bytecode of the old location is never used again."""
    fold = str.casefold if layout.windows or sys.platform == "darwin" else str
    keep = set()
    for root in (str(layout.root), os.path.realpath(layout.root)):
        rest = os.path.splitdrive(root)[1].replace("\\", "/")  # Python leaves the drive out of the cache path
        keep.add(tuple(fold(part) for part in rest.split("/") if part))
    stale = []

    def visit(folder: Path, parts: tuple) -> None:
        for child in sorted(folder.iterdir()):
            path = parts + (fold(child.name),)
            matches = [root for root in keep if root[:len(path)] == path]
            if not matches:
                stale.append(child)
            elif all(len(path) < len(root) for root in matches):
                if child.is_dir() and not child.is_symlink():
                    visit(child, path)
                else:
                    stale.append(child)

    if layout.pycache.is_dir():
        visit(layout.pycache, ())
    return stale


def remove_leftovers(ctx: Context, success: bool) -> None:
    """Remove what older versions or interrupted runs left in .tools, and offer to delete the old MongoDB data.

    The Go files and the downloads are removed only after a successful installation: a failed build keeps the
    verified Go archive, so that the next run does not download it again."""
    layout, ui = ctx.layout, ctx.ui
    leftovers = [(layout.legacy_mongodb, "the MongoDB server of an older version (no longer needed)")]
    leftovers += [(path, "the Python bytecode of an older location of the project") for path in stale_bytecode(layout)]
    if success:
        leftovers += [(layout.go_dir, "temporary Go files"), (layout.downloads, "downloaded archives")]
    for path, what in leftovers:
        if path.exists():
            size = tree_size(path)
            try:
                remove_tree(path)
                if size:
                    ui.ok(f"Removed {what}: {path} ({size_text(size)})")
            except OSError as error:
                ui.warn(f"Could not remove {path}: {error}", "You can delete that folder by hand.")
    offer_to_delete_mongodb_data(ctx)


def offer_to_delete_mongodb_data(ctx: Context) -> None:
    """The ZLint results of older versions (tens of GB at most) are deleted only when the user says so."""
    ui, data = ctx.ui, ctx.layout.legacy_mongodb_data
    if not data.exists():
        return
    size = tree_size(data)
    ui.warn(f"The folder {data} ({size_text(size)}) holds the ZLint results of an older version, stored by MongoDB, "
            "which is no longer used: the ZLint results are now kept in the SQLite databases (run the ZLint checks "
            "again to recreate them).")
    if not ui.confirm(f"Delete {data} ({size_text(size)}) now?"):
        ui.detail("It is kept. You can delete that folder yourself when its results are no longer needed.")
        return
    try:
        remove_tree(data)
        if data.parent.is_dir() and not any(data.parent.iterdir()):
            data.parent.rmdir()
        ui.ok(f"Deleted {data}")
    except OSError as error:
        ui.warn(f"Could not delete {data}: {error}", "You can delete that folder by hand.")


# ---------------------------------------------------------------------------------------------------------------------
# CT log list
# ---------------------------------------------------------------------------------------------------------------------

def _der_element(data: bytes, position: int) -> tuple:
    """(tag, start, end) of the DER element at position."""
    tag, length = data[position], data[position + 1]
    position += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[position:position + count], "big")
        position += count
    if position + length > len(data):
        raise ValueError("truncated DER data")
    return tag, position, position + length


RSA_ENCRYPTION_OID = bytes.fromhex("2a864886f70d010101")
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_public_key(pem: str) -> tuple:
    """(n, e) of an RSA public key in PEM (SubjectPublicKeyInfo) format."""
    body = "".join(line for line in pem.strip().splitlines() if not line.startswith("-----"))
    der = base64.b64decode(body)
    tag, start, _ = _der_element(der, 0)
    algorithm_tag, algorithm_start, algorithm_end = _der_element(der, start)
    oid_tag, oid_start, oid_end = _der_element(der, algorithm_start)
    if tag != 0x30 or algorithm_tag != 0x30 or oid_tag != 0x06 or der[oid_start:oid_end] != RSA_ENCRYPTION_OID:
        raise ValueError("not an RSA public key")
    bits_tag, bits_start, bits_end = _der_element(der, algorithm_end)
    key = der[bits_start + 1:bits_end]  # Skip the 'unused bits' byte of the BIT STRING
    _, sequence_start, _ = _der_element(key, 0)
    _, n_start, n_end = _der_element(key, sequence_start)
    _, e_start, e_end = _der_element(key, n_end)
    return int.from_bytes(key[n_start:n_end], "big"), int.from_bytes(key[e_start:e_end], "big")


def rsa_sha256_signature_valid(pem: str, message: bytes, signature: bytes) -> bool:
    """Verify an RSA PKCS#1 v1.5 signature with SHA-256 (as used for Google's CT log lists)."""
    try:
        n, e = rsa_public_key(pem)
    except (ValueError, IndexError):
        return False
    size = (n.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    decrypted = pow(int.from_bytes(signature, "big"), e, n).to_bytes(size, "big")
    digest_info = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    expected = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    return hmac.compare_digest(decrypted, expected)


def log_list_logs(path: Path) -> int | None:
    """Number of logs in the log list file, or None if it is missing or not a log list."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return sum(len(operator.get("logs", [])) + len(operator.get("tiled_logs", []))
                   for operator in data["operators"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def log_list_current(ctx: Context) -> str | None:
    count = log_list_logs(ctx.layout.log_list)
    return None if count is None else f"res/log_list.json ({count} logs; kept as it is)"


def install_log_list(ctx: Context) -> None:
    """Download Google's list when res/log_list.json is missing or damaged, or when its replacement was asked for
    (--force --only log_list). A valid list stays in place until the new one is verified, then it is kept as .old:
    the list of the project also has logs that Google's current list no longer contains."""
    path = ctx.layout.log_list
    replaced = path.exists() and log_list_logs(path) is not None
    if path.exists() and not replaced:
        broken = path.with_name(path.name + ".broken")
        os.replace(path, broken)
        ctx.ui.warn(f"res/log_list.json is not a valid log list: it was renamed to {broken.name}.")
    data = fetch_bytes(LOG_LIST_URL, "the CT log list")
    signature = fetch_bytes(LOG_LIST_SIGNATURE_URL, "the signature of the CT log list")
    if not rsa_sha256_signature_valid(LOG_LIST_PUBLIC_KEY, data, signature):
        raise InstallError("The downloaded CT log list does not carry Google's valid signature, so it was not saved.",
                           f"Run the installer again. If it keeps failing, download {LOG_LIST_URL} with a browser "
                           "and save it as res/log_list.json.")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    if replaced:
        old = path.with_name(path.name + ".old")
        os.replace(path, old)
        ctx.ui.detail(f"The previous list was kept as res/{old.name}.")
    os.replace(temporary, path)
    set_component(ctx, "log_list", {"status": "downloaded", "url": LOG_LIST_URL, "sha256": hashlib.sha256(data).hexdigest()})
    ctx.ui.ok(f"CT log list downloaded and verified ({log_list_logs(path)} logs)")


# ---------------------------------------------------------------------------------------------------------------------
# Status checks
# ---------------------------------------------------------------------------------------------------------------------

@dataclass
class Status:
    name: str
    state: str        # 'ok', 'warn', 'fail', 'info' or 'skip'
    detail: str
    hint: str = ""


def running_in_venv(layout: Layout) -> bool:
    try:
        return Path(sys.prefix).resolve() == layout.venv.resolve()
    except OSError:
        return False


REINSTALL_HINT = "Run the installer (install.sh, or install.bat on Windows) again to repair it."


def check_python(ctx: Context) -> Status:
    version = platform.python_version()
    if not running_in_venv(ctx.layout):
        return Status("Python", "fail", f"the project environment {ctx.layout.venv} is missing or broken",
                      REINSTALL_HINT + " After moving the project folder this is expected.")
    if sys.version_info[:2] != REQUIRED_PYTHON:
        return Status("Python", "warn", f"Python {version} in .venv (3.12 is the tested version)", REINSTALL_HINT)
    return Status("Python", "ok", f"Python {version} in .venv")


def read_requirements(path: Path) -> list:
    """(name, version) of the 'name==version' lines of requirements.txt."""
    pins = []
    for line in _read_text(str(path)).splitlines():
        match = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", line)
        if match:
            pins.append((match.group(1), match.group(2)))
    return pins


def check_packages(ctx: Context) -> Status:
    pins = read_requirements(ctx.layout.root / "requirements.txt")
    if not running_in_venv(ctx.layout):
        return Status("Python packages", "fail", "not checked: the project environment .venv is missing", REINSTALL_HINT)
    problems = []
    for name, version in pins:
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            problems.append(f"{name} is missing")
            continue
        if installed != version:
            problems.append(f"{name} {installed} instead of {version}")
    if problems:
        return Status("Python packages", "fail", "; ".join(problems), REINSTALL_HINT)
    return Status("Python packages", "ok", f"{len(pins)} packages of requirements.txt installed")


def find_sslyze() -> list:
    """The sslyze command the program uses: next to this Python (the .venv), else on PATH, else `python -m sslyze`."""
    folder = Path(sys.executable).parent
    for candidate in (folder / "sslyze", folder / "sslyze.exe", folder / "Scripts" / "sslyze.exe"):
        if candidate.is_file():
            return [str(candidate)]
    found = shutil.which("sslyze")
    return [found] if found else [sys.executable, "-W", "ignore::DeprecationWarning", "-m", "sslyze"]


def check_sslyze(ctx: Context) -> Status:
    command = find_sslyze()
    result = run([*command, "--help"], timeout=120)
    if result.returncode != 0:
        return Status("sslyze", "fail", f"'{' '.join(command)} --help' does not work:\n{tail(result.stderr, 4)}",
                      REINSTALL_HINT)
    return Status("sslyze", "ok", f"{' '.join(command)}")


def check_zlint(ctx: Context) -> Status:
    path, origin = find_zlint(ctx.layout)
    if path is None:
        return Status("ZLint", "fail", "not installed", REINSTALL_HINT)
    version = zlint_version(path)
    if version is None:
        return Status("ZLint", "fail", f"{path} does not run", explain_not_runnable(path))
    if origin != "bundled":
        return Status("ZLint", "ok" if version == ZLINT_VERSION else "warn", f"{version} ({path}, from {origin})",
                      "" if version == ZLINT_VERSION else f"The analysis was developed with ZLint {ZLINT_VERSION}.")
    if version != ZLINT_VERSION:
        return Status("ZLint", "warn", f"prebuilt ZLint {version} (the analysis uses {ZLINT_VERSION})",
                      "Run the installer again to build the exact version (it needs proxy.golang.org).")
    return Status("ZLint", "ok", f"{version} (.tools/zlint)")


def check_log_list(ctx: Context) -> Status:
    count = log_list_logs(ctx.layout.log_list)
    if count is None:
        return Status("CT log list", "fail", "res/log_list.json is missing or damaged",
                      "Run the installer again: it downloads the list when the file is missing.")
    return Status("CT log list", "ok", f"res/log_list.json ({count} logs)")


# The names the program accepts for the scan file, in its order of preference (analysis/input_file.INPUT_NAMES)
SCAN_FILE_NAMES = ("certs_polito.json", "certs_polito.json.zst", "certs_polito.json.gz", "certs_polito.json.xz",
                   "certs_polito.json.bz2")


def check_scan_file(ctx: Context) -> Status:
    folder = ctx.layout.scan_file.parent
    found = [folder / name for name in SCAN_FILE_NAMES if (folder / name).is_file()]
    if found:
        path = found[0]
        detail = f"res/{path.name} ({path.stat().st_size / GB:.1f} GB)"
        if len(found) > 1:
            detail += "; also " + ", ".join(other.name for other in found[1:]) + " (not used)"
        hint = ""
        if path.name == SCAN_FILE_NAMES[0]:
            launcher = "dca.bat" if ctx.layout.windows else _quoted(ctx.layout.launcher)
            hint = f"To save disk space, compress it (about 5 times smaller, still read in parallel): {launcher} " \
                   "--compress_input"
        return Status("Scan file", "ok", detail, hint)
    return Status("Scan file", "info", "res/certs_polito.json is not there yet",
                  "Put the ZGrab2 output there before running the *_analysis options (see INSTALL.md, step 6 "
                  "\"Add the scan file\").")


def check_launcher(ctx: Context) -> Status:
    launcher = ctx.layout.launcher
    if not launcher.is_file():
        return Status("Launcher", "fail", f"{launcher.name} is missing", "Download the project again.")
    if not ctx.layout.windows and not os.access(launcher, os.X_OK):
        return Status("Launcher", "warn", f"{launcher.name} is not executable",
                      f"Run the installer again, or start it with: sh \"{launcher}\"")
    return Status("Launcher", "ok", str(launcher))


def check_disk(ctx: Context) -> Status:
    available = free_space(ctx.layout.root)
    state = "info" if available >= RECOMMENDED_FREE_SPACE else "warn"
    hint = "" if state == "info" else ("A large scan and its SQLite databases need more space (about 30 GB for an 80 GB "
                                       "scan compressed with --compress_input): free some, or move the project to a "
                                       "bigger disk.")
    return Status("Disk space", state, f"{available / GB:.0f} GB free", hint)


def check_footprint(ctx: Context) -> Status:
    layout = ctx.layout
    tools = tree_size(layout.tools)
    if os.environ.get("DCA_UV_TEMPORARY") == "1":
        tools -= tree_size(layout.tools / "uv")  # install.sh/install.ps1 remove it right after this script
    sizes = f"{layout.tools.name} {size_text(tools)}, {layout.venv.name} {size_text(tree_size(layout.venv))}"
    return Status("Installation", "info", f"{sizes} (to uninstall, delete the project folder)")


def check_legacy_data(ctx: Context) -> Status | None:
    data = ctx.layout.legacy_mongodb_data
    if not data.exists():
        return None
    return Status("Old ZLint data", "warn", f"{data} ({size_text(tree_size(data))}) was written by the MongoDB of an "
                  "older version, which is no longer used",
                  "The ZLint results are now in the SQLite databases: delete that folder (the installer offers to) "
                  "and run the ZLint checks again.")


COMPONENT_CHECKS = {"zlint": check_zlint, "log_list": check_log_list}


def check_all(ctx: Context, components: list) -> list:
    rows = [check_python(ctx), check_packages(ctx), check_sslyze(ctx)]
    rows += [COMPONENT_CHECKS[name](ctx) for name in COMPONENT_NAMES if name in components]
    rows += [check_launcher(ctx), check_scan_file(ctx), check_disk(ctx), check_footprint(ctx)]
    legacy = check_legacy_data(ctx)
    return rows + ([legacy] if legacy else [])


def print_status_table(ui: Ui, rows: list) -> None:
    width = max(len(row.name) for row in rows)
    for row in rows:
        tag = f"[{Ui.TAGS[row.state]}]"
        first, *rest = row.detail.splitlines() or [""]
        ui.line(f"  {ui.paint(tag, row.state)} {row.name:<{width}}  {first}", f"  {tag} {row.name:<{width}}  {first}")
        indent = " " * (width + 11)
        for line in rest:
            ui.line(indent + line.strip())
        if row.hint:
            ui.line(f"{indent}What to do: {row.hint}")


# ---------------------------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Component:
    name: str
    title: str
    current: Callable[[Context], "str | None"]
    install: Callable[[Context], None]


COMPONENTS = {
    "zlint": Component("zlint", "ZLint (certificate linter)", zlint_current, install_zlint),
    "log_list": Component("log_list", "Certificate Transparency log list", log_list_current, install_log_list),
}


def _component_list(values: list | None) -> list:
    names = []
    for value in values or []:
        for name in value.replace(",", " ").split():
            name = COMPONENT_ALIASES.get(name.lower(), name.lower())
            if name in OBSOLETE_COMPONENTS:
                continue
            if name not in COMPONENT_NAMES:
                raise argparse.ArgumentTypeError(f"unknown component '{name}' (choose from: {', '.join(COMPONENT_NAMES)})")
            names.append(name)
    return names


def select_components(only: list | None, skip: list | None) -> list:
    chosen = _component_list(only) or list(COMPONENT_NAMES)
    skipped = set(_component_list(skip))
    return [name for name in COMPONENT_NAMES if name in chosen and name not in skipped]


def parse_args(argv: list | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="install_tools.py",
        description="Install (or check) ZLint and the CT log list of DigitalCertiAnalytics, inside the project "
                    "folder.")
    parser.add_argument("--check", action="store_true", help="only show the status of every component")
    parser.add_argument("--only", action="append", metavar="NAMES",
                        help="handle only these components (comma-separated: zlint, log_list)")
    parser.add_argument("--skip", action="append", metavar="NAMES",
                        help="leave out these components, e.g. --skip zlint when you set DCA_ZLINT_PATH")
    parser.add_argument("--force", action="store_true",
                        help="reinstall ZLint even if it is installed; the CT log list is downloaded "
                             "again only when log_list is named with --only")
    parser.add_argument("--project-dir", type=Path, default=PROJECT_DIR, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        args.components = select_components(args.only, args.skip)
        args.forced = forced_components(args.force, args.components, args.only)
    except argparse.ArgumentTypeError as error:
        parser.error(str(error))
    return args


# A valid CT log list is replaced only when asked by name: the project's list has logs Google's list no longer has
FORCED_ONLY_BY_NAME = ("log_list",)


def forced_components(force: bool, components: list, only: list | None) -> frozenset:
    """The components that --force reinstalls."""
    if not force:
        return frozenset()
    named = set(_component_list(only))
    return frozenset(name for name in components if name not in FORCED_ONLY_BY_NAME or name in named)


def _reexec_in_venv(layout: Layout, argv: list) -> int | None:
    """Run again with the project's .venv Python when started with another one, so the checks see the .venv."""
    python = layout.venv_python
    if running_in_venv(layout) or not python.is_file() or os.environ.get("DCA_INSTALL_TOOLS_REEXEC") == "1":
        return None
    env = dict(os.environ, DCA_INSTALL_TOOLS_REEXEC="1")
    try:
        return subprocess.run([str(python), str(Path(__file__).resolve()), *argv], env=env).returncode
    except OSError:
        return None


def prepare_project(ctx: Context) -> None:
    """Restore the exec bits lost by ZIP downloads, and build matplotlib's font cache now rather than at the first chart."""
    if not ctx.layout.windows:
        for name in ("dca", "dca.command", "install.sh", "install.command"):
            path = ctx.layout.root / name
            if path.is_file():
                path.chmod(path.stat().st_mode | 0o111)
    if running_in_venv(ctx.layout):
        if not (ctx.layout.cache / "matplotlib").is_dir():
            # It reads every font of the computer, which can take a while: say what is going on
            ctx.ui.line()
            ctx.ui.detail("Preparing the fonts for the charts (only the first time, it can take a minute)...")
        env = dict(os.environ, MPLCONFIGDIR=str(ctx.layout.cache / "matplotlib"), MPLBACKEND="Agg")
        result = run([sys.executable, "-c", "import matplotlib.pyplot"], timeout=600, env=env)
        if result.returncode != 0:
            ctx.ui.warn("matplotlib (used for the charts) does not load:\n" + tail(result.stderr, 6), REINSTALL_HINT)


def _quoted(path: Path) -> str:
    text = str(path)
    return f'"{text}"' if " " in text else text


def print_next_steps(ctx: Context, success: bool) -> None:
    ui, layout = ctx.ui, ctx.layout
    launcher = _quoted(layout.launcher)
    installer = _quoted(layout.root / ("install.bat" if layout.windows else "install.sh"))
    ui.line()
    if not success:
        ui.line(ui.paint("Some parts are not installed yet (see the messages above).", "fail"))
        ui.line(f"Fix what is suggested, then run the installer again ({installer}): it continues where it stopped.")
        return
    ui.line(ui.paint("DigitalCertiAnalytics is installed.", "ok"))
    ui.line()
    if layout.windows:
        # A quoted path followed by options is not a command in PowerShell: the commands are given for the folder
        ui.line(f"To start the program, double-click dca.bat in the project folder ({layout.root}),")
        ui.line("or open a terminal in that folder (see INSTALL.md, step 5) and type:")
        commands = ("dca.bat", "install.bat")
    else:
        ui.line("To start the program, open a terminal and run:")
        commands = (launcher, installer)
    ui.line(f"    {commands[0]} --help                 show all the options")
    ui.line(f"    {commands[0]} --leaf_analysis        analyse the leaf certificates of res/certs_polito.json")
    ui.line(f"    {commands[0]} --plot_all_results     create the charts")
    if layout.windows:
        ui.line("In PowerShell, type .\\dca.bat instead of dca.bat.")
    elif ctx.platform.system == "macos":
        ui.line("On macOS you can also double-click dca.command in the project folder.")
    ui.line()
    ui.line(f"Put the ZGrab2 scan file here first:  {layout.scan_file}")
    ui.line(f"Compress it to save disk space:       {commands[0]} --compress_input")
    ui.line(f"Check the installation at any time:   {commands[1]} --check")
    ui.line(f"To uninstall, delete the folder:       {layout.root}")


def install(ctx: Context, components: list) -> int:
    ui = ctx.ui
    ui.line(f"Installing the tools of DigitalCertiAnalytics in {ctx.layout.tools}")
    ui.line(f"Computer: {ctx.platform.describe()}")
    failed = []
    for name in components:
        component = COMPONENTS[name]
        ui.step(component.title)
        try:
            current = None if name in ctx.forced else component.current(ctx)
            if current:
                ui.ok(f"already installed: {current}")
                continue
            component.install(ctx)
        except InstallError as error:
            ui.fail(error.message, error.hint)
            failed.append(name)
    prepare_project(ctx)
    ui.step("Disk space used by the installation")
    prune_python(ctx)
    # With the older prebuilt ZLint the exact build is still to be done: its Go archive is kept for the next run
    remove_leftovers(ctx, success=not failed and component_entry(ctx, "zlint").get("source") != "prebuilt")
    ui.ok(check_footprint(ctx).detail)
    ui.step("Summary")
    rows = check_all(ctx, components)
    print_status_table(ui, rows)
    success = not failed and all(row.state != "fail" for row in rows)
    print_next_steps(ctx, success)
    return 0 if success else 1


def run_check(ctx: Context, components: list) -> int:
    ctx.ui.line(f"DigitalCertiAnalytics in {ctx.layout.root} - {ctx.platform.describe()}")
    ctx.ui.line()
    rows = check_all(ctx, components)
    print_status_table(ctx.ui, rows)
    failed = [row.name for row in rows if row.state == "fail"]
    ctx.ui.line()
    if failed:
        ctx.ui.line(ctx.ui.paint(f"Not ready: {', '.join(failed)}. Run the installer again to repair.", "fail"))
        return 1
    ctx.ui.line(ctx.ui.paint("Everything needed is ready.", "ok"))
    return 0


def main(argv: list | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = parse_args(argv)
    layout = Layout(args.project_dir.resolve())
    status = _reexec_in_venv(layout, argv)
    if status is not None:
        return status
    ui = Ui()
    ctx = Context(layout, detect_platform(), ui, load_manifest(layout), forced=args.forced)
    if args.check:
        return run_check(ctx, args.components)
    ui.open_log(layout.tools / "install.log")
    try:
        return install(ctx, args.components)
    except KeyboardInterrupt:
        ui.line()
        ui.fail("The installation was interrupted.", RUN_AGAIN)
        return 130
    except Exception as error:  # The user gets a clear message, and the details go to the log
        ui.fail(f"Unexpected error: {error}", "Run the installer again. If the error comes back, report it together "
                f"with the file {layout.tools / 'install.log'}.")
        ui.log_only(traceback.format_exc())
        return 1
    finally:
        ui.close_log()


if __name__ == "__main__":
    sys.exit(main())
