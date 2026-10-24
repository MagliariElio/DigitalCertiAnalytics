#!/usr/bin/env python3
"""Install and check the external tools of DigitalCertiAnalytics.

install.sh (macOS, Linux) and install.ps1 (Windows) set up uv, Python 3.12 and the project's .venv, then run this
script with the .venv Python. It installs, inside the project folder only:

- zlint:     ZLint, built from the exact commit the analysis uses (.tools/zlint);
- mongodb:   a portable MongoDB server (.tools/mongodb), which the program starts by itself when it needs it;
- log_list:  the Certificate Transparency log list res/log_list.json, only when the file is missing or damaged
             (a valid list is kept, also with --force, unless log_list is named with --only).

Every download is pinned to an exact version and verified with SHA-256 (the log list with Google's signature).
Running the script again is safe: what is installed is skipped and what is broken is repaired.

    install_tools.py                  install everything
    install_tools.py --check          show the status of every component
    install_tools.py --skip mongodb   e.g. when a MongoDB server already runs on localhost:27017

It uses the Python standard library only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import importlib.metadata
import io
import json
import os
import platform
import posixpath
import re
import shutil
import socket
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

# ZLint has no release for the commit the analysis uses, so it is built with Go, which is then removed
ZLINT_COMMIT = "989baefda32f5d50969ceafacc6d54215e28cc7b"
ZLINT_VERSION = "v3.6.5-0.20241104164204-989baefda32f"  # Go pseudo-version of the commit, printed by `zlint -version`
ZLINT_PACKAGE = "github.com/zmap/zlint/v3/cmd/zlint"

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
# The build is reproducible: Go 1.27.2 with the flags used here gives these binaries (a mismatch is only a warning)
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

# MongoDB 8.0 (LTS) is supported by pymongo 4.10.1; 7.0 only where 8.0 has no build. 8.0 data cannot be opened by 7.0.
MONGODB_VERSION = "8.0.34"
MONGODB_FALLBACK_VERSION = "7.0.45"
MONGODB_DOWNLOADS = "https://fastdl.mongodb.org"
MONGODB_SHA256 = {
    MONGODB_VERSION: {
        "macos-arm64": "3255cbf2e70cc5de04220046e006067d20068656d1bfa674828768a51d20d5a6",
        "macos-x86_64": "3d391b8c41df069671afaa88ca21def057178aecce1813437539143b71f28152",
        "windows-x86_64": "6b021a0864494e4decf278b36477a29eb36072432773e4e62c2f42c302630db0",
        "linux-x86_64-ubuntu2404": "3e55cdcf7013fbc805d29d8195230df4b23c7688733ee15ad58ac6bc2a416611",
        "linux-aarch64-ubuntu2404": "52655dd90adf0dbcbb87011075233285f44e262048ea30a9a48ad2a834c67736",
        "linux-x86_64-ubuntu2204": "8eef2a821651ac20f732b6636731a51b407675674ced8d7f1f1578ebc7aced43",
        "linux-aarch64-ubuntu2204": "fe918ca853000d5b48fcd3b2bc6119c72f4aab9e2b04a9a10e42923cb3aef6a4",
        "linux-x86_64-ubuntu2004": "f85e7aafabc52231e00ac05762e5a612f0a8e120364ab0d73a43ad00cade5ba3",
        "linux-aarch64-ubuntu2004": "35db4afa4fa391b6d19a009f8f73425eb284512f9931259386cbf060a3185b6b",
        "linux-x86_64-debian12": "0e869e044162d101d4ee468e89bc139628c4c9e041bdcdaec19bf99331827215",
        "linux-x86_64-rhel8": "675c97f72f57d64d177006f82aabccda68730ed7a13e7c27d4244cfa1cf729e8",
        "linux-aarch64-rhel8": "d34edb8e846c284983f6e62321bb624c82d27ebc58895b4bb84a2535a8d9b7b9",
        "linux-x86_64-rhel93": "6caa90892d5b3693789d1955761237ac686ac0a8b7bede201aacc25dc20be677",
        "linux-aarch64-rhel93": "f13892a11eb5b38ecb45b8079edb7b77f9724b63873c3a34f7fd4d6fa0d12f94",
        "linux-x86_64-rhel10": "e35cc984522d24b922b0c7d3d1c81bee99060a72adf5e1820b312e9cbb23bdd8",
        "linux-aarch64-rhel10": "91ab354eed1859ca3e768c27b91c8a653c0f4b255fb82c3e45bab2f2422986b7",
        "linux-x86_64-amazon2023": "b9fe750304de8a2f9e7f1c306e92c718a4c22d0c22d9c5ba20c8ab8426e899f7",
        "linux-aarch64-amazon2023": "eee86a2859ea1d2ea639395e47c1c843001a394db418d888373fe6d333ce53e9",
        "linux-x86_64-suse15": "3d3b418c180318bdaf20221820fde72a858333cbccd926bfe49b271cc55fb2a3",
    },
    MONGODB_FALLBACK_VERSION: {
        "macos-arm64": "23fa267630e47fb8b95935a4bbb6fed5f43f313735b6e17fe55cacce98403deb",
        "macos-x86_64": "f9fb2104e7eb525b48b61f7e5ab8af2b2172b031fded1a7f2c5be1b487a20b1a",
        "linux-x86_64-debian11": "299e78c177105e137ada530f2fe310d2301733a4953be4394c295644f3848f93",
        "linux-x86_64-amazon2": "e2281a165fa631b88cdf94332d047280a47359152e7971d2f90fa63f716424c4",
        "linux-aarch64-amazon2": "61add15c8bbb0a1ccbab22305b81e2399da8b26687698012acf7402643da6f7f",
        "linux-x86_64-rhel70": "97919a007c497875a74bfcf111f8bc39984895ce538bc9340bce60cb3855ebf8",
        "linux-x86_64-suse12": "ac6c30ed40afd374b039eea85201104b49392951030f0164d8acd649ee845179",
    },
}
# The Windows zip is 808 MB, mostly debug files: only mongod.exe is read from it, with HTTP Range requests
MONGOD_EXE_SHA256 = {
    (MONGODB_VERSION, "windows-x86_64"): "4c9e9764cbac5be8eb92733e23ce7f70b52f8ae84b6879b4d5cc010c90ec6082",
}
MONGODB_INSTALL_DOCS = "https://www.mongodb.com/docs/manual/administration/install-community/"
VC_RUNTIME_URL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
VC_RUNTIME_DLLS = ("msvcp140.dll", "msvcp140_1.dll", "vcruntime140.dll", "vcruntime140_1.dll")

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
RANGE_BLOCK_SIZE = 4 << 20          # Bytes fetched per HTTP Range request
GO_BUILD_TIMEOUT = 1800
GB = 1 << 30
MB = 1 << 20
SPACE_FOR_GO_BUILD = int(1.0 * GB)  # Go toolchain, modules and build cache, removed after the build
SPACE_FOR_MONGODB = int(0.5 * GB)   # Archive and the extracted server
SPACE_FOR_MONGODB_ZIP = int(1.9 * GB)
RECOMMENDED_FREE_SPACE = 100 * GB   # The scan file can be 80 GB, and the SQLite databases need space too

NETWORK_ERRORS = (urllib.error.URLError, http.client.HTTPException, OSError, ValueError)
PROCESS_TIMED_OUT = -1001
PROCESS_NOT_STARTED = -1002

COMPONENT_NAMES = ("zlint", "mongodb", "log_list")
COMPONENT_ALIASES = {"log-list": "log_list", "loglist": "log_list", "mongo": "mongodb", "mongod": "mongodb"}

RUN_AGAIN = "Run the installer again: it continues where it stopped."
NETWORK_HINT = ("Check your internet connection, then run the installer again: it continues where it stopped. "
                "Behind a proxy, set HTTPS_PROXY (for example HTTPS_PROXY=http://proxy.example.org:8080).")
CERTIFICATE_HINT = ("The secure connection could not be verified. On a company or university network that inspects "
                    "traffic, set SSL_CERT_FILE to the file of your organisation's certificates and run the installer "
                    "again.")
MONGODB_ALTERNATIVE = ("Everything else works. Only the ZLint checks (--leaf_zlint_check, --intermediate_zlint_check) "
                       "need MongoDB: install MongoDB yourself (" + MONGODB_INSTALL_DOCS + ") and keep it running on "
                       "localhost:27017, and the program uses it automatically.")


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
    def mongodb_dir(self) -> Path:
        return self.tools / "mongodb"

    @property
    def mongod(self) -> Path:
        return self.mongodb_dir / "bin" / self.exe("mongod")

    @property
    def mongodb_data(self) -> Path:
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


class RangeNotSupported(Exception):
    """The server does not answer HTTP Range requests."""


class HttpRangeReader(io.RawIOBase):
    """Read-only, seekable view of a remote file, fetched in blocks with HTTP Range requests.

    zipfile reads only the central directory and the members it extracts, so one file of a large zip archive can be
    downloaded without the rest.
    """

    def __init__(self, url: str, size: int, block_size: int = RANGE_BLOCK_SIZE):
        super().__init__()
        self.url, self.size, self.block_size = url, size, block_size
        self.position = 0
        self.block_start = 0
        self.block = b""
        self.requests = 0
        self.fetched = 0
        self.on_fetch: Callable[[int], None] | None = None

    @classmethod
    def open(cls, url: str, block_size: int = RANGE_BLOCK_SIZE) -> "HttpRangeReader":
        with _urlopen(url, {"Range": "bytes=0-0"}) as response:
            content_range = response.headers.get("Content-Range", "") or ""
            response.read()
            match = re.fullmatch(r"bytes 0-0/(\d+)", content_range.strip())
            if _response_status(response) != 206 or not match:
                raise RangeNotSupported(url)
        return cls(url, int(match.group(1)), block_size)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self.position, io.SEEK_END: self.size}[whence]
        self.position = max(0, base + offset)
        return self.position

    def readinto(self, buffer) -> int:
        """Fill the buffer up to the end of the file: zipfile reads its headers with a single read() and does not
        retry a short one, so a read that crosses a block boundary continues in the next block."""
        view = memoryview(buffer).cast("B")
        filled = 0
        while filled < len(view) and self.position < self.size:
            if not self.block_start <= self.position < self.block_start + len(self.block):
                self._load(self.position)
            offset = self.position - self.block_start
            data = self.block[offset:offset + len(view) - filled]
            view[filled:filled + len(data)] = data
            filled += len(data)
            self.position += len(data)
        return filled

    def _load(self, start: int) -> None:
        end = min(start + self.block_size, self.size) - 1
        errors = []
        for attempt in range(len(RETRY_DELAYS) + 1):
            try:
                with _urlopen(self.url, {"Range": f"bytes={start}-{end}"}) as response:
                    if _response_status(response) != 206:
                        raise RangeNotSupported(self.url)
                    data = response.read()
                if len(data) != end - start + 1:
                    raise OSError(f"received {len(data)} bytes instead of {end - start + 1}")
                break
            except NETWORK_ERRORS as error:
                errors.append(_describe_error(error))
                _pause_before_retry(attempt)
        else:
            raise OSError(f"could not read {self.url}: {errors[-1]}")
        self.requests += 1
        self.fetched += len(data)
        self.block_start, self.block = start, data
        if self.on_fetch is not None:
            self.on_fetch(self.fetched)


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


def select_mongod(member: str) -> str | None:
    """Selector keeping only bin/mongod[.exe] of a MongoDB archive, whatever its top folder is called."""
    match = re.search(r"(?:^|/)bin/(mongod(?:\.exe)?)$", member.replace("\\", "/"))
    return f"bin/{match.group(1)}" if match else None


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
    if source == "go-build" and go_version == GO_VERSION:
        reference = ZLINT_BUILD_SHA256.get((ctx.platform.system, ctx.platform.arch))
    if reference and digest != reference:
        ctx.ui.warn("The ZLint program differs from the reference build (it can happen with another Go setup); its "
                    "version is the right one, so it is used.")
    entry = {"status": "installed", "version": version, "source": source, "path": relative_to_tools(ctx.layout, binary),
             "sha256": digest}
    if source == "go-build":
        entry.update(commit=ZLINT_COMMIT, go=go_version, reference_build=digest == reference)
    set_component(ctx, "zlint", entry)
    ctx.ui.ok(f"ZLint {version} installed in {binary}")


def build_zlint(ctx: Context) -> None:
    layout, ui = ctx.layout, ctx.ui
    go_version, name, digest = go_toolchain_for(ctx.platform)
    ensure_free_space(layout.tools, SPACE_FOR_GO_BUILD, "building ZLint")
    ui.detail("ZLint is built from its source code with Go, which is removed afterwards (about 170 MB to download).")
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


def install_zlint(ctx: Context) -> None:
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
# MongoDB: choosing the build
# ---------------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class MongoBuild:
    version: str
    key: str                  # e.g. 'macos-arm64', 'windows-x86_64', 'linux-x86_64-ubuntu2404'
    url: str
    sha256: str               # Of the archive
    mongod_sha256: str = ""   # Of mongod.exe inside the Windows zip, which is not downloaded whole
    official: bool = True     # False when MongoDB does not list this build for the system, but it should run

    @property
    def filename(self) -> str:
        return self.url.rsplit("/", 1)[-1]


def mongo_build(version: str, key: str, official: bool = True) -> MongoBuild:
    sha256 = MONGODB_SHA256[version][key]
    if key.startswith("macos-"):
        url = f"{MONGODB_DOWNLOADS}/osx/mongodb-{key}-{version}.tgz"
    elif key.startswith("windows-"):
        url = f"{MONGODB_DOWNLOADS}/windows/mongodb-{key}-{version}.zip"
    else:
        url = f"{MONGODB_DOWNLOADS}/linux/mongodb-{key}-{version}.tgz"
    return MongoBuild(version, key, url, sha256, MONGOD_EXE_SHA256.get((version, key), ""), official)


DISTRO_FAMILIES = (
    ("nixos", {"nixos"}),
    ("amazon", {"amzn"}),
    ("fedora", {"fedora"}),
    ("rhel", {"rhel", "centos", "rocky", "almalinux", "ol", "circle", "eurolinux", "navy", "scientific"}),
    ("suse", {"sles", "sled", "opensuse-leap", "suse", "opensuse"}),
    ("ubuntu", {"ubuntu"}),
    ("debian", {"debian", "raspbian"}),
)
UBUNTU_CODENAMES = {
    "bionic": (18, 4), "focal": (20, 4), "groovy": (20, 10), "hirsute": (21, 4), "impish": (21, 10),
    "jammy": (22, 4), "kinetic": (22, 10), "lunar": (23, 4), "mantic": (23, 10), "noble": (24, 4),
}
DEBIAN_CODENAMES = {"buster": 10, "bullseye": 11, "bookworm": 12, "trixie": 13, "forky": 14}


def distro_family(os_release: dict) -> str:
    """'ubuntu', 'debian', 'rhel', 'fedora', 'amazon', 'suse', 'nixos' or 'unknown', from ID first, then ID_LIKE."""
    candidates = [os_release.get("ID", "").lower()] + os_release.get("ID_LIKE", "").lower().split()
    for candidate in candidates:
        for family, members in DISTRO_FAMILIES:
            if candidate in members:
                return family
    return "unknown"


def _major(text: str) -> int | None:
    version = parse_version(text)
    return version[0] if version else None


def _ubuntu_version(os_release: dict) -> tuple | None:
    """Ubuntu's (major, minor); derivatives (Mint, Pop!_OS, ...) are mapped through UBUNTU_CODENAME."""
    if os_release.get("ID", "").lower() == "ubuntu":
        version = parse_version(os_release.get("VERSION_ID", ""))
        if len(version) >= 2:
            return version[:2]
    codename = (os_release.get("UBUNTU_CODENAME") or os_release.get("VERSION_CODENAME") or "").lower()
    return UBUNTU_CODENAMES.get(codename)  # None: a release newer than this table


def _ubuntu_targets(os_release: dict, arch: str) -> list:
    version = _ubuntu_version(os_release)
    if version is None or version >= (24, 4):
        return [(MONGODB_VERSION, "ubuntu2404", True)]
    if version >= (22, 4):
        return [(MONGODB_VERSION, "ubuntu2204", True)]
    if version >= (20, 4):
        return [(MONGODB_VERSION, "ubuntu2004", True)]
    return []


def _debian_major(os_release: dict) -> int:
    if os_release.get("ID", "").lower() == "debian" and _major(os_release.get("VERSION_ID", "")):
        return _major(os_release["VERSION_ID"])
    codename = os_release.get("VERSION_CODENAME", "").lower()
    return DEBIAN_CODENAMES.get(codename, 13)  # Testing, unstable and rolling derivatives: like the newest release


def _debian_targets(os_release: dict, arch: str) -> list:
    major = _debian_major(os_release)
    if major >= 12 and arch == "x86_64":
        return [(MONGODB_VERSION, "debian12", major == 12)] + ([(MONGODB_VERSION, "ubuntu2404", False)] if major > 12 else [])
    if major >= 12:
        return [(MONGODB_VERSION, "ubuntu2204" if major == 12 else "ubuntu2404", False)]
    if major == 11 and arch == "x86_64":
        return [(MONGODB_FALLBACK_VERSION, "debian11", True)]
    return []


def _rhel_targets(os_release: dict, arch: str) -> list:
    major = _major(os_release.get("VERSION_ID", ""))
    targets = {8: "rhel8", 9: "rhel93", 10: "rhel10"}
    if major in targets:
        return [(MONGODB_VERSION, targets[major], True)]
    if major == 7 and arch == "x86_64":
        return [(MONGODB_FALLBACK_VERSION, "rhel70", True)]
    if major and major > 10:
        return [(MONGODB_VERSION, "rhel10", False)]
    return []


def _fedora_targets(os_release: dict, arch: str) -> list:
    return [(MONGODB_VERSION, "rhel93", False), (MONGODB_VERSION, "rhel10", False)]


def _amazon_targets(os_release: dict, arch: str) -> list:
    version = os_release.get("VERSION_ID", "")
    if version.startswith("2023"):
        return [(MONGODB_VERSION, "amazon2023", True)]
    if version == "2":
        return [(MONGODB_FALLBACK_VERSION, "amazon2", True)]
    return []


def _suse_targets(os_release: dict, arch: str) -> list:
    major = _major(os_release.get("VERSION_ID", ""))
    if major == 15:
        return [(MONGODB_VERSION, "suse15", True)]
    if major == 12:
        return [(MONGODB_FALLBACK_VERSION, "suse12", True)]
    return _unknown_targets(os_release, arch)  # e.g. openSUSE Tumbleweed


def _unknown_targets(os_release: dict, arch: str) -> list:
    # No official build (Arch, Manjaro, Gentoo, Void, ...): the RHEL 9 build needs only common libraries
    return [(MONGODB_VERSION, "rhel93", False), (MONGODB_VERSION, "ubuntu2204", False)]


def _nixos_targets(os_release: dict, arch: str) -> list:
    return []  # No standard dynamic loader: generic binaries do not run


LINUX_TARGETS = {"ubuntu": _ubuntu_targets, "debian": _debian_targets, "rhel": _rhel_targets,
                 "fedora": _fedora_targets, "amazon": _amazon_targets, "suse": _suse_targets,
                 "nixos": _nixos_targets, "unknown": _unknown_targets}


def linux_mongodb_targets(os_release: dict, arch: str) -> list:
    """The MongoDB Linux builds to try, best first, as (version, target, official) with arch 'x86_64' or 'aarch64'."""
    return LINUX_TARGETS[distro_family(os_release)](os_release, arch)


def _linux_candidates(plat: PlatformInfo) -> tuple:
    if plat.libc == "musl":
        return [], "MongoDB has no build for Linux distributions based on musl, such as Alpine"
    arch = {"x86_64": "x86_64", "arm64": "aarch64"}.get(plat.arch)
    if arch is None:
        return [], f"MongoDB has no build for {plat.arch} processors"
    builds = []
    for version, target, official in linux_mongodb_targets(plat.os_release, arch):
        key = f"linux-{arch}-{target}"
        if key in MONGODB_SHA256[version]:
            builds.append(mongo_build(version, key, official))
    return builds, "" if builds else f"MongoDB has no build that runs on {plat.describe()}"


def _macos_candidates(plat: PlatformInfo) -> tuple:
    arch = "arm64" if plat.arch == "arm64" else "x86_64"
    if plat.mac_version >= (14,):
        return [mongo_build(MONGODB_VERSION, f"macos-{arch}")], ""
    minimum = (11,) if arch == "arm64" else (10, 14)
    if plat.mac_version >= minimum:
        return [mongo_build(MONGODB_FALLBACK_VERSION, f"macos-{arch}")], ""
    return [], f"MongoDB needs macOS {'.'.join(map(str, minimum))} or newer"


def _windows_candidates(plat: PlatformInfo) -> tuple:
    if plat.arch not in ("x86_64", "arm64"):
        return [], "MongoDB needs 64-bit Windows"
    if plat.arch == "arm64" and plat.windows_build < 22000:
        return [], ("MongoDB has no ARM build for Windows, and Windows 10 on ARM cannot run the x64 one "
                    "(Windows 11 can)")
    return [mongo_build(MONGODB_VERSION, "windows-x86_64")], ""


def mongodb_candidates(plat: PlatformInfo) -> tuple:
    """The MongoDB builds to try on this computer, best first, and the reason when there is none."""
    choosers = {"macos": _macos_candidates, "windows": _windows_candidates, "linux": _linux_candidates}
    if plat.system not in choosers:
        return [], f"MongoDB has no build for {plat.system}"
    return choosers[plat.system](plat)


def _linux_cpu_supported(arch: str, cpuinfo: str) -> tuple:
    if not cpuinfo:
        return True, ""
    flag_lines = [line.split(":", 1)[-1] for line in cpuinfo.splitlines()
                  if line.lower().startswith(("flags", "features"))]
    words = set(" ".join(flag_lines).split())
    if arch == "x86_64" and "avx" not in words:
        return False, "this processor has no AVX instructions, which MongoDB 5.0 and newer need (Intel 2011 or newer)"
    if arch == "arm64" and "atomics" not in words:
        return False, ("this ARM processor is older than ARMv8.2-A, which MongoDB 5.0 and newer need (a Raspberry "
                       "Pi 4 is too old, a Raspberry Pi 5 works)")
    return True, ""


def cpu_supports_mongodb(plat: PlatformInfo, cpuinfo: str | None = None, mac_features: str | None = None) -> tuple:
    """(True, '') when the processor can run MongoDB 5.0+ (or it cannot be told), else (False, reason)."""
    if plat.system == "linux":
        return _linux_cpu_supported(plat.arch, _read_text("/proc/cpuinfo") if cpuinfo is None else cpuinfo)
    if plat.system == "macos" and plat.arch == "x86_64":
        features = _sysctl("machdep.cpu.features") if mac_features is None else mac_features
        if features and "AVX1.0" not in features.split():
            return False, "this Mac's processor has no AVX instructions, which MongoDB 5.0 and newer need"
    if plat.system == "windows" and plat.arch == "x86_64" and not _windows_has_avx():
        return False, "this processor has no AVX instructions, which MongoDB 5.0 and newer need"
    return True, ""


def _windows_has_avx() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.kernel32.IsProcessorFeaturePresent(39))  # PF_AVX_INSTRUCTIONS_AVAILABLE
    except (AttributeError, OSError, ImportError):
        return True


def missing_vc_runtime(system_dir: Path | None = None) -> list:
    """The Visual C++ runtime DLLs mongod.exe needs that are not installed in Windows."""
    if system_dir is None:
        system_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    return [name for name in VC_RUNTIME_DLLS if not (system_dir / name).is_file()]


def _data_written_by(layout: Layout, ctx: Context) -> str | None:
    """The MongoDB version that wrote data/mongodb, if it has data."""
    if not (layout.mongodb_data / "WiredTiger").exists():
        return None
    version = component_entry(ctx, "mongodb").get("version") or ""
    if not version:
        version = _read_text(str(layout.mongodb_dir / "VERSION")).strip()
    return version or None


def guard_data_version(ctx: Context, builds: list, reason: str) -> tuple:
    """Never install a MongoDB older than the one that wrote the existing data: it would refuse to open it."""
    written_by = _data_written_by(ctx.layout, ctx)
    if not builds or not written_by:
        return builds, reason
    kept = [build for build in builds if _major(build.version) >= _major(written_by)]
    if kept:
        return kept, reason
    return [], (f"the database folder {ctx.layout.mongodb_data} was written by MongoDB {written_by}, which is newer "
                f"than the MongoDB this computer can run ({builds[0].version}), so it could not be opened. Move that "
                "folder somewhere else (or delete it if its ZLint results are no longer needed) and run the installer "
                "again")


# ---------------------------------------------------------------------------------------------------------------------
# MongoDB: installing and testing the build
# ---------------------------------------------------------------------------------------------------------------------

STATUS_ILLEGAL_INSTRUCTION = 0xC000001D
STATUS_DLL_NOT_FOUND = 0xC0000135


def mongod_version(binary: Path) -> tuple:
    """(version or None, CompletedProcess) of `mongod --version`."""
    result = run([binary, "--version"], timeout=60)
    match = re.search(r"db version v(\S+)", result.stdout)
    return (match.group(1) if result.returncode == 0 and match else None), result


def _library_hint(plat: PlatformInfo) -> str:
    family = distro_family(plat.os_release)
    if family in ("ubuntu", "debian"):
        return ("Install the missing system libraries with: sudo apt install libcurl4 openssl (on Ubuntu 24.04 and "
                "newer: sudo apt install libcurl4t64 openssl), then run the installer again.")
    if family in ("rhel", "fedora", "amazon"):
        return ("Install the missing system libraries with: sudo dnf install libcurl openssl xz-libs, then run the "
                "installer again.")
    if family == "suse":
        return ("Install the missing system libraries with: sudo zypper install libcurl4 libopenssl3, then run the "
                "installer again.")
    return ("Install the curl and OpenSSL 3 libraries with your package manager, then run the installer again. "
            + MONGODB_ALTERNATIVE)


def explain_mongod_failure(plat: PlatformInfo, result: subprocess.CompletedProcess) -> tuple:
    """(reason, hint) for a mongod that does not start."""
    output = (result.stderr or "") + (result.stdout or "")
    code = result.returncode
    if code in (-4, STATUS_ILLEGAL_INSTRUCTION, 132) or "Illegal instruction" in output:
        return "the processor lacks instructions MongoDB needs (AVX, or ARMv8.2-A on ARM)", MONGODB_ALTERNATIVE
    if code == STATUS_DLL_NOT_FOUND or "MSVCP140" in output.upper() or "VCRUNTIME140" in output.upper():
        return "the Microsoft Visual C++ runtime is missing", VC_RUNTIME_HINT
    library = re.search(r"error while loading shared libraries: (\S+?):", output)
    if library:
        return f"the system library {library.group(1)} is missing", _library_hint(plat)
    if re.search(r"(GLIBC|GLIBCXX|CURL_OPENSSL|OPENSSL)_[\d.]+' not found|version `[^']+' not found", output):
        return "the system libraries are too old or different from the ones MongoDB was built for", _library_hint(plat)
    if code == PROCESS_NOT_STARTED:
        return f"it cannot be started ({output.strip()})", explain_not_runnable(None)
    return f"it exits with code {code}:\n{tail(output, 6)}", MONGODB_ALTERNATIVE


VC_RUNTIME_HINT = ("MongoDB needs the Microsoft Visual C++ Redistributable (x64). Download it from " + VC_RUNTIME_URL
                   + " and run it (it asks once for administrator permission; ask your IT department on a managed "
                   "computer), then run install.bat again. " + MONGODB_ALTERNATIVE)


def explain_not_runnable(path: Path | None) -> str:
    where = f" ({path})" if path else ""
    return ("The program could not run" + where + ". The disk or folder may not allow running programs (a USB stick, a "
            "network share or a folder mounted with 'noexec'), or an antivirus blocked it. Move the project folder to "
            "your home folder and run the installer again.")


def _download_mongod_exe(ctx: Context, build: MongoBuild, dest: Path) -> None:
    """Read only mongod.exe from the 808 MB Windows zip, with HTTP Range requests; verify it."""
    reader = HttpRangeReader.open(build.url)
    part = dest.with_name(dest.name + ".part")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(reader) as zipped:
        info = next((item for item in zipped.infolist() if select_mongod(item.filename)), None)
        if info is None:
            raise InstallError("The MongoDB archive does not contain mongod.exe.", RUN_AGAIN)
        progress = Progress(ctx.ui, f"MongoDB {build.version} server", info.compress_size)
        reader.on_fetch = progress.update
        with zipped.open(info) as source, open(part, "wb") as writer:
            shutil.copyfileobj(source, writer, CHUNK_SIZE * 16)
        progress.finish(min(reader.fetched, info.compress_size))
    actual = file_sha256(part)
    if actual != build.mongod_sha256:
        part.unlink()
        raise InstallError(f"The downloaded mongod.exe did not match its expected SHA-256 checksum ({actual}), so it was "
                           "deleted.", "The file was damaged or changed on the way. Run the installer again.")
    os.replace(part, dest)


def _fetch_windows_mongod(ctx: Context, build: MongoBuild, staging: Path) -> None:
    target = staging / "bin" / "mongod.exe"
    ensure_free_space(staging, SPACE_FOR_MONGODB, "the MongoDB server")
    try:
        _download_mongod_exe(ctx, build, target)
        return
    except (RangeNotSupported, zipfile.BadZipFile, *NETWORK_ERRORS) as error:
        ctx.ui.detail(f"Partial download not possible ({_describe_error(error)}): downloading the whole archive "
                      f"(808 MB) instead.")
    ensure_free_space(staging, SPACE_FOR_MONGODB_ZIP, "the MongoDB archive")
    archive = download(ctx.ui, [build.url], ctx.layout.downloads / build.filename, build.sha256,
                       f"MongoDB {build.version} archive")
    extract_archive(archive, staging, select_mongod)
    archive.unlink(missing_ok=True)


def _fetch_mongod(ctx: Context, build: MongoBuild, staging: Path) -> Path:
    """Put the build's mongod in staging/bin and return its path."""
    remove_tree(staging)
    if build.mongod_sha256:
        _fetch_windows_mongod(ctx, build, staging)
    else:
        ensure_free_space(ctx.layout.tools, SPACE_FOR_MONGODB, "the MongoDB server")
        label = f"MongoDB {build.version} server" + ("" if build.official else " (generic build for this system)")
        archive = download(ctx.ui, [build.url], ctx.layout.downloads / build.filename, build.sha256, label)
        extract_archive(archive, staging, select_mongod)
        archive.unlink(missing_ok=True)
    binary = staging / "bin" / ctx.layout.exe("mongod")
    if not binary.is_file():
        raise InstallError("The MongoDB archive does not contain the mongod program.", RUN_AGAIN)
    return binary


def _activate_mongodb(ctx: Context, build: MongoBuild, staging: Path) -> None:
    layout = ctx.layout
    try:
        remove_tree(layout.mongodb_dir)
        os.replace(staging, layout.mongodb_dir)
    except OSError as error:
        raise InstallError(f"Could not replace the MongoDB server in {layout.mongodb_dir}: {error}.",
                           "The MongoDB server of this project may still be running: close the program (or restart the "
                           "computer) and run the installer again.") from error
    (layout.mongodb_dir / "VERSION").write_text(build.version + "\n", encoding="utf-8")
    layout.mongodb_data.mkdir(parents=True, exist_ok=True)
    set_component(ctx, "mongodb", {
        "status": "installed", "version": build.version, "build": build.key, "official_build": build.official,
        "url": build.url, "archive_sha256": build.sha256, "path": relative_to_tools(layout, layout.mongod),
        "sha256": file_sha256(layout.mongod)})
    ctx.ui.ok(f"MongoDB {build.version} server installed in {layout.mongodb_dir}")
    ctx.ui.detail("The program starts it by itself when needed (database files in data/mongodb).")


def _try_mongodb_build(ctx: Context, build: MongoBuild) -> tuple | None:
    """Install one build; None when it works, else (reason, hint) for why it does not run here."""
    staging = ctx.layout.tools / "mongodb.new"
    binary = _fetch_mongod(ctx, build, staging)
    version, result = mongod_version(binary)
    if version is None:
        remove_tree(staging)
        return explain_mongod_failure(ctx.platform, result)
    _activate_mongodb(ctx, build, staging)
    return None


def _mark_mongodb_unavailable(ctx: Context, reason: str, hint: str) -> None:
    previous = component_entry(ctx, "mongodb")
    if previous.get("status") == "installed" and ctx.layout.mongod.is_file():
        ctx.ui.warn(f"The bundled MongoDB server could not be updated: {reason}.", hint)
        return
    set_component(ctx, "mongodb", {"status": "unavailable", "reason": reason, "hint": hint})
    ctx.ui.warn(f"The MongoDB server cannot be installed on this computer: {reason}.", hint)


def _mongodb_plan(ctx: Context) -> tuple:
    builds, reason = mongodb_candidates(ctx.platform)
    builds, reason = guard_data_version(ctx, builds, reason)
    if builds:
        supported, cpu_reason = cpu_supports_mongodb(ctx.platform)
        if not supported:
            return [], cpu_reason
    return builds, reason


def mongodb_current(ctx: Context) -> str | None:
    entry = component_entry(ctx, "mongodb")
    if entry.get("status") != "installed" or not ctx.layout.mongod.is_file():
        return None
    builds, _ = _mongodb_plan(ctx)
    if not any(build.key == entry.get("build") and build.version == entry.get("version") for build in builds):
        return None
    if entry.get("sha256") != file_sha256(ctx.layout.mongod) or mongod_version(ctx.layout.mongod)[0] is None:
        return None
    return f"MongoDB {entry['version']} server"


def install_mongodb(ctx: Context) -> None:
    builds, reason = _mongodb_plan(ctx)
    if not builds:
        _mark_mongodb_unavailable(ctx, reason, MONGODB_ALTERNATIVE)
        return
    if ctx.platform.windows and missing_vc_runtime():
        ctx.ui.warn("The Microsoft Visual C++ runtime that MongoDB needs is not installed.", VC_RUNTIME_HINT)
    failures = []
    for build in builds:
        failure = _try_mongodb_build(ctx, build)
        if failure is None:
            return
        failures.append(failure)
        ctx.ui.detail(f"The {build.key} build does not run here: {failure[0]}.")
    _mark_mongodb_unavailable(ctx, failures[-1][0], failures[-1][1])


def mongodb_server_answers(host: str = "127.0.0.1", port: int = 27017, timeout: float = 1.0) -> bool:
    """Whether something (normally a MongoDB server) accepts connections on host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


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


def check_mongodb(ctx: Context) -> Status:
    layout = ctx.layout
    running = mongodb_server_answers()
    running_note = "; a MongoDB server is running now on localhost:27017" if running else ""
    if layout.mongod.is_file():
        version, result = mongod_version(layout.mongod)
        if version is not None:
            return Status("MongoDB", "ok", f"{version} (.tools/mongodb, started by the program when needed{running_note})")
        reason, hint = explain_mongod_failure(ctx.platform, result)
        return Status("MongoDB", "warn" if running else "fail", f"the bundled server does not start: {reason}"
                      + running_note, hint)
    if running:
        return Status("MongoDB", "ok", "a MongoDB server answers on localhost:27017 and is used by the program")
    entry = component_entry(ctx, "mongodb")
    if entry.get("status") == "unavailable":
        return Status("MongoDB", "warn", f"not available on this computer: {entry.get('reason')}",
                      entry.get("hint") or MONGODB_ALTERNATIVE)
    return Status("MongoDB", "fail", "not installed, and no MongoDB server answers on localhost:27017",
                  "Run the installer again, or start your own MongoDB server on localhost:27017.")


def check_log_list(ctx: Context) -> Status:
    count = log_list_logs(ctx.layout.log_list)
    if count is None:
        return Status("CT log list", "fail", "res/log_list.json is missing or damaged",
                      "Run the installer again: it downloads the list when the file is missing.")
    return Status("CT log list", "ok", f"res/log_list.json ({count} logs)")


def check_scan_file(ctx: Context) -> Status:
    path = ctx.layout.scan_file
    if path.is_file():
        return Status("Scan file", "ok", f"res/certs_polito.json ({path.stat().st_size / GB:.1f} GB)")
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
    hint = "" if state == "info" else ("A large scan (up to 80 GB) and its SQLite databases need much more space: "
                                       "free some, or move the project to a bigger disk.")
    return Status("Disk space", state, f"{available / GB:.0f} GB free", hint)


COMPONENT_CHECKS = {"zlint": check_zlint, "mongodb": check_mongodb, "log_list": check_log_list}


def check_all(ctx: Context, components: list) -> list:
    rows = [check_python(ctx), check_packages(ctx), check_sslyze(ctx)]
    rows += [COMPONENT_CHECKS[name](ctx) for name in COMPONENT_NAMES if name in components]
    rows += [check_launcher(ctx), check_scan_file(ctx), check_disk(ctx)]
    return rows


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
    "mongodb": Component("mongodb", "MongoDB server (stores the ZLint results)", mongodb_current, install_mongodb),
    "log_list": Component("log_list", "Certificate Transparency log list", log_list_current, install_log_list),
}


def _component_list(values: list | None) -> list:
    names = []
    for value in values or []:
        for name in value.replace(",", " ").split():
            name = COMPONENT_ALIASES.get(name.lower(), name.lower())
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
        description="Install (or check) ZLint, the MongoDB server and the CT log list of DigitalCertiAnalytics, "
                    "inside the project folder.")
    parser.add_argument("--check", action="store_true", help="only show the status of every component")
    parser.add_argument("--only", action="append", metavar="NAMES",
                        help="handle only these components (comma-separated: zlint, mongodb, log_list)")
    parser.add_argument("--skip", action="append", metavar="NAMES",
                        help="leave out these components, e.g. --skip mongodb when you already run MongoDB")
    parser.add_argument("--force", action="store_true",
                        help="reinstall ZLint and MongoDB even if they are installed; the CT log list is downloaded "
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
