"""Tests of scripts/install_tools.py: no network, no real ZLint, MongoDB or Go (local files and monkeypatching)."""
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.error
import zipfile
from pathlib import Path

import pytest

# Admin: Anuar Elio Magliari
# Politecnico di Torino

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "install_tools.py"
_spec = importlib.util.spec_from_file_location("install_tools", SCRIPT)
it = importlib.util.module_from_spec(_spec)
sys.modules["install_tools"] = it  # dataclasses look the module up while the classes are created
_spec.loader.exec_module(it)

posix_only = pytest.mark.skipif(os.name == "nt", reason="the fake programs are shell scripts")

MACOS_ARM = it.PlatformInfo("macos", "arm64", mac_version=(26, 6))
LINUX_X86 = it.PlatformInfo("linux", "x86_64", libc="glibc",
                            os_release={"ID": "ubuntu", "VERSION_ID": "24.04", "PRETTY_NAME": "Ubuntu 24.04 LTS"})


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    """No pauses between retries, no real sslyze, and no MongoDB server that happens to run on this computer."""
    monkeypatch.setattr(it, "RETRY_DELAYS", (0, 0, 0))
    monkeypatch.delenv("DCA_ZLINT_PATH", raising=False)
    monkeypatch.setattr(it, "check_sslyze", lambda ctx: it.Status("sslyze", "ok", "sslyze (not run by the tests)"))
    monkeypatch.setattr(it, "mongodb_server_answers", lambda: False)


@pytest.fixture
def project(tmp_path):
    """A minimal project folder."""
    (tmp_path / "res").mkdir()
    (tmp_path / "requirements.txt").write_text("rich==13.9.3\n")
    (tmp_path / "dca").write_text("#!/bin/sh\n")
    return tmp_path


def make_context(project, plat=LINUX_X86, manifest=None):
    layout = it.Layout(project, windows=False)
    return it.Context(layout, plat, it.Ui(io.StringIO(), color=False), manifest if manifest is not None else {})


def output_of(ctx):
    return ctx.ui.stream.getvalue()


def fake_program(path, output, code=0):
    """A shell script that prints `output` and exits with `code`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\necho '{output}'\nexit {code}\n")
    path.chmod(0o755)
    return path


def sha256(data):
    return hashlib.sha256(data).hexdigest()


# --- Platform and MongoDB build selection -----------------------------------------------------------------------------

def test_parse_os_release_handles_quotes_and_comments():
    text = '# comment\nID=ubuntu\nVERSION_ID="22.04"\nID_LIKE=\'debian\'\n\nBROKEN LINE\n'
    assert it.parse_os_release(text) == {"ID": "ubuntu", "VERSION_ID": "22.04", "ID_LIKE": "debian"}


@pytest.mark.parametrize("machine, expected", [("x86_64", "x86_64"), ("AMD64", "x86_64"), ("arm64", "arm64"),
                                               ("aarch64", "arm64"), ("armv7l", "armv7l")])
def test_normalize_arch(machine, expected):
    assert it.normalize_arch(machine) == expected


@pytest.mark.parametrize("plat, key, version", [
    (it.PlatformInfo("macos", "arm64", mac_version=(26, 6)), "macos-arm64", it.MONGODB_VERSION),
    (it.PlatformInfo("macos", "x86_64", mac_version=(14, 0)), "macos-x86_64", it.MONGODB_VERSION),
    (it.PlatformInfo("macos", "arm64", mac_version=(13, 6, 1)), "macos-arm64", it.MONGODB_FALLBACK_VERSION),
    (it.PlatformInfo("macos", "x86_64", mac_version=(10, 15)), "macos-x86_64", it.MONGODB_FALLBACK_VERSION),
    (it.PlatformInfo("windows", "x86_64", windows_build=19045), "windows-x86_64", it.MONGODB_VERSION),
    (it.PlatformInfo("windows", "arm64", windows_build=26100), "windows-x86_64", it.MONGODB_VERSION),
])
def test_mongodb_candidates_on_macos_and_windows(plat, key, version):
    builds, reason = it.mongodb_candidates(plat)
    assert reason == ""
    assert [(build.key, build.version) for build in builds] == [(key, version)]
    assert builds[0].sha256 == it.MONGODB_SHA256[version][key]


def test_windows_build_reads_only_mongod_exe():
    build = it.mongodb_candidates(it.PlatformInfo("windows", "x86_64", windows_build=22631))[0][0]
    assert build.url == "https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-8.0.34.zip"
    assert build.mongod_sha256 == "4c9e9764cbac5be8eb92733e23ce7f70b52f8ae84b6879b4d5cc010c90ec6082"


@pytest.mark.parametrize("plat", [
    it.PlatformInfo("macos", "x86_64", mac_version=(10, 13)),
    it.PlatformInfo("macos", "arm64", mac_version=(10, 16)),
    it.PlatformInfo("windows", "arm64", windows_build=19045),
    it.PlatformInfo("windows", "x86", windows_build=19045),
    it.PlatformInfo("linux", "x86_64", libc="musl", os_release={"ID": "alpine", "VERSION_ID": "3.20"}),
    it.PlatformInfo("linux", "x86_64", libc="glibc", os_release={"ID": "nixos"}),
    it.PlatformInfo("linux", "riscv64", libc="glibc", os_release={"ID": "ubuntu", "VERSION_ID": "24.04"}),
    it.PlatformInfo("freebsd14", "x86_64"),
])
def test_mongodb_candidates_explain_unsupported_systems(plat):
    builds, reason = it.mongodb_candidates(plat)
    assert builds == []
    assert reason


@pytest.mark.parametrize("os_release, arch, expected", [
    ({"ID": "ubuntu", "VERSION_ID": "24.04"}, "x86_64", ["8.0.34 linux-x86_64-ubuntu2404"]),
    ({"ID": "ubuntu", "VERSION_ID": "26.04"}, "arm64", ["8.0.34 linux-aarch64-ubuntu2404"]),
    ({"ID": "ubuntu", "VERSION_ID": "22.04"}, "arm64", ["8.0.34 linux-aarch64-ubuntu2204"]),
    ({"ID": "ubuntu", "VERSION_ID": "20.04"}, "x86_64", ["8.0.34 linux-x86_64-ubuntu2004"]),
    ({"ID": "linuxmint", "ID_LIKE": "ubuntu debian", "VERSION_ID": "21.3", "UBUNTU_CODENAME": "jammy"}, "x86_64",
     ["8.0.34 linux-x86_64-ubuntu2204"]),
    ({"ID": "pop", "ID_LIKE": "ubuntu debian", "VERSION_ID": "24.04", "UBUNTU_CODENAME": "noble"}, "x86_64",
     ["8.0.34 linux-x86_64-ubuntu2404"]),
    ({"ID": "debian", "VERSION_ID": "12"}, "x86_64", ["8.0.34 linux-x86_64-debian12"]),
    ({"ID": "debian", "VERSION_ID": "12"}, "arm64", ["8.0.34 linux-aarch64-ubuntu2204"]),
    ({"ID": "debian", "VERSION_ID": "13"}, "x86_64", ["8.0.34 linux-x86_64-debian12", "8.0.34 linux-x86_64-ubuntu2404"]),
    ({"ID": "debian", "VERSION_ID": "11"}, "x86_64", ["7.0.45 linux-x86_64-debian11"]),
    ({"ID": "kali", "ID_LIKE": "debian", "VERSION_ID": "2026.3"}, "x86_64",
     ["8.0.34 linux-x86_64-debian12", "8.0.34 linux-x86_64-ubuntu2404"]),
    ({"ID": "rhel", "VERSION_ID": "8.10"}, "x86_64", ["8.0.34 linux-x86_64-rhel8"]),
    ({"ID": "rocky", "ID_LIKE": "rhel centos fedora", "VERSION_ID": "9.4"}, "arm64", ["8.0.34 linux-aarch64-rhel93"]),
    ({"ID": "almalinux", "ID_LIKE": "rhel centos fedora", "VERSION_ID": "10.0"}, "x86_64", ["8.0.34 linux-x86_64-rhel10"]),
    ({"ID": "centos", "ID_LIKE": "rhel fedora", "VERSION_ID": "7"}, "x86_64", ["7.0.45 linux-x86_64-rhel70"]),
    ({"ID": "fedora", "VERSION_ID": "42"}, "x86_64", ["8.0.34 linux-x86_64-rhel93", "8.0.34 linux-x86_64-rhel10"]),
    ({"ID": "amzn", "ID_LIKE": "centos rhel fedora", "VERSION_ID": "2023"}, "arm64", ["8.0.34 linux-aarch64-amazon2023"]),
    ({"ID": "amzn", "ID_LIKE": "centos rhel fedora", "VERSION_ID": "2"}, "x86_64", ["7.0.45 linux-x86_64-amazon2"]),
    ({"ID": "sles", "VERSION_ID": "15.6"}, "x86_64", ["8.0.34 linux-x86_64-suse15"]),
    ({"ID": "sles", "VERSION_ID": "15.6"}, "arm64", []),
    ({"ID": "arch"}, "x86_64", ["8.0.34 linux-x86_64-rhel93", "8.0.34 linux-x86_64-ubuntu2204"]),
    ({"ID": "opensuse-tumbleweed", "ID_LIKE": "opensuse suse", "VERSION_ID": "20261020"}, "x86_64",
     ["8.0.34 linux-x86_64-rhel93", "8.0.34 linux-x86_64-ubuntu2204"]),
])
def test_linux_mongodb_candidates(os_release, arch, expected):
    builds, reason = it.mongodb_candidates(it.PlatformInfo("linux", arch, libc="glibc", os_release=os_release))
    assert [f"{build.version} {build.key}" for build in builds] == expected
    assert bool(reason) == (not expected)
    for build in builds:
        target = build.key.split("-", 2)[2]
        assert build.url == f"https://fastdl.mongodb.org/linux/mongodb-{build.key}-{build.version}.tgz"
        assert len(build.sha256) == 64 and target in build.url


def test_every_pinned_mongodb_build_has_a_valid_url_and_hash():
    for version, builds in it.MONGODB_SHA256.items():
        for key, digest in builds.items():
            build = it.mongo_build(version, key)
            assert build.url.startswith("https://fastdl.mongodb.org/") and version in build.filename
            assert len(digest) == 64 and int(digest, 16) >= 0


@pytest.mark.parametrize("plat, name", [
    (it.PlatformInfo("macos", "arm64"), "go1.27.2.darwin-arm64.tar.gz"),
    (it.PlatformInfo("macos", "x86_64"), "go1.27.2.darwin-amd64.tar.gz"),
    (it.PlatformInfo("linux", "x86_64"), "go1.27.2.linux-amd64.tar.gz"),
    (it.PlatformInfo("linux", "arm64"), "go1.27.2.linux-arm64.tar.gz"),
    (it.PlatformInfo("windows", "x86_64"), "go1.27.2.windows-amd64.zip"),
    (it.PlatformInfo("windows", "arm64"), "go1.27.2.windows-arm64.zip"),
])
def test_go_toolchain_for_every_supported_platform(plat, name):
    assert it.go_toolchain_for(plat)[:2] == (it.GO_VERSION, name)
    assert (plat.system, plat.arch) in it.ZLINT_BUILD_SHA256


@pytest.mark.parametrize("mac_version, arch, name", [
    ((12, 7, 6), "arm64", "go1.24.13.darwin-arm64.tar.gz"),
    ((11, 0), "x86_64", "go1.24.13.darwin-amd64.tar.gz"),
    ((13, 0), "arm64", "go1.27.2.darwin-arm64.tar.gz"),
])
def test_go_toolchain_for_older_macos(mac_version, arch, name):
    # Go 1.27 needs macOS 13; Go 1.24 is the last release for macOS 11 and 12
    version, archive, digest = it.go_toolchain_for(it.PlatformInfo("macos", arch, mac_version=mac_version))
    assert archive == name and version in name and len(digest) == 64


def test_go_toolchain_for_unsupported_platform_explains():
    with pytest.raises(it.InstallError, match="cannot be built"):
        it.go_toolchain_for(it.PlatformInfo("linux", "riscv64"))
    with pytest.raises(it.InstallError, match="macOS 11 or newer"):
        it.go_toolchain_for(it.PlatformInfo("macos", "x86_64", mac_version=(10, 15, 7)))


def test_prebuilt_zlint_fallback_only_where_it_can_run(monkeypatch):
    assert it.prebuilt_zlint_available(it.PlatformInfo("linux", "x86_64"))
    assert it.prebuilt_zlint_available(it.PlatformInfo("windows", "arm64"))  # Windows 11 runs x64 programs
    assert not it.prebuilt_zlint_available(it.PlatformInfo("linux", "arm64"))
    monkeypatch.setattr(it, "rosetta_installed", lambda: True)
    assert it.prebuilt_zlint_available(it.PlatformInfo("macos", "arm64"))
    monkeypatch.setattr(it, "rosetta_installed", lambda: False)
    assert not it.prebuilt_zlint_available(it.PlatformInfo("macos", "arm64"))  # An Intel program needs Rosetta


@pytest.mark.parametrize("arch, cpuinfo, supported", [
    ("x86_64", "flags\t\t: fpu vme sse sse2 avx avx2\n", True),
    ("x86_64", "flags\t\t: fpu vme sse sse2 sse4_2\n", False),
    ("arm64", "Features\t: fp asimd evtstrm aes atomics\n", True),
    ("arm64", "Features\t: fp asimd evtstrm crc32\n", False),
    ("x86_64", "", True),  # Unknown: the start of mongod decides
])
def test_cpu_check_on_linux(arch, cpuinfo, supported):
    assert it.cpu_supports_mongodb(it.PlatformInfo("linux", arch), cpuinfo=cpuinfo)[0] is supported


def test_cpu_check_on_intel_mac():
    plat = it.PlatformInfo("macos", "x86_64", mac_version=(14, 0))
    assert it.cpu_supports_mongodb(plat, mac_features="FPU SSE AVX1.0 RDRAND")[0]
    assert not it.cpu_supports_mongodb(plat, mac_features="FPU SSE SSE4.2")[0]


def test_missing_vc_runtime(tmp_path):
    (tmp_path / "vcruntime140.dll").write_bytes(b"")
    assert it.missing_vc_runtime(tmp_path) == ["msvcp140.dll", "msvcp140_1.dll", "vcruntime140_1.dll"]


@pytest.mark.parametrize("returncode, stderr, expected", [
    (-4, "", "processor"),
    (0xC0000135, "", "Visual C++"),
    (127, "mongod: error while loading shared libraries: libcurl.so.4: cannot open shared object file", "libcurl.so.4"),
    (1, "mongod: /lib64/libcurl.so.4: version `CURL_OPENSSL_4' not found (required by mongod)", "too old"),
    (it.PROCESS_NOT_STARTED, "Permission denied", "cannot be started"),
])
def test_explain_mongod_failure(returncode, stderr, expected):
    result = subprocess.CompletedProcess(["mongod"], returncode, "", stderr)
    reason, hint = it.explain_mongod_failure(LINUX_X86, result)
    assert expected in reason
    assert hint


def test_library_hint_names_the_package_manager():
    rocky = it.PlatformInfo("linux", "x86_64", os_release={"ID": "rocky", "ID_LIKE": "rhel centos fedora"})
    assert "apt install" in it._library_hint(LINUX_X86)
    assert "dnf install" in it._library_hint(rocky)


def test_newer_data_is_never_opened_by_an_older_mongodb(project):
    ctx = make_context(project, manifest={"components": {"mongodb": {"status": "installed", "version": "8.0.34"}}})
    (ctx.layout.mongodb_data / "WiredTiger").parent.mkdir(parents=True)
    (ctx.layout.mongodb_data / "WiredTiger").write_text("WiredTiger\n")
    older = [it.mongo_build(it.MONGODB_FALLBACK_VERSION, "macos-arm64")]
    builds, reason = it.guard_data_version(ctx, older, "")
    assert builds == [] and "newer" in reason
    newer = [it.mongo_build(it.MONGODB_VERSION, "macos-arm64")]
    assert it.guard_data_version(ctx, newer, "") == (newer, "")


# --- Downloads and checksums ------------------------------------------------------------------------------------------

def test_download_verifies_the_checksum(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"pinned content")
    ui = it.Ui(io.StringIO(), color=False)
    dest = it.download(ui, [source.as_uri()], tmp_path / "out" / "file.bin", sha256(b"pinned content"), "the test file")
    assert dest.read_bytes() == b"pinned content"
    assert not (tmp_path / "out" / "file.bin.part").exists()


def test_download_with_a_wrong_checksum_deletes_the_file_and_explains(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"tampered content")
    dest = tmp_path / "out" / "file.bin"
    with pytest.raises(it.InstallError, match="checksum") as error:
        it.download(it.Ui(io.StringIO(), color=False), [source.as_uri()], dest, sha256(b"pinned content"), "the file")
    assert "Run the installer again" in error.value.hint
    assert not dest.exists() and not dest.with_name("file.bin.part").exists()


def test_download_reuses_a_verified_file(tmp_path, monkeypatch):
    dest = tmp_path / "file.bin"
    dest.write_bytes(b"already here")
    monkeypatch.setattr(it, "_fetch", lambda *args: pytest.fail("nothing must be downloaded"))
    ui = it.Ui(io.StringIO(), color=False)
    assert it.download(ui, ["https://example.invalid/file"], dest, sha256(b"already here"), "the file") == dest


def test_download_network_error_explains_what_to_do(tmp_path, monkeypatch):
    calls = []

    def unreachable(url, headers=None):
        calls.append(url)
        raise urllib.error.URLError("Name or service not known")

    monkeypatch.setattr(it, "_urlopen", unreachable)
    with pytest.raises(it.InstallError, match="Could not download") as error:
        it.download(it.Ui(io.StringIO(), color=False), ["https://a.invalid/f", "https://b.invalid/f"],
                    tmp_path / "f", "0" * 64, "the file")
    assert "internet connection" in error.value.hint
    assert calls == ["https://a.invalid/f", "https://b.invalid/f"] * 2  # Every attempt tries the next mirror


class FakeResponse(io.BytesIO):
    def __init__(self, data, status=200, headers=None):
        super().__init__(data)
        self.status = status
        self.headers = {"Content-Length": str(len(data)), **(headers or {})}


def test_download_resumes_a_partial_file(tmp_path, monkeypatch):
    content = b"0123456789" * 100
    dest = tmp_path / "file.bin"
    dest.with_name("file.bin.part").write_bytes(content[:300])
    requested = []

    def server(url, headers=None):
        requested.append(headers)
        start = int(headers["Range"].split("=")[1].rstrip("-"))
        return FakeResponse(content[start:], status=206)

    monkeypatch.setattr(it, "_urlopen", server)
    it.download(it.Ui(io.StringIO(), color=False), ["https://x.invalid/f"], dest, sha256(content), "the file")
    assert requested == [{"Range": "bytes=300-"}]
    assert dest.read_bytes() == content


def test_fetch_bytes_retries(monkeypatch):
    answers = [urllib.error.URLError("timeout"), FakeResponse(b"data")]

    def server(url, headers=None):
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(it, "_urlopen", server)
    assert it.fetch_bytes("https://x.invalid/list.json", "the list") == b"data"


def test_http_range_reader_extracts_one_member_of_a_remote_zip(monkeypatch):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr("mongodb-win32-x86_64-windows-8.0.34/bin/mongod.pdb", os.urandom(300_000))
        zipped.writestr("mongodb-win32-x86_64-windows-8.0.34/bin/mongod.exe", b"MZ" + b"x" * 50_000)
    archive = buffer.getvalue()

    def server(url, headers=None):
        start, end = (int(value) for value in headers["Range"].split("=")[1].split("-"))
        return FakeResponse(archive[start:end + 1], 206, {"Content-Range": f"bytes {start}-{end}/{len(archive)}"})

    monkeypatch.setattr(it, "_urlopen", server)
    reader = it.HttpRangeReader.open("https://fastdl.invalid/mongodb.zip", block_size=16_384)
    with zipfile.ZipFile(reader) as zipped:
        member = next(info for info in zipped.infolist() if it.select_mongod(info.filename))
        assert zipped.read(member) == b"MZ" + b"x" * 50_000
    assert reader.fetched < len(archive) / 2  # The large .pdb was not downloaded


def range_server(archive):
    def server(url, headers=None):
        start, end = (int(value) for value in headers["Range"].split("=")[1].split("-"))
        return FakeResponse(archive[start:end + 1], 206, {"Content-Range": f"bytes {start}-{end}/{len(archive)}"})
    return server


def test_http_range_reader_fills_reads_across_blocks(monkeypatch):
    data = bytes(range(256)) * 40
    monkeypatch.setattr(it, "_urlopen", range_server(data))
    reader = it.HttpRangeReader.open("https://x.invalid/file", block_size=1000)
    reader.seek(990)
    assert reader.read(2500) == data[990:3490]  # Crosses three blocks, in one read
    reader.seek(len(data) - 5)
    assert reader.read(100) == data[-5:] and reader.read(10) == b""


def test_http_range_reader_reads_a_central_directory_larger_than_a_block(monkeypatch):
    # zipfile reads the central directory with one read(): a short read made it fail with "Truncated central directory"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zipped:
        for number in range(400):
            zipped.writestr(f"mongodb-win32-x86_64-windows-8.0.34/lib/file-with-a-long-name-{number:04d}.txt", b"x")
        zipped.writestr("mongodb-win32-x86_64-windows-8.0.34/bin/mongod.exe", b"MZ server")
    archive = buffer.getvalue()
    monkeypatch.setattr(it, "_urlopen", range_server(archive))
    reader = it.HttpRangeReader.open("https://fastdl.invalid/mongodb.zip", block_size=4096)
    with zipfile.ZipFile(reader) as zipped:
        member = next(info for info in zipped.infolist() if it.select_mongod(info.filename))
        assert zipped.read(member) == b"MZ server"


def test_http_range_reader_detects_servers_without_ranges(monkeypatch):
    monkeypatch.setattr(it, "_urlopen", lambda url, headers=None: FakeResponse(b"whole file", 200))
    with pytest.raises(it.RangeNotSupported):
        it.HttpRangeReader.open("https://x.invalid/file.zip")


# --- Archive extraction -----------------------------------------------------------------------------------------------

def make_tar(path, members):
    with tarfile.open(path, "w:gz") as tar:
        for name, data, mode in members:
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            tar.addfile(info, io.BytesIO(data))
    return path


def test_extract_tar_keeps_the_executable_bit(tmp_path):
    archive = make_tar(tmp_path / "a.tar.gz", [("go/bin/go", b"binary", 0o755), ("go/README", b"text", 0o644)])
    written = it.extract_archive(archive, tmp_path / "out")
    assert sorted(path.name for path in written) == ["README", "go"]
    if os.name != "nt":
        assert os.access(tmp_path / "out" / "go" / "bin" / "go", os.X_OK)
        assert not os.access(tmp_path / "out" / "go" / "README", os.X_OK)


@pytest.mark.parametrize("name", ["../evil.txt", "/etc/evil.txt", "ok/../../evil.txt", "C:/evil.txt", "..\\evil.txt"])
def test_extract_zip_refuses_zip_slip(tmp_path, name):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("fine.txt", b"fine")
        zipped.writestr(name, b"evil")
    with pytest.raises(it.InstallError, match="unsafe|outside"):
        it.extract_archive(archive, tmp_path / "out" / "dest")
    assert not (tmp_path / "evil.txt").exists() and not (tmp_path / "out" / "evil.txt").exists()


def test_extract_tar_refuses_paths_and_links_leaving_the_folder(tmp_path):
    archive = make_tar(tmp_path / "evil.tar.gz", [("../evil.txt", b"evil", 0o644)])
    with pytest.raises(it.InstallError):
        it.extract_archive(archive, tmp_path / "out")
    linked = tmp_path / "link.tar.gz"
    with tarfile.open(linked, "w:gz") as tar:
        info = tarfile.TarInfo("top/link")
        info.type, info.linkname = tarfile.SYMTYPE, "../../../etc/passwd"
        tar.addfile(info)
    with pytest.raises(it.InstallError):
        it.extract_archive(linked, tmp_path / "out2")
    assert not (tmp_path / "evil.txt").exists()


def test_extract_only_mongod_from_a_mongodb_archive(tmp_path):
    archive = make_tar(tmp_path / "mongodb.tgz", [
        ("mongodb-macos-aarch64--8.0.34/LICENSE-Community.txt", b"license", 0o644),
        ("mongodb-macos-aarch64--8.0.34/bin/mongod", b"server", 0o755),
        ("mongodb-macos-aarch64--8.0.34/bin/mongos", b"router", 0o755),
    ])
    written = it.extract_archive(archive, tmp_path / "out", it.select_mongod)
    assert written == [tmp_path / "out" / "bin" / "mongod"]
    assert it.select_mongod("mongodb-win32-x86_64-windows-8.0.34\\bin\\mongod.exe") == "bin/mongod.exe"
    assert it.select_mongod("mongodb-win32-x86_64-windows-8.0.34/bin/mongod.pdb") is None


def test_damaged_archive_gives_a_clear_error(tmp_path):
    archive = tmp_path / "broken.tar.gz"
    archive.write_bytes(b"\x1f\x8b not really gzip")
    with pytest.raises(it.InstallError, match="Could not extract"):
        it.extract_archive(archive, tmp_path / "out")


# --- Components: idempotence ------------------------------------------------------------------------------------------

def installed_zlint(project, version=it.ZLINT_VERSION):
    ctx = make_context(project)
    binary = fake_program(ctx.layout.zlint, f"ZLint version {version}")
    ctx.manifest = {"components": {"zlint": {"status": "installed", "version": version, "sha256": it.file_sha256(binary)}}}
    return ctx


@posix_only
def test_installed_zlint_is_skipped(project, monkeypatch):
    ctx = installed_zlint(project)
    monkeypatch.setattr(it, "build_zlint", lambda ctx: pytest.fail("ZLint must not be rebuilt"))
    assert it.install(ctx, ["zlint"]) in (0, 1)  # The summary may fail on the missing .venv: not what is tested here
    assert "already installed: ZLint " + it.ZLINT_VERSION in output_of(ctx)


@posix_only
def test_changed_zlint_binary_is_reinstalled(project, monkeypatch):
    ctx = installed_zlint(project)
    ctx.layout.zlint.write_text("#!/bin/sh\necho 'ZLint version v0.0.1'\n")
    built = []
    monkeypatch.setattr(it, "build_zlint", lambda ctx: built.append(True))
    it.install(ctx, ["zlint"])
    assert built == [True]


@posix_only
def test_failed_zlint_build_falls_back_to_the_prebuilt_release(project, monkeypatch):
    ctx = make_context(project)

    def failing_build(ctx):
        raise it.InstallError("Building ZLint failed", it.GO_BUILD_HINT)

    monkeypatch.setattr(it, "build_zlint", failing_build)
    monkeypatch.setattr(it, "install_prebuilt_zlint", lambda ctx: fake_program(ctx.layout.zlint, "ZLint version 3.6.4"))
    it.install_zlint(ctx)
    assert "prebuilt ZLint 3.6.4" in output_of(ctx)


def test_zlint_build_failure_on_an_arm_mac_without_rosetta_says_how_to_get_it(project, monkeypatch):
    ctx = make_context(project, plat=MACOS_ARM)

    def failing_build(ctx):
        raise it.InstallError("Building ZLint failed", it.GO_BUILD_HINT)

    monkeypatch.setattr(it, "build_zlint", failing_build)
    monkeypatch.setattr(it, "rosetta_installed", lambda: False)
    monkeypatch.setattr(it, "install_prebuilt_zlint", lambda ctx: pytest.fail("the Intel ZLint cannot run here"))
    with pytest.raises(it.InstallError) as error:
        it.install_zlint(ctx)
    assert "proxy.golang.org" in error.value.hint and "softwareupdate --install-rosetta" in error.value.hint


# A stand-in for the go program: `go install` writes a zlint that reports the pinned version, or fails like a network
# problem; `go clean` does nothing
FAKE_GO = """#!/bin/sh
if [ "$1" = install ]; then
    if [ {build_code} != 0 ]; then echo 'cannot reach proxy.golang.org' >&2; exit {build_code}; fi
    mkdir -p "$GOBIN"
    printf '#!/bin/sh\\necho "ZLint version {version}"\\n' > "$GOBIN/zlint"
    chmod 755 "$GOBIN/zlint"
fi
exit 0
"""


def fake_go_toolchain(folder, build_code):
    """A Go archive whose go program makes `go install` exit with build_code (0: the build works)."""
    folder.mkdir(parents=True, exist_ok=True)
    script = FAKE_GO.format(build_code=build_code, version=it.ZLINT_VERSION).encode()
    return make_tar(folder / "go-test.tar.gz", [("go/bin/go", script, 0o755)])


@posix_only
@pytest.mark.parametrize("build_code", [0, 1])
def test_go_archive_is_kept_only_after_a_failed_build(project, monkeypatch, build_code):
    ctx = make_context(project, plat=it.PlatformInfo("linux", "x86_64", libc="glibc"))
    source = fake_go_toolchain(project / "mirror", build_code)
    monkeypatch.setattr(it, "GO_ARCHIVES", {("linux", "x86_64"): (source.name, it.file_sha256(source))})
    monkeypatch.setattr(it, "GO_MIRRORS", (source.parent.as_uri() + "/",))
    if build_code:
        with pytest.raises(it.InstallError, match="Building ZLint failed"):
            it.build_zlint(ctx)
        # The next run finds the verified archive and does not download it again
        assert (ctx.layout.downloads / source.name).is_file()
    else:
        it.build_zlint(ctx)
        assert not (ctx.layout.downloads / source.name).exists()
        entry = json.loads(ctx.layout.manifest.read_text())["components"]["zlint"]
        assert entry["go"] == it.GO_VERSION and entry["version"] == it.ZLINT_VERSION
    assert not ctx.layout.go_dir.exists()  # The toolchain and the caches are always removed


@posix_only
def test_installed_mongodb_is_skipped(project, monkeypatch):
    ctx = make_context(project, plat=MACOS_ARM)
    binary = fake_program(ctx.layout.mongod, "db version v8.0.34")
    ctx.manifest = {"components": {"mongodb": {"status": "installed", "version": "8.0.34", "build": "macos-arm64",
                                               "sha256": it.file_sha256(binary)}}}
    monkeypatch.setattr(it, "_try_mongodb_build", lambda ctx, build: pytest.fail("MongoDB must not be reinstalled"))
    assert it.mongodb_current(ctx) == "MongoDB 8.0.34 server"


@posix_only
def test_mongodb_install_tries_the_next_build_and_records_it(project, monkeypatch):
    plat = it.PlatformInfo("linux", "x86_64", libc="glibc", os_release={"ID": "arch"})
    ctx = make_context(project, plat=plat)
    monkeypatch.setattr(it, "cpu_supports_mongodb", lambda plat: (True, ""))

    def fetch(ctx, build, staging):
        it.remove_tree(staging)
        works = build.key.endswith("ubuntu2204")
        return fake_program(staging / "bin" / "mongod", "db version v8.0.34" if works else "", 0 if works else 127)

    monkeypatch.setattr(it, "_fetch_mongod", fetch)
    it.install_mongodb(ctx)
    entry = json.loads(ctx.layout.manifest.read_text())["components"]["mongodb"]
    assert (entry["status"], entry["build"], entry["official_build"]) == ("installed", "linux-x86_64-ubuntu2204", False)
    assert ctx.layout.mongod.is_file() and ctx.layout.mongodb_data.is_dir()
    assert (ctx.layout.mongodb_dir / "VERSION").read_text().strip() == "8.0.34"


def test_mongodb_unavailable_is_a_warning_with_a_way_out(project):
    ctx = make_context(project, plat=it.PlatformInfo("linux", "x86_64", libc="musl", os_release={"ID": "alpine"}))
    it.install_mongodb(ctx)
    assert "[WARN]" in output_of(ctx) and "localhost:27017" in output_of(ctx)
    assert component_status(ctx, "mongodb") == "unavailable"
    assert it.check_mongodb(ctx).state == "warn"


def component_status(ctx, name):
    return json.loads(ctx.layout.manifest.read_text())["components"][name]["status"]


def test_existing_log_list_is_never_replaced(project, monkeypatch):
    ctx = make_context(project)
    ctx.layout.log_list.write_text(json.dumps({"operators": [{"logs": [{}, {}], "tiled_logs": [{}]}]}))
    monkeypatch.setattr(it, "fetch_bytes", lambda *args: pytest.fail("the list must not be downloaded"))
    assert it.log_list_current(ctx) == "res/log_list.json (3 logs; kept as it is)"


def signed_log_list(monkeypatch, logs=("a",)):
    """Google's files for a log list signed with a test key, which the installer then trusts."""
    rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    data = json.dumps({"operators": [{"logs": [{"log_id": log} for log in logs]}]}).encode()
    monkeypatch.setattr(it, "LOG_LIST_PUBLIC_KEY", pem)
    return {it.LOG_LIST_URL: data, it.LOG_LIST_SIGNATURE_URL: key.sign(data, padding.PKCS1v15(), hashes.SHA256())}


def test_missing_log_list_is_downloaded_and_its_signature_checked(project, monkeypatch):
    files = signed_log_list(monkeypatch)
    data = files[it.LOG_LIST_URL]
    monkeypatch.setattr(it, "fetch_bytes", lambda url, label: files[url])
    ctx = make_context(project)
    it.install_log_list(ctx)
    assert ctx.layout.log_list.read_bytes() == data

    files[it.LOG_LIST_URL] = data.replace(b'"a"', b'"b"')
    ctx.layout.log_list.unlink()
    with pytest.raises(it.InstallError, match="signature"):
        it.install_log_list(ctx)
    assert not ctx.layout.log_list.exists()


def test_force_keeps_a_valid_log_list_unless_it_is_named():
    everything = list(it.COMPONENT_NAMES)
    assert it.forced_components(False, everything, None) == frozenset()
    assert it.forced_components(True, everything, None) == {"zlint", "mongodb"}
    assert it.forced_components(True, ["log_list"], ["log_list"]) == {"log_list"}
    assert it.parse_args(["--force"]).forced == {"zlint", "mongodb"}


def project_log_list(ctx, logs=165):
    ctx.layout.log_list.write_text(json.dumps({"operators": [{"logs": [{}] * logs}]}))
    return ctx.layout.log_list.read_bytes()


def test_plain_force_never_touches_a_valid_log_list(project, monkeypatch):
    ctx = make_context(project)
    original = project_log_list(ctx)
    ctx.forced = it.forced_components(True, list(it.COMPONENT_NAMES), None)
    monkeypatch.setattr(it, "fetch_bytes", lambda *args: pytest.fail("the list must not be downloaded"))
    it.install(ctx, ["log_list"])
    assert ctx.layout.log_list.read_bytes() == original
    assert "kept as it is" in output_of(ctx) and not list(project.glob("res/*.broken"))


def test_replacing_a_valid_log_list_on_request_keeps_the_old_one(project, monkeypatch):
    ctx = make_context(project)
    original = project_log_list(ctx)
    files = signed_log_list(monkeypatch, logs=("new",))
    monkeypatch.setattr(it, "fetch_bytes", lambda url, label: files[url])
    it.install_log_list(ctx)
    assert ctx.layout.log_list.read_bytes() == files[it.LOG_LIST_URL]
    assert (project / "res" / "log_list.json.old").read_bytes() == original
    assert "is not a valid log list" not in output_of(ctx)


def test_failed_download_leaves_the_valid_log_list_in_place(project, monkeypatch):
    ctx = make_context(project)
    original = project_log_list(ctx)

    def offline(url, label):
        raise it.InstallError(f"Could not download {label}.", it.NETWORK_HINT)

    monkeypatch.setattr(it, "fetch_bytes", offline)
    with pytest.raises(it.InstallError):
        it.install_log_list(ctx)
    assert ctx.layout.log_list.read_bytes() == original
    assert it.check_log_list(ctx).state == "ok" and not list(project.glob("res/log_list.json.*"))


def test_damaged_log_list_is_renamed_and_replaced(project, monkeypatch):
    ctx = make_context(project)
    ctx.layout.log_list.write_text("<html>not a list</html>")
    files = signed_log_list(monkeypatch)
    monkeypatch.setattr(it, "fetch_bytes", lambda url, label: files[url])
    it.install_log_list(ctx)
    assert (project / "res" / "log_list.json.broken").read_text() == "<html>not a list</html>"
    assert it.log_list_logs(ctx.layout.log_list) == 1


def test_signature_check_with_google_key_rejects_garbage():
    assert hashlib.sha256(it.LOG_LIST_PUBLIC_KEY.encode()).hexdigest() == \
        "a284e4ad744211a6636a03c59aca9446ecd5ff2c14d7cb6edd69f7ba2108bf95"
    n, e = it.rsa_public_key(it.LOG_LIST_PUBLIC_KEY)
    assert n.bit_length() == 4096 and e == 65537
    assert not it.rsa_sha256_signature_valid(it.LOG_LIST_PUBLIC_KEY, b"{}", b"\x00" * 512)
    assert not it.rsa_sha256_signature_valid(it.LOG_LIST_PUBLIC_KEY, b"{}", b"short")


# --- Command line and --check -----------------------------------------------------------------------------------------

def test_select_components():
    assert it.select_components(None, None) == ["zlint", "mongodb", "log_list"]
    assert it.select_components(["mongodb,zlint"], None) == ["zlint", "mongodb"]
    assert it.select_components(None, ["mongodb", "log-list"]) == ["zlint"]
    with pytest.raises(SystemExit):
        it.parse_args(["--skip", "everything"])


@posix_only
def test_check_reports_every_component_and_fails_when_one_is_missing(project, monkeypatch, capsys):
    ctx = installed_zlint(project)
    it.save_manifest(ctx)
    monkeypatch.setattr(it, "detect_platform", lambda: LINUX_X86)
    status = it.main(["--check", "--project-dir", str(project)])
    output = capsys.readouterr().out
    assert status == 1
    for row in ("Python", "Python packages", "sslyze", "ZLint", "MongoDB", "CT log list", "Scan file", "Disk space"):
        assert row in output
    assert "[ OK ] ZLint" in output and it.ZLINT_VERSION in output
    assert "[FAIL] MongoDB" in output and "What to do:" in output
    assert "[FAIL] CT log list" in output


@posix_only
def test_check_passes_when_everything_is_ready(project, monkeypatch, capsys):
    ctx = installed_zlint(project)
    it.save_manifest(ctx)
    ctx.layout.log_list.write_text(json.dumps({"operators": [{"logs": [{}]}]}))
    (project / "dca").chmod(0o755)
    monkeypatch.setattr(it, "detect_platform", lambda: LINUX_X86)
    monkeypatch.setattr(it, "mongodb_server_answers", lambda: True)  # The user's own MongoDB
    monkeypatch.setattr(it, "check_python", lambda ctx: it.Status("Python", "ok", "3.12"))
    monkeypatch.setattr(it, "check_packages", lambda ctx: it.Status("Python packages", "ok", "all"))
    assert it.main(["--check", "--project-dir", str(project)]) == 0
    output = capsys.readouterr().out
    assert "a MongoDB server answers on localhost:27017" in output
    assert "Everything needed is ready." in output


def test_check_with_skip_leaves_the_component_out(project, monkeypatch, capsys):
    monkeypatch.setattr(it, "detect_platform", lambda: LINUX_X86)
    it.main(["--check", "--skip", "mongodb,zlint", "--project-dir", str(project)])
    output = capsys.readouterr().out
    assert "MongoDB" not in output and "ZLint" not in output and "CT log list" in output


def test_scan_file_hint_points_to_the_guide(project):
    assert "INSTALL.md, step 6" in it.check_scan_file(make_context(project)).hint


@pytest.mark.parametrize("windows", [False, True])
def test_next_steps_are_commands_that_work_in_every_terminal(tmp_path, windows):
    project = tmp_path / "Mario Rossi" / "DigitalCertiAnalytics"
    ctx = it.Context(it.Layout(project, windows=windows), LINUX_X86, it.Ui(io.StringIO(), color=False))
    it.print_next_steps(ctx, True)
    output = output_of(ctx)
    if windows:
        # A quoted path followed by options is an error in PowerShell: the commands are for the project folder
        assert "    dca.bat --help" in output and ".\\dca.bat" in output and "install.bat --check" in output
        assert f'"{project}' not in output
    else:
        assert f'"{project / "dca"}" --help' in output


def test_check_python_outside_the_venv_fails(project):
    status = it.check_python(make_context(project))
    assert status.state == "fail" and "install" in status.hint


def test_read_requirements(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("# pins\ncryptography==42.0.8\nrich == 13.9.3  # comment\nnumpy>=2\n")
    assert it.read_requirements(path) == [("cryptography", "42.0.8"), ("rich", "13.9.3")]


def test_go_environment_keeps_everything_in_the_project(tmp_path):
    layout = it.Layout(tmp_path, windows=False)
    user_env = {"PATH": "/bin", "GOPROXY": "https://goproxy.cn,direct", "GOOS": "plan9", "GOFLAGS": "-mod=vendor"}
    env = it.go_environment(layout, tmp_path / "go", user_env)
    assert env["GOPROXY"] == "https://goproxy.cn,direct"  # The user's proxy setting is kept
    assert "GOOS" not in env and env["GOFLAGS"] == "-modcacherw"
    for name in ("GOPATH", "GOCACHE", "GOMODCACHE", "GOTMPDIR", "GOBIN", "HOME", "XDG_CONFIG_HOME", "APPDATA"):
        assert Path(env[name]).is_relative_to(tmp_path), name


def test_manifest_round_trip(project):
    ctx = make_context(project)
    it.set_component(ctx, "zlint", {"status": "installed", "version": "x"})
    manifest = it.load_manifest(ctx.layout)
    assert manifest["components"]["zlint"]["version"] == "x" and manifest["platform"]["system"] == "linux"
    ctx.layout.manifest.write_text("not json")
    assert it.load_manifest(ctx.layout) == {}


# --- Shell scripts (install.sh, dca.command) ---------------------------------------------------------------------------

def fake_project(folder, marker):
    """The files install.sh recognises a project by, plus a marker file and a stub installer that says where it ran."""
    for name in ("requirements.txt", "src/analysis/main.py", "scripts/install_tools.py", marker):
        (folder / name).parent.mkdir(parents=True, exist_ok=True)
        (folder / name).write_text("")
    (folder / "install.sh").write_text('#!/bin/sh\necho "stub installer in $(pwd -P) with: $*"\n')
    return folder


def piped_install_sh(cwd, home, arguments=(), **env):
    """Run install.sh as `curl ... | bash -s -- ARGUMENTS` from cwd."""
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), **env}
    return subprocess.run(["bash", "-s", "--", *arguments], input=(ROOT / "install.sh").read_text(), cwd=cwd,
                          capture_output=True, text=True, env=environment, timeout=120)


shell_only = pytest.mark.skipif(os.name == "nt" or not shutil.which("bash") or not shutil.which("curl"),
                                reason="needs bash and curl")


@shell_only
def test_piped_install_sh_shows_its_help(tmp_path):
    result = piped_install_sh(tmp_path, tmp_path, ["--help"])
    assert result.returncode == 0
    assert "--skip mongodb" in result.stdout and "DCA_INSTALL_DIR" in result.stdout


@shell_only
def test_piped_install_sh_inside_a_copy_updates_that_copy(tmp_path):
    newer = fake_project(tmp_path / "archive" / "DigitalCertiAnalytics-main", "UPDATED_MARKER.txt")
    archive = tmp_path / "main.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(newer, arcname="DigitalCertiAnalytics-main")
    copy = fake_project(tmp_path / "my copy", "res/certs_polito.json")
    (copy / "install.sh").unlink()

    result = piped_install_sh(copy, tmp_path / "home", ["--skip", "mongodb"], DCA_ARCHIVE_URL=archive.as_uri())

    assert result.returncode == 0, result.stderr
    assert (copy / "UPDATED_MARKER.txt").is_file() and (copy / "res" / "certs_polito.json").is_file()
    assert f"stub installer in {copy.resolve()} with: --skip mongodb" in result.stdout
    assert not (tmp_path / "home" / "DigitalCertiAnalytics").exists()


@shell_only
def test_dca_command_asks_again_after_options_it_does_not_understand(tmp_path):
    shutil.copy(ROOT / "dca.command", tmp_path / "dca.command")
    # A stand-in for dca: like argparse, it exits with 2 for an option without the two dashes
    (tmp_path / "dca").write_text('#!/bin/sh\ncase "$1" in --help) echo usage ;; --*) echo "ran $*" ;; '
                                  '*) echo "error: unrecognized arguments: $1" >&2; exit 2 ;; esac\n')
    result = subprocess.run(["bash", str(tmp_path / "dca.command")], input="leaf_analysis\n--leaf_analysis\n\n",
                            capture_output=True, text=True, timeout=60)
    assert "Those options were not understood" in result.stdout
    assert "ran --leaf_analysis" in result.stdout and result.returncode == 0
