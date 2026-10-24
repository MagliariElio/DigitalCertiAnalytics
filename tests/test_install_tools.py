"""Tests of scripts/install_tools.py: no network, no real ZLint or Go (local files and monkeypatching)."""
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
REAL_INSTALL_RELEASE_ZLINT = it.install_release_zlint  # The autouse fixture replaces it

MACOS_ARM = it.PlatformInfo("macos", "arm64", mac_version=(26, 6))
LINUX_X86 = it.PlatformInfo("linux", "x86_64", libc="glibc",
                            os_release={"ID": "ubuntu", "VERSION_ID": "24.04", "PRETTY_NAME": "Ubuntu 24.04 LTS"})


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    """No pauses between retries, no real sslyze, and no release download (the tests that need one set it up)."""
    monkeypatch.setattr(it, "RETRY_DELAYS", (0, 0, 0))
    monkeypatch.delenv("DCA_ZLINT_PATH", raising=False)
    monkeypatch.setattr(it, "check_sslyze", lambda ctx: it.Status("sslyze", "ok", "sslyze (not run by the tests)"))
    monkeypatch.setattr(it, "install_release_zlint", lambda ctx: False)


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


# --- Platform ---------------------------------------------------------------------------------------------------------

def test_parse_os_release_handles_quotes_and_comments():
    text = '# comment\nID=ubuntu\nVERSION_ID="22.04"\nID_LIKE=\'debian\'\n\nBROKEN LINE\n'
    assert it.parse_os_release(text) == {"ID": "ubuntu", "VERSION_ID": "22.04", "ID_LIKE": "debian"}


@pytest.mark.parametrize("machine, expected", [("x86_64", "x86_64"), ("AMD64", "x86_64"), ("arm64", "arm64"),
                                               ("aarch64", "arm64"), ("armv7l", "armv7l")])
def test_normalize_arch(machine, expected):
    assert it.normalize_arch(machine) == expected


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
    assert it.forced_components(True, everything, None) == {"zlint"}
    assert it.forced_components(True, ["log_list"], ["log_list"]) == {"log_list"}
    assert it.parse_args(["--force"]).forced == {"zlint"}


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


# --- ZLint from the project's release --------------------------------------------------------------------------------

@pytest.mark.parametrize("plat, name", [
    (MACOS_ARM, "zlint-macos-arm64"),
    (LINUX_X86, "zlint-linux-x86_64"),
    (it.PlatformInfo("windows", "arm64"), "zlint-windows-arm64.exe"),
    (it.PlatformInfo("macos", "x86_64", mac_version=(12, 7)), None),   # Programs built with Go 1.27 need macOS 13
    (it.PlatformInfo("linux", "riscv64"), None),
])
def test_zlint_release_asset(plat, name):
    assert it.zlint_release_asset(plat) == name


def test_every_release_asset_has_a_pinned_checksum():
    for (system, arch), digest in it.ZLINT_BUILD_SHA256.items():
        assert len(digest) == 64 and int(digest, 16) >= 0
        assert it.zlint_release_asset(it.PlatformInfo(system, arch, mac_version=(26,))) is not None
    assert it.ZLINT_RELEASE_URL.endswith(f"/releases/download/zlint-{it.ZLINT_VERSION}/")


def use_release(monkeypatch, fetch):
    monkeypatch.setattr(it, "install_release_zlint", REAL_INSTALL_RELEASE_ZLINT)
    monkeypatch.setattr(it, "_fetch", fetch)
    built = []
    monkeypatch.setattr(it, "build_zlint", lambda ctx: built.append(True))
    return built


@posix_only
def test_release_zlint_is_installed_when_it_is_the_pinned_build(project, monkeypatch):
    ctx = make_context(project)
    program = f"#!/bin/sh\necho 'ZLint version {it.ZLINT_VERSION}'\n".encode()
    monkeypatch.setitem(it.ZLINT_BUILD_SHA256, ("linux", "x86_64"), sha256(program))
    requested = []

    def fetch(ui, url, part, label):
        requested.append(url)
        part.write_bytes(program)

    built = use_release(monkeypatch, fetch)
    it.install_zlint(ctx)
    assert requested == [it.ZLINT_RELEASE_URL + "zlint-linux-x86_64"] and not built
    entry = ctx.manifest["components"]["zlint"]
    assert entry["source"] == "release" and entry["reference_build"] is True and entry["commit"] == it.ZLINT_COMMIT
    assert os.access(ctx.layout.zlint, os.X_OK) and not (ctx.layout.tools / "zlint.new").exists()


@posix_only
def test_release_zlint_with_another_checksum_is_refused_and_built_instead(project, monkeypatch):
    ctx = make_context(project)
    built = use_release(monkeypatch, lambda ui, url, part, label: part.write_bytes(b"#!/bin/sh\necho changed\n"))
    it.install_zlint(ctx)
    assert built == [True]
    assert "its SHA-256 differs from the pinned build" in output_of(ctx)
    assert not ctx.layout.zlint.exists() and not (ctx.layout.tools / "zlint.new").exists()


@posix_only
def test_release_zlint_that_does_not_run_is_removed_and_built_instead(project, monkeypatch):
    ctx = make_context(project)
    program = b"#!/bin/sh\necho 'ZLint version v0.0.1'\n"
    monkeypatch.setitem(it.ZLINT_BUILD_SHA256, ("linux", "x86_64"), sha256(program))
    built = use_release(monkeypatch, lambda ui, url, part, label: part.write_bytes(program))
    it.install_zlint(ctx)
    assert built == [True] and not ctx.layout.zlint.exists()


def test_unpublished_release_falls_back_to_the_build_at_once(project, monkeypatch):
    ctx = make_context(project)
    calls = []

    def not_found(ui, url, part, label):
        calls.append(url)
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    built = use_release(monkeypatch, not_found)
    it.install_zlint(ctx)
    assert len(calls) == 1 and built == [True]   # No retries and no pauses for a release that does not exist
    assert "it is not published yet" in output_of(ctx)


# --- The unused parts of Python and the leftovers of older versions ---------------------------------------------------

PYTHON_FILES = ("lib/python3.12/ensurepip/__init__.py", "lib/python3.12/idlelib/idle.py",
                "lib/python3.12/tkinter/__init__.py", "lib/python3.12/turtledemo/demo.py", "lib/python3.12/turtle.py",
                "lib/python3.12/lib-dynload/_tkinter.cpython-312-darwin.so", "lib/python3.12/site-packages/pip/x.py",
                "lib/tcl9.0/init.tcl", "lib/tk9.0/tk.tcl", "lib/libtcl9.0.dylib", "lib/libtcl9tk9.0.dylib",
                "lib/itcl4.3.8/itcl.tcl", "lib/thread3.0.6/thread.tcl", "include/python3.12/Python.h",
                "share/man/man1/python3.1", "bin/pip3", "bin/idle3", "bin/2to3")
PYTHON_KEPT = ("lib/python3.12/json/__init__.py", "lib/python3.12/lib-dynload/_ssl.cpython-312-darwin.so",
               "lib/python3.12/site-packages/README.txt", "lib/pkgconfig/python3.pc", "lib/python3.12/os.py")


def fake_python(base, linked):
    """A Python installation laid out like python-build-standalone's on macOS and Linux."""
    for name in PYTHON_FILES + PYTHON_KEPT + ("lib/libpython3.12.dylib",):
        (base / name).parent.mkdir(parents=True, exist_ok=True)
        (base / name).write_text(name)
    (base / "bin" / "python3.12").write_bytes(b"\x7fELF..." + (b"libpython3.12.so.1.0" if linked else b"static"))
    return base


@pytest.mark.parametrize("linked", [False, True])
def test_python_unused_files(tmp_path, linked):
    base = fake_python(tmp_path / "cpython-3.12.13-macos-aarch64-none", linked)
    unused = {path.relative_to(base).as_posix() for path in it.python_unused_files(base, windows=False, version=(3, 12))}
    stdlib = "lib/python3.12/"
    expected = {stdlib + "ensurepip", stdlib + "idlelib", stdlib + "tkinter", stdlib + "turtledemo", stdlib + "turtle.py",
                stdlib + "lib-dynload/_tkinter.cpython-312-darwin.so", stdlib + "site-packages/pip", "lib/tcl9.0",
                "lib/tk9.0", "lib/libtcl9.0.dylib", "lib/libtcl9tk9.0.dylib", "lib/itcl4.3.8", "lib/thread3.0.6",
                "include", "share", "bin/pip3", "bin/idle3", "bin/2to3"}
    if not linked:
        expected.add("lib/libpython3.12.dylib")
    assert unused == expected
    assert not any(name.startswith(kept) for kept in PYTHON_KEPT + ("bin/python3.12",) for name in unused)


def test_python_unused_files_on_windows(tmp_path):
    for name in ("Lib/tkinter/__init__.py", "Lib/json/__init__.py", "DLLs/_tkinter.pyd", "DLLs/tcl86t.dll",
                 "DLLs/_ssl.pyd", "tcl/tcl8.6/init.tcl", "include/Python.h", "libs/python312.lib",
                 "Lib/site-packages/pip/x.py", "Scripts/pip.exe", "python312.dll"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(name)
    unused = {path.relative_to(tmp_path).as_posix() for path in it.python_unused_files(tmp_path, windows=True)}
    assert unused == {"Lib/tkinter", "DLLs/_tkinter.pyd", "DLLs/tcl86t.dll", "tcl", "include", "libs",
                      "Lib/site-packages/pip", "Scripts/pip.exe"}


def python_check(monkeypatch, code, calls=None):
    def check(ctx):
        if calls is not None:
            calls.append(sorted(p.name for p in (ctx.layout.tools / it.PRUNE_FOLDER).iterdir()))
        if isinstance(code, BaseException):
            raise code
        return subprocess.CompletedProcess([], code, "", "ImportError: No module named 'something'")
    monkeypatch.setattr(it, "python_works", check)


def test_unused_parts_of_python_are_deleted_only_after_python_still_works(project, monkeypatch):
    ctx = make_context(project)
    base = fake_python(ctx.layout.python_dir / "cpython-3.12.13-macos-aarch64-none", linked=False)
    calls = []
    python_check(monkeypatch, 0, calls)
    it.prune_python(ctx, base, (3, 12))
    assert calls and it.PRUNE_RECORD in calls[0]          # Moved aside while the check ran
    assert not any((base / name).exists() for name in PYTHON_FILES)
    assert all((base / name).exists() for name in PYTHON_KEPT + ("bin/python3.12",))
    assert not (ctx.layout.tools / it.PRUNE_FOLDER).exists()
    assert "Removed" in output_of(ctx) and "never uses" in output_of(ctx)


@pytest.mark.parametrize("failure", [1, KeyboardInterrupt()])
def test_unused_parts_of_python_are_put_back_when_python_breaks(project, monkeypatch, failure):
    ctx = make_context(project)
    base = fake_python(ctx.layout.python_dir / "cpython-3.12.13-macos-aarch64-none", linked=False)
    python_check(monkeypatch, failure)
    if isinstance(failure, BaseException):
        with pytest.raises(KeyboardInterrupt):
            it.prune_python(ctx, base, (3, 12))
    else:
        it.prune_python(ctx, base, (3, 12))
        assert "so they are kept" in output_of(ctx) and "ImportError" in output_of(ctx)
    assert all((base / name).read_text() == name for name in PYTHON_FILES + ("lib/libpython3.12.dylib",))
    assert not (ctx.layout.tools / it.PRUNE_FOLDER).exists()


def test_what_a_killed_run_moved_aside_is_put_back(project):
    ctx = make_context(project)
    original = ctx.layout.python_dir / "cpython" / "lib" / "python3.12" / "tkinter"
    folder = ctx.layout.tools / it.PRUNE_FOLDER
    (folder / "0-tkinter").mkdir(parents=True)
    (folder / "0-tkinter" / "__init__.py").write_text("tk")
    original.parent.mkdir(parents=True)
    (folder / it.PRUNE_RECORD).write_text(json.dumps([[str(original), str(folder / "0-tkinter")],
                                                      [str(original.parent / "x"), str(folder / "1-x")]]))
    it.prune_python(ctx)          # The Python of the tests is not the project's: only the restore happens
    assert (original / "__init__.py").read_text() == "tk" and not folder.exists()


def test_only_the_projects_own_python_is_ever_pruned(project, monkeypatch):
    layout = make_context(project).layout
    monkeypatch.setattr(sys, "base_prefix", str(project / "elsewhere"))
    assert it.bundled_python(layout) is None
    monkeypatch.setattr(sys, "base_prefix", str(layout.python_dir / "cpython-3.12.13-linux-x86_64-gnu"))
    assert it.bundled_python(layout) == (layout.python_dir / "cpython-3.12.13-linux-x86_64-gnu").resolve()


@posix_only
def test_tree_size_counts_a_linked_file_once(tmp_path):
    (tmp_path / "a").write_bytes(b"x" * 1000)
    os.link(tmp_path / "a", tmp_path / "b")
    (tmp_path / "c").symlink_to(tmp_path / "a")
    assert it.tree_size(tmp_path) == 1000


@pytest.mark.parametrize("success", [True, False])
def test_leftovers_of_older_versions_are_removed(project, success):
    ctx = make_context(project)
    for folder in (ctx.layout.legacy_mongodb / "bin", ctx.layout.go_dir / "toolchain", ctx.layout.downloads):
        folder.mkdir(parents=True)
        (folder / "file").write_text("x")
    it.remove_leftovers(ctx, success)
    assert not ctx.layout.legacy_mongodb.exists()
    # After a failed build the verified Go archive is kept for the next run
    assert ctx.layout.go_dir.exists() != success and ctx.layout.downloads.exists() != success


def test_bytecode_of_an_older_location_of_the_project_is_removed(project):
    ctx = make_context(project)
    cache = ctx.layout.pycache
    current = cache.joinpath(*Path(os.path.realpath(project)).parts[1:]) / ".venv" / "x.cpython-312.pyc"
    old = cache.joinpath(*Path(os.path.realpath(project)).parent.parts[1:]) / "old-copy" / ".venv" / "x.cpython-312.pyc"
    elsewhere = cache / "somewhere" / "else.pyc"
    for path in (current, old, elsewhere):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"bytecode")
    it.remove_leftovers(ctx, True)
    assert current.is_file() and not old.exists() and not elsewhere.exists()
    assert "older location of the project" in output_of(ctx)
    it.remove_leftovers(ctx, True)            # Nothing left to remove: the current bytecode stays
    assert current.is_file()


def old_mongodb_data(ctx):
    data = ctx.layout.legacy_mongodb_data
    data.mkdir(parents=True)
    (data / "collection-0.wt").write_bytes(b"x" * 2048)
    return data


def test_old_mongodb_data_is_only_reported_without_a_terminal(project):
    ctx = make_context(project)
    data = old_mongodb_data(ctx)
    it.remove_leftovers(ctx, True)
    assert data.is_dir() and "ZLint results of an older version" in output_of(ctx) and "It is kept" in output_of(ctx)
    row = it.check_legacy_data(ctx)
    assert row.state == "warn" and str(data) in row.detail


@pytest.mark.parametrize("answer", [True, False])
def test_old_mongodb_data_is_deleted_only_when_the_user_says_so(project, monkeypatch, answer):
    ctx = make_context(project)
    data = old_mongodb_data(ctx)
    questions = []
    monkeypatch.setattr(ctx.ui, "confirm", lambda question: questions.append(question) or answer)
    it.remove_leftovers(ctx, True)
    assert len(questions) == 1 and str(data) in questions[0]
    assert data.exists() != answer and (project / "data").exists() != answer
    assert (it.check_legacy_data(ctx) is None) == answer


def test_confirm_without_a_terminal_answers_no(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("asked without a terminal"))
    assert it.Ui(io.StringIO(), color=False).confirm("Delete?") is False


def test_scan_file_can_be_compressed(project):
    ctx = make_context(project)
    (project / "res" / "certs_polito.json.zst").write_bytes(b"z")
    status = it.check_scan_file(ctx)
    assert status.state == "ok" and status.detail.startswith("res/certs_polito.json.zst") and not status.hint
    (project / "res" / "certs_polito.json").write_text("{}\n")
    status = it.check_scan_file(ctx)
    assert status.detail.startswith("res/certs_polito.json (") and "also certs_polito.json.zst (not used)" in status.detail
    assert "--compress_input" in status.hint


# --- Command line and --check -----------------------------------------------------------------------------------------

def test_select_components():
    assert it.select_components(None, None) == ["zlint", "log_list"]
    assert it.select_components(["log-list,zlint"], None) == ["zlint", "log_list"]
    assert it.select_components(None, ["log-list"]) == ["zlint"]
    with pytest.raises(SystemExit):
        it.parse_args(["--skip", "everything"])


def test_the_old_mongodb_component_is_accepted_and_ignored():
    """Commands written for older versions (--skip mongodb) keep working: MongoDB is simply no longer installed."""
    assert it.select_components(None, ["mongodb"]) == ["zlint", "log_list"]
    assert it.select_components(["zlint,mongo"], None) == ["zlint"]
    assert it.parse_args(["--skip", "mongodb", "--force"]).forced == {"zlint"}


@posix_only
def test_check_reports_every_component_and_fails_when_one_is_missing(project, monkeypatch, capsys):
    ctx = installed_zlint(project)
    it.save_manifest(ctx)
    monkeypatch.setattr(it, "detect_platform", lambda: LINUX_X86)
    status = it.main(["--check", "--project-dir", str(project)])
    output = capsys.readouterr().out
    assert status == 1
    for row in ("Python", "Python packages", "sslyze", "ZLint", "CT log list", "Scan file", "Disk space",
                "Installation"):
        assert row in output
    assert "MongoDB" not in output
    assert "[ OK ] ZLint" in output and it.ZLINT_VERSION in output
    assert "[FAIL] CT log list" in output and "What to do:" in output


@posix_only
def test_check_passes_when_everything_is_ready(project, monkeypatch, capsys):
    ctx = installed_zlint(project)
    it.save_manifest(ctx)
    ctx.layout.log_list.write_text(json.dumps({"operators": [{"logs": [{}]}]}))
    (project / "dca").chmod(0o755)
    monkeypatch.setattr(it, "detect_platform", lambda: LINUX_X86)
    monkeypatch.setattr(it, "check_python", lambda ctx: it.Status("Python", "ok", "3.12"))
    monkeypatch.setattr(it, "check_packages", lambda ctx: it.Status("Python packages", "ok", "all"))
    assert it.main(["--check", "--project-dir", str(project)]) == 0
    output = capsys.readouterr().out
    assert "Installation" in output and ".tools 0 MB, .venv 0 MB" in output
    assert "Everything needed is ready." in output


def test_check_with_skip_leaves_the_component_out(project, monkeypatch, capsys):
    monkeypatch.setattr(it, "detect_platform", lambda: LINUX_X86)
    it.main(["--check", "--skip", "zlint", "--project-dir", str(project)])
    output = capsys.readouterr().out
    assert "ZLint" not in output and "CT log list" in output


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
    assert "--only zlint" in result.stdout and "DCA_INSTALL_DIR" in result.stdout
    assert "mongo" not in result.stdout.lower()


@shell_only
def test_piped_install_sh_inside_a_copy_updates_that_copy(tmp_path):
    newer = fake_project(tmp_path / "archive" / "DigitalCertiAnalytics-main", "UPDATED_MARKER.txt")
    archive = tmp_path / "main.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(newer, arcname="DigitalCertiAnalytics-main")
    copy = fake_project(tmp_path / "my copy", "res/certs_polito.json")
    (copy / "install.sh").unlink()

    result = piped_install_sh(copy, tmp_path / "home", ["--skip", "zlint"], DCA_ARCHIVE_URL=archive.as_uri())

    assert result.returncode == 0, result.stderr
    assert (copy / "UPDATED_MARKER.txt").is_file() and (copy / "res" / "certs_polito.json").is_file()
    assert f"stub installer in {copy.resolve()} with: --skip zlint" in result.stdout
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
