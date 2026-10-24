#!/bin/sh
# Installer of DigitalCertiAnalytics for macOS and Linux.
#
# From the project folder:            sh install.sh        (on macOS you can also double-click install.command)
# Without a copy of the project:      curl -fsSL https://raw.githubusercontent.com/MagliariElio/DigitalCertiAnalytics/main/install.sh | bash
#                                     (it downloads the project into ~/DigitalCertiAnalytics first; run inside a copy
#                                     of the project, it updates that copy)
#
# Everything is installed inside the project folder (.tools, .venv, data): no administrator rights are needed and
# nothing is changed elsewhere on the computer. To uninstall, delete the folder. Running it again is safe: it repairs
# what is broken and skips what is already installed.
#
# Options:
#   --check            only show the status of every component
#   --skip mongodb     do not install the bundled MongoDB server (e.g. when you already run one on localhost:27017)
#   --only zlint       install only these components (zlint, mongodb, log_list)
#   --force            reinstall ZLint and MongoDB even if they are already installed (the CT log list is kept)
#
# Advanced environment variables:
#   DCA_INSTALL_DIR    where "curl | bash" puts the project (default: ~/DigitalCertiAnalytics)
#   DCA_ARCHIVE_URL    the project archive "curl | bash" downloads (default: the main branch on GitHub)
#
# The script is POSIX sh. All of it is in functions and runs from the last line, so a download through "curl | bash"
# that stops half-way runs nothing.

UV_VERSION="0.12.24"
PYTHON_VERSION="3.12"
# Newest upload date of the Python packages, so every installation gets the same versions
PACKAGES_EXCLUDE_NEWER="2026-10-01T00:00:00Z"
PROJECT_ARCHIVE_URL="https://github.com/MagliariElio/DigitalCertiAnalytics/archive/refs/heads/main.tar.gz"
UV_MIRRORS="https://releases.astral.sh/github/uv/releases/download https://github.com/astral-sh/uv/releases/download"

# --- Messages ---------------------------------------------------------------------------------------------------------

setup_colors() {
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
        BOLD=$(printf '\033[1m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m')
        RED=$(printf '\033[31m'); RESET=$(printf '\033[0m')
    else
        BOLD=""; GREEN=""; YELLOW=""; RED=""; RESET=""
    fi
}

say() { printf '%s\n' "$*"; }
step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$RESET"; }
ok() { printf '    %s[ OK ]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() {
    printf '    %s[WARN]%s %s\n' "$YELLOW" "$RESET" "$1"
    [ -n "${2:-}" ] && printf '           What to do: %s\n' "$2"
    return 0
}
# fail MESSAGE HINT: print what went wrong and what to do, then stop
fail() {
    printf '\n    %s[FAIL]%s %s\n' "$RED" "$RESET" "$1" >&2
    [ -n "${2:-}" ] && printf '           What to do: %s\n' "$2" >&2
    exit 1
}

usage() {
    # Not read from this file: under "curl | bash" there is no file
    cat <<'EOF'
Installer of DigitalCertiAnalytics for macOS and Linux.

From the project folder:            sh install.sh        (on macOS you can also double-click install.command)
Without a copy of the project:      curl -fsSL https://raw.githubusercontent.com/MagliariElio/DigitalCertiAnalytics/main/install.sh | bash
                                    (it downloads the project into ~/DigitalCertiAnalytics first; run inside a copy
                                    of the project, it updates that copy)

Everything is installed inside the project folder (.tools, .venv, data): no administrator rights are needed and
nothing is changed elsewhere on the computer. To uninstall, delete the folder. Running it again is safe: it repairs
what is broken and skips what is already installed.

Options:
  --check            only show the status of every component
  --skip mongodb     do not install the bundled MongoDB server (e.g. when you already run one on localhost:27017)
  --only zlint       install only these components (zlint, mongodb, log_list)
  --force            reinstall ZLint and MongoDB even if they are already installed (the CT log list is kept)

Advanced environment variables:
  DCA_INSTALL_DIR    where "curl | bash" puts the project (default: ~/DigitalCertiAnalytics)
  DCA_ARCHIVE_URL    the project archive "curl | bash" downloads (default: the main branch on GitHub)
EOF
}

on_interrupt() {
    printf '\n\nThe installation was interrupted. Run the installer again: it continues where it stopped.\n' >&2
    exit 130
}

# --- Helpers ----------------------------------------------------------------------------------------------------------

is_project_dir() {
    [ -n "$1" ] && [ -f "$1/requirements.txt" ] && [ -f "$1/src/analysis/main.py" ] && [ -f "$1/scripts/install_tools.py" ]
}

has_command() { command -v "$1" >/dev/null 2>&1; }

# fetch URL FILE: download with curl or wget, with retries
fetch() {
    if has_command curl; then
        if [ -t 2 ]; then fetch_progress="-#"; else fetch_progress="-sS"; fi
        curl -fL "$fetch_progress" --retry 3 --retry-delay 3 --connect-timeout 30 -o "$2" "$1"
    elif has_command wget; then
        wget -q -O "$2" "$1"
    else
        fail "Neither curl nor wget is installed, so nothing can be downloaded." \
             "Install curl with your package manager (for example: sudo apt install curl) and run the installer again."
    fi
}

sha256_of() {
    if has_command sha256sum; then sha256sum "$1" | awk '{print $1}'
    elif has_command shasum; then shasum -a 256 "$1" | awk '{print $1}'
    elif has_command openssl; then openssl dgst -sha256 "$1" | awk '{print $NF}'
    else echo ""
    fi
}

uv_sha256() {
    case "$1" in
        aarch64-apple-darwin) echo 0c4346de7abdb49495b393b9ec809fe387aa43e586be20fecb972216c1e71732 ;;
        x86_64-apple-darwin) echo 4fa82e37cb94767661f532b001e470b67a186c7260e305bd84ddb78fd545c0b6 ;;
        x86_64-unknown-linux-gnu) echo b4dfaef47d491a7296981f8374a4595f55dbf84e8937c8ecd2983574d8bb3da6 ;;
        aarch64-unknown-linux-gnu) echo 5231be65f496304623895dacdbf1de8504fec90303684bdf05805aa34414dd21 ;;
        *) echo "" ;;
    esac
}

cannot_run_hint() {
    echo "The disk or folder may not allow running programs (a USB stick, a network share or a folder mounted" \
         "with 'noexec'), or an antivirus blocked it. Move the project folder into your home folder and run the" \
         "installer again."
}

# --- Platform ---------------------------------------------------------------------------------------------------------

# Alpine and the other Linux systems built on the musl C library (a glibc system can have the musl loader too)
is_musl() {
    if getconf GNU_LIBC_VERSION >/dev/null 2>&1; then return 1; fi
    if has_command ldd && ldd --version 2>&1 | grep -qi musl; then return 0; fi
    for loader in /lib/ld-musl-*; do [ -e "$loader" ] && return 0; done
    return 1
}

detect_platform() {
    case "$(uname -s)" in
        Darwin) OS=macos ;;
        Linux) OS=linux ;;
        *) fail "This installer works on macOS and Linux only (this system is $(uname -s))." \
                "On Windows, double-click install.bat in the project folder instead." ;;
    esac
    machine=$(uname -m)
    case "$machine" in
        x86_64|amd64) ARCH=x86_64 ;;
        arm64|aarch64) ARCH=aarch64 ;;
        *) fail "This computer has a '$machine' processor, which is not supported." \
                "A 64-bit computer is needed (Intel/AMD x86_64, or ARM64 such as Apple Silicon)." ;;
    esac
    if [ "$OS" = macos ]; then
        # A Terminal running under Rosetta reports x86_64 on an Apple Silicon Mac: use the native builds
        if [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ]; then ARCH=aarch64; fi
        UV_TRIPLE="$ARCH-apple-darwin"
    else
        if [ "$(getconf LONG_BIT 2>/dev/null)" = 32 ]; then
            fail "This is a 32-bit Linux system, which is not supported." "Use a 64-bit Linux system."
        fi
        if is_musl; then
            # Several of the Python packages (pymongo, matplotlib, ...) have no ready-made versions for musl
            fail "Alpine Linux and the other Linux systems based on musl are not supported." \
                 "Use a Linux system based on glibc, such as Ubuntu, Debian or Fedora (also fine in a container or a virtual machine)."
        fi
        UV_TRIPLE="$ARCH-unknown-linux-gnu"
    fi
}

# --- Project folder ---------------------------------------------------------------------------------------------------

# Sets PROJECT: the folder of this script, else the current folder, else a fresh download (for "curl | bash").
# "curl | bash" run inside a copy of the project updates that copy, as a run from another folder updates
# ~/DigitalCertiAnalytics (or DCA_INSTALL_DIR).
locate_project() {
    case "$0" in
        */install.sh|install.sh) script_dir=$(cd "$(dirname "$0")" 2>/dev/null && pwd -P) ;;
        *) script_dir="" ;;
    esac
    if is_project_dir "$script_dir"; then PROJECT=$script_dir; return 0; fi
    here=$(pwd -P)
    # A copy of install.sh run in the project folder, or --check, which never changes anything
    if is_project_dir "$here" && { [ -n "$script_dir" ] || [ -n "$check_only" ]; }; then PROJECT=$here; return 0; fi
    if is_project_dir "$here" && [ -z "${DCA_INSTALL_DIR:-}" ]; then download_project "$here" "$@"; fi
    download_project "${DCA_INSTALL_DIR:-"$HOME/DigitalCertiAnalytics"}" "$@"
}

# download_project FOLDER ARGUMENTS...: put the newest version of the project into FOLDER, then run its installer
download_project() {
    target=$1
    shift
    archive_url=${DCA_ARCHIVE_URL:-$PROJECT_ARCHIVE_URL}
    if [ -e "$target" ] && ! is_project_dir "$target" && [ -n "$(ls -A "$target" 2>/dev/null)" ]; then
        fail "The folder $target already exists and does not contain DigitalCertiAnalytics." \
             "Rename or move that folder, or choose another one with DCA_INSTALL_DIR=/path/to/folder, and run the command again."
    fi
    if [ -d "$target/.git" ]; then
        say "Found a git copy of the project in $target: it is used as it is (update it with 'git pull')."
    else
        step "Downloading DigitalCertiAnalytics into $target"
        say "    Your data in that folder (data/, res/certs_polito.json, the analysis results) is kept."
        mkdir -p "$target" || fail "Could not create the folder $target." "Choose another folder with DCA_INSTALL_DIR."
        bootstrap="$target/.tools/cache/bootstrap"
        rm -rf "$bootstrap" && mkdir -p "$bootstrap/files" || fail "Could not write into $target." "Check the folder permissions."
        fetch "$archive_url" "$bootstrap/project.tar.gz" ||
            fail "Could not download the project from $archive_url." "Check your internet connection and run the command again."
        tar -xzf "$bootstrap/project.tar.gz" -C "$bootstrap/files" ||
            fail "The downloaded project archive is damaged." "Run the command again."
        top=""
        for entry in "$bootstrap/files"/*; do [ -d "$entry" ] && top=$entry && break; done
        is_project_dir "$top" || fail "The downloaded archive does not contain DigitalCertiAnalytics." \
                                      "Check the address in DCA_ARCHIVE_URL, or run the command again."
        # Only the project's own files are replaced: data/, .tools/, .venv/ and res/certs_polito.json are not in it
        (cd "$top" && tar -cf - .) | (cd "$target" && tar -xf -) || fail "Could not copy the project into $target." \
                                                                        "Check the free disk space and run the command again."
        rm -rf "$bootstrap"
        ok "Project downloaded into $target"
    fi
    # Continue with the installer that came with the downloaded project
    exec /bin/sh "$target/install.sh" "$@" </dev/null
}

# --- Checks before installing -----------------------------------------------------------------------------------------

restore_permissions() {
    # ZIP downloads can lose the executable bit; macOS marks files from the internet as "quarantined"
    chmod +x "$PROJECT/install.sh" "$PROJECT/install.command" "$PROJECT/dca" "$PROJECT/dca.command" 2>/dev/null
    if [ "$OS" = macos ] && has_command xattr; then
        for script in install.sh install.command dca dca.command; do
            xattr -d com.apple.quarantine "$PROJECT/$script" 2>/dev/null
        done
    fi
    return 0
}

check_location() {
    if [ "$(id -u 2>/dev/null)" = 0 ]; then
        warn "The installer is running as administrator (root), which is not needed." \
             "Run it as your normal user, without sudo, so that the files stay yours."
    fi
    case "$PROJECT" in
        /mnt/[a-zA-Z]/*)
            case "$(uname -r 2>/dev/null)" in
                *[Mm]icrosoft*|*WSL*)
                    warn "The project is on a Windows drive ($PROJECT), used from WSL." \
                         "That is very slow, and the database files can be damaged there: install into the Linux home folder instead, by running the curl command after 'cd ~' (it installs into ~/DigitalCertiAnalytics)." ;;
            esac ;;
    esac
    case "$PROJECT" in
        *"/Library/Mobile Documents/"*|*"/Library/CloudStorage/"*|*/Dropbox/*|*/OneDrive*)
            warn "The project is in a folder synchronised with the cloud ($PROJECT)." \
                 "Cloud syncing of the large databases slows everything down and can damage them: move the project to a folder that is not synchronised, such as ~/DigitalCertiAnalytics." ;;
    esac
    if [ "$OS" = macos ] && [ -d "$HOME/Library/Mobile Documents/com~apple~CloudDocs/Desktop" ]; then
        case "$PROJECT" in
            "$HOME/Desktop/"*|"$HOME/Documents/"*)
                warn "iCloud synchronises your Desktop and Documents folders, and the project is inside one of them." \
                     "Move the project to a folder that is not synchronised, such as ~/DigitalCertiAnalytics, to avoid slow and damaged databases." ;;
        esac
    fi
    free_kb=$(df -Pk "$PROJECT" 2>/dev/null | awk 'NR==2 {print $4}')
    if [ -n "$free_kb" ] && [ "$free_kb" -lt 2000000 ] 2>/dev/null; then
        warn "Only $((free_kb / 1024)) MB of disk space are free: the installation needs about 1.5 GB." \
             "Free some disk space if the installation fails."
    fi
}

# --- uv, Python and the virtual environment ---------------------------------------------------------------------------

uv_is_suitable() {
    [ -n "$1" ] && [ -x "$1" ] || return 1
    uv_reported=$("$1" --version 2>/dev/null) || return 1
    case "$uv_reported" in
        "uv $UV_VERSION"|"uv $UV_VERSION "*) return 0 ;;
    esac
    return 1
}

install_uv() {
    step "uv $UV_VERSION (installs Python and the Python packages)"
    UV="$PROJECT/.tools/uv/uv"
    if uv_is_suitable "$UV"; then ok "uv $UV_VERSION is already installed"; return 0; fi
    system_uv=$(command -v uv 2>/dev/null)
    if uv_is_suitable "$system_uv"; then UV=$system_uv; ok "Using uv $UV_VERSION already installed in $UV"; return 0; fi

    expected=$(uv_sha256 "$UV_TRIPLE")
    [ -n "$expected" ] || fail "uv has no build for this system ($UV_TRIPLE)." "A 64-bit macOS or Linux computer is needed."
    file="uv-$UV_TRIPLE.tar.gz"
    work="$PROJECT/.tools/cache/uv-download"
    rm -rf "$work" && mkdir -p "$work" || fail "Could not write into $PROJECT/.tools." "Check the folder permissions."
    downloaded=""
    for mirror in $UV_MIRRORS; do
        mirror_host=${mirror#https://}
        say "           Downloading $file (about 15 MB) from ${mirror_host%%/*}..."
        if fetch "$mirror/$UV_VERSION/$file" "$work/$file"; then
            actual=$(sha256_of "$work/$file")
            [ -n "$actual" ] || fail "No program to verify the download (sha256sum, shasum or openssl) was found." \
                                     "Install coreutils or openssl with your package manager and run the installer again."
            if [ "$actual" = "$expected" ]; then downloaded=1; break; fi
            warn "The file downloaded from $mirror does not match its expected SHA-256 checksum, so it was deleted."
            rm -f "$work/$file"
        fi
    done
    [ -n "$downloaded" ] || fail "Could not download uv $UV_VERSION." \
        "Check your internet connection (behind a proxy, set HTTPS_PROXY) and run the installer again."
    tar -xzf "$work/$file" -C "$work" || fail "Could not extract $file." "Check the free disk space and run the installer again."
    mkdir -p "$PROJECT/.tools/uv" &&
        mv -f "$work/uv-$UV_TRIPLE/uv" "$work/uv-$UV_TRIPLE/uvx" "$PROJECT/.tools/uv/" &&
        chmod 755 "$PROJECT/.tools/uv/uv" "$PROJECT/.tools/uv/uvx" || fail "Could not install uv into $PROJECT/.tools/uv."
    rm -rf "$work"
    uv_is_suitable "$UV" || fail "uv was downloaded but cannot run ($UV)." "$(cannot_run_hint)"
    ok "uv $UV_VERSION installed in .tools/uv"
}

configure_environment() {
    # uv and Python stay inside the project folder (the temporary files too: see use_private_tmp)
    export UV_PYTHON_INSTALL_DIR="$PROJECT/.tools/python"
    export UV_CACHE_DIR="$PROJECT/.tools/cache/uv"
    export UV_PYTHON_INSTALL_BIN=0 UV_PYTHON_INSTALL_REGISTRY=0 UV_NO_CONFIG=1 UV_MANAGED_PYTHON=1
    export UV_PYTHON_DOWNLOADS=automatic UV_HTTP_TIMEOUT="${UV_HTTP_TIMEOUT:-300}"
    unset PYTHONHOME PYTHONPATH VIRTUAL_ENV CONDA_PREFIX UV_PYTHON UV_SYSTEM_PYTHON
    VENV_PY="$PROJECT/.venv/bin/python"
}

# Temporary files of the installation, removed at its end (not for --check, which writes nothing)
use_private_tmp() {
    export TMPDIR="$PROJECT/.tools/cache/tmp"
    mkdir -p "$TMPDIR" || fail "Could not write into $PROJECT/.tools." "Check the folder permissions and the free disk space."
}

# The .venv works and uses the project's own Python 3.12 (it breaks when the project folder is moved)
venv_is_healthy() {
    [ -x "$VENV_PY" ] || return 1
    "$VENV_PY" -c 'import os, sys; root = os.path.realpath(sys.argv[1]) + os.sep
sys.exit(0 if sys.version_info[:2] == (3, 12) and os.path.realpath(sys.base_prefix).startswith(root) else 1)' \
        "$PROJECT/.tools/python" >/dev/null 2>&1
}

install_python() {
    step "Python $PYTHON_VERSION and the Python packages"
    "$UV" python install "$PYTHON_VERSION" ||
        fail "Could not install Python $PYTHON_VERSION." "Check your internet connection and run the installer again."
    if venv_is_healthy; then
        ok "The project environment .venv is ready"
    else
        [ -e "$PROJECT/.venv" ] && say "           The project environment .venv is outdated or was moved: it is recreated."
        # Quiet: its "Activate with: source .venv/bin/activate" is not needed, the dca launcher does that
        "$UV" venv --quiet --clear --python "$PYTHON_VERSION" --prompt DigitalCertiAnalytics "$PROJECT/.venv" ||
            fail "Could not create the project environment in $PROJECT/.venv." "$(cannot_run_hint)"
        ok "Project environment created in .venv"
    fi
    "$UV" pip install --python "$VENV_PY" -r "$PROJECT/requirements.txt" \
        --only-binary :all: --no-binary sslyze --exclude-newer "$PACKAGES_EXCLUDE_NEWER" ||
        fail "Could not install the Python packages." \
             "If the messages above are about the network, check your internet connection (behind a proxy, set HTTPS_PROXY) and run the installer again. If they say that a package has no usable wheels for this system, the system is too old or not supported: use a recent 64-bit Ubuntu, Debian or Fedora, or macOS 11 or newer."
    ok "Python packages installed"
}

run_tools_installer() {
    DCA_UV_VERSION=$("$UV" --version 2>/dev/null)
    export DCA_UV_VERSION
    "$VENV_PY" "$PROJECT/scripts/install_tools.py" "$@"
    status=$?
    if [ "$OS" = macos ] && has_command xattr && [ -d "$PROJECT/.tools" ]; then
        xattr -dr com.apple.quarantine "$PROJECT/.tools" 2>/dev/null
    fi
    rm -rf "$PROJECT/.tools/cache/tmp"
    return "$status"
}

run_check_only() {
    configure_environment
    if ! venv_is_healthy; then
        printf '    %s[FAIL]%s DigitalCertiAnalytics is not installed in %s (or the folder was moved).\n' "$RED" "$RESET" "$PROJECT"
        say "           What to do: run the installer:  sh \"$PROJECT/install.sh\""
        return 1
    fi
    "$VENV_PY" "$PROJECT/scripts/install_tools.py" "$@"
}

# --- Main -------------------------------------------------------------------------------------------------------------

main() {
    setup_colors
    trap on_interrupt INT TERM
    check_only=""
    for argument in "$@"; do
        case "$argument" in
            -h|--help) usage; return 0 ;;
            --check) check_only=1 ;;
        esac
    done
    detect_platform
    has_command tar || fail "The 'tar' program is missing." "Install tar with your package manager and run the installer again."
    locate_project "$@"
    cd "$PROJECT" || fail "Could not open the folder $PROJECT."
    restore_permissions
    if [ -n "$check_only" ]; then
        run_check_only "$@"
        return $?
    fi

    say "${BOLD}DigitalCertiAnalytics installer${RESET}"
    say "Everything is installed inside $PROJECT"
    say "(no administrator rights needed; to uninstall, delete the folder)."
    check_location
    install_uv
    configure_environment
    use_private_tmp
    install_python
    run_tools_installer "$@"
}

main "$@"
