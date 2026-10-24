# Installing DigitalCertiAnalytics

This guide explains, step by step, how to install DigitalCertiAnalytics on **Windows**, **macOS** and **Linux**.
You do not need to know anything about programming: copy the commands exactly as they are written, or double-click
the files named below.

**At a glance**

- The installer does everything by itself: it downloads Python, the Python packages, ZLint and a MongoDB database
  server, and checks every download against its official checksum.
- **No administrator rights are needed.** Nothing is installed anywhere else on the computer: everything stays inside
  one folder, the *project folder*. To uninstall, delete that folder. (Only on macOS, if you double-click
  `install.command`, macOS may ask for your password once to allow it: see [Way B](#way-b-download-the-zip-file).)
- **Time:** about 1 minute on a fast connection, and up to 15 minutes on a slow connection or an older computer.
- **Download:** about 270 MB (on Windows somewhat less, because only the part of MongoDB that is needed is downloaded).
- **Disk space:** about 600 MB after the installation. About 1.2 GB must be free while it runs, because ZLint is built
  from its source code and the temporary files are deleted afterwards. The scan file you analyse can be much bigger (up
  to 80 GB), and the databases created from it need space too.
- **Running it again is safe.** It skips what is already installed and repairs what is broken, so "run the installer
  again" is the answer to most problems.

**Contents**

1. [Before you start](#1-before-you-start)
2. [Install on Windows](#2-install-on-windows)
3. [Install on macOS](#3-install-on-macos)
4. [Install on Linux](#4-install-on-linux)
5. [Check that everything works](#5-check-that-everything-works)
6. [Add the scan file](#6-add-the-scan-file)
7. [Run the program](#7-run-the-program)
8. [Update, repair, move or uninstall](#8-update-repair-move-or-uninstall)
9. [Troubleshooting](#9-troubleshooting)
10. [Manual installation (for developers)](#10-manual-installation-for-developers)

---

## 1. Before you start

**You need:**

- A 64-bit computer (almost every computer sold since 2010) with an internet connection.
- **Windows** 10 or 11 (64-bit; a computer with an ARM processor needs Windows 11), **macOS** 11 (Big Sur) or newer, or
  a 64-bit **Linux** system such as Ubuntu, Debian, Fedora, Linux Mint, Rocky Linux or openSUSE. Alpine Linux and the
  other Linux systems based on *musl* are not supported.
- About 2 GB of free disk space for the installation, plus space for your scan file and its results.

**Choose a good place for the project folder:**

- Use a normal folder on the computer's own disk, for example your home folder. The one-line installation commands below
  put the project there automatically.
- **Avoid folders that are synchronised with the cloud** (OneDrive, iCloud Drive, Dropbox, Google Drive). Syncing the
  large databases slows everything down and can damage them. On many computers the *Desktop* and *Documents* folders are
  synchronised without you noticing, so avoid them too.
- **Windows:** keep the path short, such as `C:\DCA` or `C:\Users\<you>\DigitalCertiAnalytics`. Windows has trouble
  with paths longer than 260 characters.
- Avoid USB sticks and network drives: some of them do not allow programs to run.

---

## 2. Install on Windows

Choose **one** of the two ways.

### Way A: download the ZIP file and double-click (easiest)

1. Open the project page in your browser: <https://github.com/MagliariElio/DigitalCertiAnalytics>
2. Click the green **Code** button, then **Download ZIP**.
3. Open your **Downloads** folder, right-click `DigitalCertiAnalytics-main.zip` and choose **Extract All...**.
   Change the destination to a short folder such as `C:\DCA` and click **Extract**.
   - Do not run anything from *inside* the ZIP file without extracting it first: it does not work.
   - Windows often creates a folder inside a folder (`DigitalCertiAnalytics-main\DigitalCertiAnalytics-main`). Open
     the folders until you see the file `install.bat`.
4. Double-click **`install.bat`**. If Windows hides file extensions, it is shown as `install` with the type
   *Windows Batch File*.
5. Windows may show a blue window, **"Windows protected your PC"**. This happens because the file was downloaded from
   the internet and is not signed by a company. Click **More info**, then **Run anyway**. (Some versions instead show
   *"The publisher could not be verified. Are you sure you want to run this software?"*: click **Run**.) Do this only if
   you downloaded the ZIP from the official page above. You see this warning only once: the installer removes the
   "downloaded from the internet" mark from the project files.
6. A black window opens and shows the progress. Wait until it shows **"Done. You can close this window."**, then press
   any key.

### Way B: one line in PowerShell

1. Click the **Start** button, type `PowerShell` and open **Windows PowerShell**. You do *not* need
   "Run as administrator".
2. Copy this line, paste it into the PowerShell window (right-click pastes) and press **Enter**:

   ```powershell
   powershell -ExecutionPolicy Bypass -c "irm https://raw.githubusercontent.com/MagliariElio/DigitalCertiAnalytics/main/install.ps1 | iex"
   ```

   `-ExecutionPolicy Bypass` allows the installer to run for this one command only: no setting of the computer is
   changed. (If your PowerShell already allows scripts, the short form
   `irm https://raw.githubusercontent.com/MagliariElio/DigitalCertiAnalytics/main/install.ps1 | iex` does the same.)
3. The project is downloaded into `C:\Users\<you>\DigitalCertiAnalytics` and installed there. Wait until the summary
   appears (see [what you will see](#what-you-will-see)). Files downloaded this way get no security warnings.

To install into another folder, run `$env:DCA_INSTALL_DIR = 'C:\DCA'` first, then the line above.

---

## 3. Install on macOS

Choose **one** of the two ways. Way A is the easiest, because macOS shows no security warnings for it.

### Way A: one line in Terminal (recommended)

1. Open **Terminal**: press **Cmd + Space**, type `Terminal` and press **Enter**.
2. Copy this line, paste it into the Terminal window (**Cmd + V**) and press **Enter**:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/MagliariElio/DigitalCertiAnalytics/main/install.sh | bash
   ```

3. The project is downloaded into the folder `DigitalCertiAnalytics` in your home folder
   (`/Users/<you>/DigitalCertiAnalytics`; in Finder use **Go > Home**) and installed there. Wait until the summary
   appears (see [what you will see](#what-you-will-see)).

To install into another folder, put `DCA_INSTALL_DIR=/path/to/folder` before `bash` at the end of the line, for
example `... | DCA_INSTALL_DIR="$HOME/Projects/DigitalCertiAnalytics" bash`.

### Way B: download the ZIP file

1. Open <https://github.com/MagliariElio/DigitalCertiAnalytics>, click the green **Code** button, then
   **Download ZIP**. Safari unzips it into your **Downloads** folder by itself (otherwise double-click the ZIP file).
2. Move the folder `DigitalCertiAnalytics-main` to your home folder: in Finder choose **Go > Home** (or press
   **Shift + Cmd + H**) to open your home folder in a new window, then drag the folder from **Downloads** into it. (Not
   to the Desktop or Documents if iCloud synchronises them.)
3. Start the installer in **one** of these two ways:
   - **In Terminal (no security questions):** open **Terminal** (press **Cmd + Space**, type `Terminal`, press
     **Enter**), paste this line and press **Enter**:

     ```bash
     sh ~/DigitalCertiAnalytics-main/install.sh
     ```

   - **By double-click:** double-click **`install.command`** in that folder. A Terminal window opens and shows the
     progress; at the end it says **"Done. You can close this window."** Press **Enter** to close it.

macOS checks files downloaded with a browser, so the first double-click of `install.command` is blocked:

- **macOS 15 (Sequoia) and newer:** a message says *"Apple could not verify 'install.command' is free of malware..."*.
  Click **Done**. Open **System Settings > Privacy & Security**, scroll down to **Security**, and next to
  *"'install.command' was blocked..."* click **Open Anyway**. Enter your password (on a computer where you are not an
  administrator, macOS may ask for an administrator's name and password), then click **Open Anyway** again. If that is
  not possible, use the Terminal line above instead.
- **macOS 14 and older:** Control-click (or right-click) `install.command`, choose **Open**, then click **Open**.
- If macOS says the file *"could not be executed because you do not have appropriate access privileges"*, use the
  Terminal line above instead.

macOS may also ask *"Terminal would like to access files in your Desktop folder"* (or Documents, or Downloads). Click
**Allow**: the installer needs to write into the project folder.

---

## 4. Install on Linux

1. Open a terminal (on Ubuntu: press **Ctrl + Alt + T**).
2. Copy this line, paste it into the terminal (**Ctrl + Shift + V**) and press **Enter**:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/MagliariElio/DigitalCertiAnalytics/main/install.sh | bash
   ```

   Ubuntu does not always include `curl`. If the terminal says `curl: command not found`, use this line instead:

   ```bash
   wget -qO- https://raw.githubusercontent.com/MagliariElio/DigitalCertiAnalytics/main/install.sh | bash
   ```

3. The project is downloaded into `~/DigitalCertiAnalytics` (the folder `DigitalCertiAnalytics` in your home folder)
   and installed there. Wait until the summary appears (see [what you will see](#what-you-will-see)).

**From a downloaded ZIP file:** extract it, open the extracted folder in the file manager, right-click an empty area
and choose **Open in Terminal**, then type `sh install.sh` and press **Enter**. Double-clicking `install.sh` usually
opens it in a text editor instead of running it.

Do not use `sudo`: the installer does not need administrator rights, and files created as administrator would not
belong to you.

---

### What you will see

The installer prints one section per part (`==> uv`, `==> Python 3.12 and the Python packages`, `==> ZLint`,
`==> MongoDB server`, `==> Certificate Transparency log list`) and ends with a summary like this one:

```text
==> Summary
  [ OK ] Python           Python 3.12.15 in .venv
  [ OK ] Python packages  10 packages of requirements.txt installed
  [ OK ] sslyze           /Users/you/DigitalCertiAnalytics/.venv/bin/sslyze
  [ OK ] ZLint            v3.6.5-0.20241104164204-989baefda32f (.tools/zlint)
  [ OK ] MongoDB          8.0.34 (.tools/mongodb, started by the program when needed)
  [ OK ] CT log list      res/log_list.json (165 logs)
  [ OK ] Launcher         /Users/you/DigitalCertiAnalytics/dca
  [INFO] Scan file        res/certs_polito.json is not there yet
                          What to do: Put the ZGrab2 output there before running the *_analysis options (see INSTALL.md, step 6 "Add the scan file").
  [WARN] Disk space       78 GB free
                          What to do: A large scan (up to 80 GB) and its SQLite databases need much more space: ...

DigitalCertiAnalytics is installed.
```

- **`[ OK ]`** (green): this part works.
- **`[INFO]`**: for your information. *Scan file* is `INFO` until you add your scan file (see
  [step 6](#6-add-the-scan-file)).
- **`[WARN]`** (yellow): it works, but read the *What to do* line. *Disk space* is `WARN` when less than 100 GB are free;
  that matters only for very large scans.
- **`[FAIL]`** (red): this part does not work yet. The *What to do* line says how to fix it; then run the installer
  again. See also [Troubleshooting](#9-troubleshooting).

A copy of everything the installer printed is saved in the file `.tools/install.log` inside the project folder, which
is useful if you ask someone for help.

---

## 5. Check that everything works

You can print the summary again at any time, without installing anything. It takes less than a second.

First open a terminal **in the project folder**:

- **Windows:** open the project folder in File Explorer, click the address bar at the top, type `cmd` and press
  **Enter**. A black *Command Prompt* window opens in that folder.
- **macOS:** open Terminal, type `cd ` (with a space after it), drag the project folder from Finder into the Terminal
  window, and press **Enter**. If you used the one-line installation, typing `cd ~/DigitalCertiAnalytics` and
  pressing **Enter** does the same.
- **Linux:** right-click an empty area of the project folder in the file manager and choose **Open in Terminal**, or
  type `cd ~/DigitalCertiAnalytics` and press **Enter**.

Then type the command for your system and press **Enter**:

| System        | Command                  |
|---------------|--------------------------|
| Windows       | `install.bat --check`    |
| macOS, Linux  | `./install.sh --check`   |

It ends with **"Everything needed is ready."** when every required part works (on Windows, press any key to close
the message). If a line says `[FAIL]`, it ends with
*"Not ready: ..."*: follow the *What to do* line and run the installer again.

---

## 6. Add the scan file

The program analyses the output of a ZGrab2 scan (see [the README](README.md#tool-used-zgrab2)). It always reads it
from this file inside the project folder:

```text
res/certs_polito.json
```

1. Open the project folder, then the folder `res` inside it.
2. Copy your scan file into `res`.
3. Rename it to exactly `certs_polito.json`. On Windows, if file extensions are hidden, type only `certs_polito`:
   otherwise the file ends up named `certs_polito.json.json`.

The file can be very large (up to 80 GB), so make sure the disk has enough free space for it and for the databases
created from it. Run the check of [step 5](#5-check-that-everything-works) again: the *Scan file* line now says
`[ OK ]` with the size of the file.

*Advanced (macOS, Linux):* to avoid copying a very large file, you can put a link to it instead:
`ln -s "/path/to/your/scan.json" res/certs_polito.json`.

The other input file, `res/log_list.json` (the list of the Certificate Transparency logs), is already included. The
installer downloads it from Google only if it is missing.

---

## 7. Run the program

The program is started with the **`dca`** launcher in the project folder (`dca.bat` on Windows). It always uses the
project's own Python and tools, from whatever folder you start it.

### By double-click

- **Windows:** double-click **`dca.bat`**.
- **macOS:** double-click **`dca.command`**.

A window opens with the list of options. Type the options you want, for example
`--leaf_analysis --plot_leaf_results`, and press **Enter**. At the end the window waits for a key press, so you can
read the result. Press **Enter** without typing anything to close it.

### From a terminal

Open a terminal in the project folder (see [step 5](#5-check-that-everything-works)), then:

| What you want to do                                       | macOS, Linux                               | Windows                                       |
|-----------------------------------------------------------|--------------------------------------------|-----------------------------------------------|
| Show all the options                                      | `./dca --help`                             | `dca.bat --help`                              |
| Analyse the leaf certificates and draw their charts       | `./dca --leaf_analysis --plot_leaf_results` | `dca.bat --leaf_analysis --plot_leaf_results` |
| Analyse leaf, intermediate and root certificates, all charts | `./dca --leaf_analysis --intermediate_analysis --root_analysis --plot_all_results` | `dca.bat --leaf_analysis --intermediate_analysis --root_analysis --plot_all_results` |
| Check the OCSP status of the leaf certificates (internet) | `./dca --leaf_ocsp_analysis`               | `dca.bat --leaf_ocsp_analysis`                |
| Check the leaf certificates with ZLint                    | `./dca --leaf_zlint_check`                 | `dca.bat --leaf_zlint_check`                  |
| Validate the certificate chains with sslyze (internet)    | `./dca --leaf_chain_validation`            | `dca.bat --leaf_chain_validation`             |
| Show more details while it runs                           | add `-v`                                   | add `-v`                                      |

In PowerShell, type `.\dca.bat` instead of `dca.bat`. The full list of options and more examples are in the
[README](README.md#2-run-the-program). The help text starts with `usage: python -m analysis.main`: that is the command
the launcher runs for you.

Good to know:

- Start with `--leaf_analysis` (or `--intermediate_analysis`, `--root_analysis`): it reads the scan file and creates the
  database that the other options work on.
- `--leaf_zlint_check` and `--intermediate_zlint_check` store their results in MongoDB. The program starts the MongoDB
  server included in the project by itself and stops it at the end. You do not need to do anything.
- `--leaf_ocsp_analysis`, `--intermediate_ocsp_analysis`, `--root_ocsp_analysis` and `--leaf_chain_validation` contact
  servers on the internet.
- **The results** are in the folder `src/analysis` inside the project folder: one folder per certificate type
  (`leaf`, `intermediate`, `root`), each with its database (`leaf_certificates.db`, ...) and a `plots` folder with the
  charts. The program's log is the file `src/app.log`.
- **To stop the program**, press **Ctrl + C** and wait until it has stopped. What is already saved stays saved, and an
  interrupted OCSP analysis continues where it stopped the next time. On Windows, the window then asks *"Terminate
  batch job (Y/N)?"*: type `Y` and press **Enter** (either answer is fine). Prefer Ctrl + C to closing the window. (On
  macOS and Linux, closing the window while ZLint runs works like Ctrl + C: the results are saved and the MongoDB server
  is stopped.)
- If you type an option wrongly in the window of `dca.command` or `dca.bat` (for example without the two dashes), the
  window says so and asks again.
- A full analysis of a large scan can take many hours. Keep the computer plugged in, and set it not to go to sleep. On
  macOS you can put `caffeinate -i` in front of the command, which keeps the Mac awake while the program runs:
  `caffeinate -i ./dca --leaf_analysis`.
- `dca` also works from another folder, for example `~/DigitalCertiAnalytics/dca --help` or
  `C:\DCA\dca.bat --help`.

---

## 8. Update, repair, move or uninstall

### Update to the newest version

- **If you installed with the one-line command** (sections 2B, 3A and 4): run the same line again. It downloads the
  newest version into the same folder and **keeps your data**: the scan file `res/certs_polito.json`, the databases and
  charts in `src/analysis`, and the MongoDB data in `data`. Then it updates the installation.
- **If you installed from a ZIP file:** open a terminal **in the project folder** (see
  [step 5](#5-check-that-everything-works); on Windows open **PowerShell** there, for example by typing `powershell`
  instead of `cmd` in the address bar), then run the one-line command of your system
  ([Windows Way B](#way-b-one-line-in-powershell), [macOS Way A](#way-a-one-line-in-terminal-recommended),
  [Linux](#4-install-on-linux)). Run inside a copy of the project, it updates that copy and keeps your data, as above.
- **If you use `git`:** run `git pull`, then the installer. The one-line command leaves a git copy unchanged.

### Repair

Run the installer again, the same way you installed it (double-click `install.bat` or `install.command`, or type
`sh install.sh` in the project folder). It checks every part, skips what works and reinstalls what is broken or
missing.

To reinstall ZLint and MongoDB even though they look fine, add `--force`:

| System        | Command                     |
|---------------|-----------------------------|
| Windows       | `install.bat --force`       |
| macOS, Linux  | `sh install.sh --force`     |

`--force` keeps the CT log list `res/log_list.json` that comes with the project, which includes logs that Google's
current list no longer contains. To replace it with Google's current list anyway, use `--force --only log_list`: the
previous list is kept as `res/log_list.json.old`. For a completely clean reinstallation, delete the folders `.tools`
and `.venv` inside the project folder and run the installer again. Your results and data are not in those folders.
(On macOS, folders whose name starts with a dot are hidden: press **Cmd + Shift + .** in Finder to show them.)

Other installer options: `--skip mongodb` (do not install the MongoDB server, for example because you already run your
own) and `--only zlint,mongodb,log_list` (install only those parts).

### Move the project folder

You can move or rename the project folder, but the installation remembers where it was. After moving it, `dca` says
*"DigitalCertiAnalytics is not installed yet, or the project folder was moved."*: run the installer again in the new
place. It takes only a few seconds, because nothing is downloaded again.

### Uninstall

1. Make sure the program is not running: let it finish, or press **Ctrl + C** in its window and wait until it has
   stopped (the window of `dca.command` or `dca.bat` then says *"Press Enter to close this window"* or *"Press any key
   to continue"*). Then close the window.
2. Copy anything you want to keep to another place: your scan file `res/certs_polito.json`, the results in
   `src/analysis`, and the ZLint results in `data`.
3. Delete the project folder.

That is all: nothing was installed anywhere else, and no settings of the computer were changed. On Windows, if a file
"is open in another program", restart the computer and delete the folder again.

---

## 9. Troubleshooting

Every error message of the installer and of the program ends with a **"What to do:"** line, or says what to do in the
message itself. Here are the most common ones.

### No internet connection, or a company or university network

*"Could not download uv 0.12.24."*, *"Could not download Go 1.27.2: ..."*, *"Could not install the Python packages."*
(when the messages above it are about the network)

- Check that the computer is online, then run the installer again: it continues where it stopped (partial downloads
  are resumed).
- **Behind a proxy**, tell the installer its address, then run the installer **in the same window**:
  - macOS, Linux: `export HTTPS_PROXY=http://proxy.example.org:8080`
  - Windows (Command Prompt): `set HTTPS_PROXY=http://proxy.example.org:8080`, then `install.bat`
  - Windows (PowerShell): `$env:HTTPS_PROXY = 'http://proxy.example.org:8080'`
- *"The secure connection could not be verified..."*: the network inspects encrypted traffic. Ask your IT department
  for the file with the organisation's certificates and set `SSL_CERT_FILE` to it (and `UV_SYSTEM_CERTS=1`), in the
  same way as `HTTPS_PROXY` above.
- If the network blocks some websites, ask your IT department to allow these addresses: `github.com`,
  `objects.githubusercontent.com`, `release-assets.githubusercontent.com`, `raw.githubusercontent.com`,
  `codeload.github.com`, `releases.astral.sh`, `pypi.org`, `files.pythonhosted.org`, `go.dev`, `dl.google.com`,
  `proxy.golang.org`, `sum.golang.org`, `fastdl.mongodb.org`, `www.gstatic.com`.

### ZLint: "Building ZLint failed"

ZLint is built from its source code, which Go downloads from `proxy.golang.org`. If that fails (usually a network that
blocks it), the installer installs the official ready-made ZLint 3.6.4 instead, and the summary shows:

```text
  [WARN] ZLint  prebuilt ZLint 3.6.4 (the analysis uses v3.6.5-0.20241104164204-989baefda32f)
                What to do: Run the installer again to build the exact version (it needs proxy.golang.org).
```

Everything works, with 3 checks fewer. Run the installer again later from another network to get the exact version:
the downloaded Go is kept for that, so it is not downloaded again. On a company network you may need to set `GOPROXY`
(in China: `GOPROXY=https://goproxy.cn,direct`), in the same way as `HTTPS_PROXY` above.

On macOS 11 and 12 ZLint is built with Go 1.24, because newer Go versions need macOS 13; the result is the same ZLint.

The ready-made ZLint is an Intel program. On a Mac with Apple Silicon it needs Apple's Rosetta: if Rosetta is missing,
the message says so and gives the command that installs it, `softwareupdate --install-rosetta --agree-to-license`
(it asks for your password). Then run the installer again.

### MongoDB "cannot be installed on this computer"

```text
    [WARN] The MongoDB server cannot be installed on this computer: this processor has no AVX instructions,
           which MongoDB 5.0 and newer need (Intel 2011 or newer).
```

This is a warning, not an error: **everything else works**. Only the ZLint checks (`--leaf_zlint_check`,
`--intermediate_zlint_check`) need MongoDB. The reason is in the message:

- **The processor is too old**: no AVX instructions (some Intel Celeron, Pentium and Atom processors, very old PCs and
  some virtual machines), or an ARM processor older than ARMv8.2 (for example a Raspberry Pi 4; a Raspberry Pi 5
  works).
- **The system has no MongoDB version**: for example NixOS.
- **A system library is missing** (*"the system library libcurl.so.4 is missing"*): the message gives the command that
  installs it, for example `sudo apt install libcurl4 openssl` (Ubuntu 24.04 and newer: `sudo apt install libcurl4t64
  openssl`) or `sudo dnf install libcurl openssl xz-libs`. This needs your administrator password. Then run the
  installer again.
- **Windows: "The Microsoft Visual C++ runtime that MongoDB needs is not installed."** Download and run
  <https://aka.ms/vs/17/release/vc_redist.x64.exe> (it asks once for administrator permission; on a computer managed by
  an IT department, ask them), then run `install.bat` again.

To run the ZLint checks anyway, install MongoDB yourself (<https://www.mongodb.com/docs/manual/administration/install-community/>)
and keep it running on this computer (`localhost`, port 27017): the program finds and uses it by itself, and
`./install.sh --check` (or `install.bat --check`) then shows `[ OK ]`. Or run the ZLint checks on another computer.

Linux distributions without an official MongoDB version (for example Fedora, Arch Linux or Manjaro) get the closest
compatible version, which the installer tests before keeping it.

### Not enough disk space

*"Not enough free disk space for building ZLint: 1.0 GB are needed, only 0.4 GB are free on the disk of ..."*

Free some disk space (empty the Trash or Recycle Bin, delete large files you do not need), or move the project folder
to a disk with more free space, then run the installer again. Remember that the scan file and its databases need much
more space than the installation.

### Antivirus, or a disk that cannot run programs

*"uv was downloaded but cannot run"*, *"The program could not run (...). The disk or folder may not allow running
programs ..."*

- The project folder may be on a USB stick, a network drive or a disk that does not allow running programs. Move it to
  your home folder and run the installer again.
- An antivirus may have blocked or deleted a downloaded program (ZLint and MongoDB are sometimes flagged by mistake).
  Allow the project folder in the antivirus (this may need your IT department), then run the installer again.
- An antivirus that scans every file can make the installation and the analysis much slower. That is normal.

### Windows: other messages

- *"The project folder has a long path (... characters), and Windows limits paths to 260 characters."* Move the
  project to a short folder such as `C:\DCA` and run `install.bat` again.
- *"The project is inside OneDrive ..."* Move the project to a folder outside OneDrive, such as `C:\DCA`.
- *"The argument '...install.ps1' to the -File parameter does not exist."* `install.bat` was started from inside the
  ZIP file. Extract the ZIP first (right-click, **Extract All...**) and run `install.bat` from the extracted folder.
- *"running scripts is disabled on this system"*: you started `install.ps1` directly. Double-click `install.bat`
  instead, which allows the script for this run only. If it is still blocked, the computer is managed by an
  organisation that does not allow scripts: ask the IT department.

### macOS and Linux: other messages

- *"Could not install the Python packages."* followed by *"has no usable wheels"* or *"Wheels are required"*: the
  system is too old or not supported (for example Alpine Linux, which the installer refuses at the start). Use a recent
  64-bit Ubuntu, Debian or Fedora, or macOS 11 or newer.
- *"The project is on a Windows drive (/mnt/c/...), used from WSL."*: in WSL, install into the Linux home folder
  instead: type `cd ~`, then the one-line command of [section 4](#4-install-on-linux).
- *"zsh: permission denied: ./dca"* or *"./install.sh: Permission denied"*: start it with `sh`, for example
  `sh install.sh` or `sh dca --help`. The installer then fixes the permissions of the files, so `./dca` works again.
- *"The installer is running as administrator (root), which is not needed."* Run it again without `sudo`.
- *"... folder synchronised with the cloud ..."* or *"iCloud synchronises your Desktop and Documents folders ..."*:
  move the project to a folder that is not synchronised, such as `~/DigitalCertiAnalytics`, and run the installer
  again.

### Messages while the program runs

- *"DigitalCertiAnalytics is not installed yet, or the project folder was moved."* Run the installer (again) in the
  project folder.
- *"The file '.../res/certs_polito.json' does not exist or has a different name"*: put the scan file in place (see
  [step 6](#6-add-the-scan-file)).
- *"ZLint is not installed, so the certificates cannot be checked with ZLint."* or *"sslyze is not installed..."*: run
  the installer again.
- *"Port 27017 of this computer is used by another program, which is not a MongoDB server ..."*: another program uses
  the port that MongoDB needs. Close that program (or restart the computer) and run the analysis again.
- *"Another MongoDB server ... is using the data folder ... but does not answer"*: wait a minute and try again; if it
  keeps happening, restart the computer.
- *"The bundled MongoDB server is left running because another program is connected to it"*: another analysis, or a
  tool such as MongoDB Compass, is still using it. The last analysis that uses it stops it; or close that program.
- *"The MongoDB server included with the project stopped right after starting ..."* or *"did not become ready ..."*:
  the reason is at the end of the file `data/mongodb.log`. Restarting the computer or running the installer again
  usually fixes it.

### Asking for help

Please include:

- the output of `install.bat --check` (Windows) or `./install.sh --check` (macOS, Linux);
- the file `.tools/install.log` (the last installation) and, for problems while the program runs, `src/app.log`
  and `data/mongodb.log`.

---

## 10. Manual installation (for developers)

The installer is the recommended way, also for developers. It uses
[uv](https://docs.astral.sh/uv/) 0.12.24 to install Python 3.12 and the packages, and `scripts/install_tools.py` for
ZLint, MongoDB and the CT log list. If you prefer to set things up yourself:

### Python and the packages

The versions in `requirements.txt` install on Python 3.10 to 3.12 (the installer uses 3.12; the conda GitHub Action
uses 3.10, see `environment.yml`). The code also works on Python 3.13 and 3.14, with newer versions of the libraries.
From the project folder:

```bash
python3.12 -m venv .venv             # Windows: py -3.12 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
```

With conda instead: `conda env create -f environment.yml` and `conda activate digitalcertianalytics`.

On Linux systems with an old glibc, add `--only-binary :all: --no-binary sslyze` to the `pip install` line, so that pip
picks older ready-made packages instead of trying to compile new ones. sslyze 6.0.0 needs `cryptography` 42, so that
pin cannot be raised without upgrading sslyze.

Run the program from the `src` folder with the environment active:

```bash
cd src
python -m analysis.main --help
```

`dca` and `dca.bat` do the same with the `.venv` of the project folder, so they also work for a `.venv` you created
yourself.

### Your own MongoDB server

Install MongoDB Community Server (<https://www.mongodb.com/docs/manual/administration/install-community/>) and run it
as a service on `localhost:27017`, for example on Linux:

```bash
sudo systemctl enable --now mongod
```

The program uses any MongoDB server that answers on `mongodb://localhost:27017/` and never stops it. The bundled server
is started only when nothing answers there and `.tools/mongodb` exists. To leave the bundled server out, install with
`--skip mongodb`.

### Your own ZLint

The analysis uses ZLint at commit `989baefda32f5d50969ceafacc6d54215e28cc7b` (Go pseudo-version
`v3.6.5-0.20241104164204-989baefda32f`). With Go 1.18 or newer:

```bash
go install -trimpath -ldflags="-s -w -X main.version=v3.6.5-0.20241104164204-989baefda32f" \
    github.com/zmap/zlint/v3/cmd/zlint@989baefda32f5d50969ceafacc6d54215e28cc7b
```

This is the command the installer runs (with every Go folder inside `.tools/cache/go`, deleted afterwards). The program
looks for ZLint in this order:

1. the file named by the environment variable `DCA_ZLINT_PATH`;
2. `.tools/zlint/zlint` (`zlint.exe` on Windows), where the installer puts it;
3. `zlint/v3/zlint` (`zlint.exe` on Windows), the location used by earlier versions of this README;
4. `zlint` on the `PATH` (for example `~/go/bin` after `go install`).

`./install.sh --check` (or `install.bat --check`) reports which one it found.

### sslyze

sslyze is installed with the Python packages. The program looks for it on the `PATH`, then next to the Python that runs
the program (the environment's `bin` or `Scripts` folder, also when the environment is not activated), and finally runs
it as `python -m sslyze`.

### Tests

The tests need no network, MongoDB, ZLint or sslyze, which they simulate with small shell scripts. They run on macOS
and Linux; on Windows, run them in WSL (the GitHub Action runs them on Linux and macOS). From the project folder, with
the environment active:

```bash
python -m pip install pytest flake8
pytest
flake8 --extend-exclude .tools,data
```

With the installer's `.venv`, which has no `pip`, install the two tools with the installer's uv instead (macOS, Linux;
if the installer used a `uv` already on your computer, `.tools/uv` does not exist: use `uv` instead):

```bash
UV_CACHE_DIR=.tools/cache/uv .tools/uv/uv pip install --python .venv/bin/python pytest flake8
.venv/bin/python -m pytest
.venv/bin/python -m flake8 --extend-exclude .tools,data
```

On Windows (Command Prompt), flake8 works too: `set UV_CACHE_DIR=.tools\cache\uv`, then
`.tools\uv\uv.exe pip install --python .venv\Scripts\python.exe flake8` and
`.venv\Scripts\python.exe -m flake8 --extend-exclude .tools,data`.

`--extend-exclude .tools,data` keeps flake8 out of the installed tools, which contain the Python standard library.

The GitHub Action `.github/workflows/install.yml` runs the installer on Linux, macOS (Apple Silicon and Intel) and
Windows on every push and pull request, then `--check`, the tests (Linux and macOS), flake8 and a short analysis of a
generated scan file.
