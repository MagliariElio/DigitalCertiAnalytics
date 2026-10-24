# Digital Certificate Analysis with ZGrab2

## Project Description

This project analyses the digital certificates of 10 million domains using the open-source tool [ZGrab2](https://github.com/zmap/zgrab2?tab=readme-ov-file). Each domain is scanned to retrieve the server's digital certificate and, when available, the certificates of its intermediate chain. The output is then analysed and stored in a database for further checks.

## Tool Used: ZGrab2

ZGrab2 is an application-layer scanner that collects information from remote servers over network protocols. In this project it was used to contact the servers on port 443 (TLS) and collect their digital certificates.

The tool was run with the following command:

```bash
zgrab2 tls --port 443 -f input_file.txt --output-file=certs_polito.json --timeout=30
```

Where:
- `--port 443` sets the port to contact (TLS/SSL).
- `-f input_file.txt` is the file with the domains to scan. It must contain only domain names, with no other details, as described in the official ZGrab2 documentation.
- `--output-file=certs_polito.json` is the output file with the scan results.
- `--timeout=30` sets a 30-second timeout for each request.

## Dataset

The scan used the *Top 10 Million Domains* file downloaded from [DomCop](https://www.domcop.com/files/top/top10milliondomains.csv.zip). Scanning the 10 million domains took about 17 hours.

### Error Types
The errors found during the scan fall into the following categories:
- `connection-timeout`: the connection timed out.
- `unknown-error`: unknown error.
- `io-timeout`: an input/output operation timed out.

### Output Examples

#### Error Response
An error response has the following structure:

```json
{
    "domain": "itun.es",
    "data": {
        "tls": {
            "status": "connection-timeout",
            "protocol": "tls",
            "timestamp": "2024-10-06T00:44:30+02:00",
            "error": "dial tcp: lookup itun.es on 192.168.1.254:53: no such host"
        }
    }
}
```

#### Success Response
A successful response has the following structure:

```json
{
    "domain": "soundcloud.com",
    "data": {
        "tls": {
            "status": "success",
            "protocol": "tls",
            "result": {
                "handshake_log": {
                    "server_hello": {
                        // TLS handshake properties
                    },
                    "server_certificates": {
                        // Server certificate and chain details
                    }
                }
            },
            "timestamp": "2024-10-06T00:44:30+02:00"
        }
    }
}
```

## Certificate Analysis

The results were saved in a JSON file of about 80 GB. Additional software was developed to read this file and store the data in SQLite3 databases. The software runs checks such as the OCSP status, the criticality of the extensions and other validation checks. These checks were run on every certificate of the chain: leaf, intermediate and root.

## Using the Analysis Software

The repository contains a program that analyses the data further, checks specific properties of the certificates and extracts additional information (see [DigitalCertiAnalytics](#digitalcertianalytics) below).

## Results

- **Total Domains Scanned**: 10,000,000
- **Successes**: 6,545,217 (65% success rate)
- **Failures**: 3,454,783

# DigitalCertiAnalytics

## Description

**DigitalCertiAnalytics** is a tool that analyses digital certificates and produces a set of detailed analyses from the extracted data. The program can:

- Analyse the leaf, intermediate and root certificates contained in the JSON file produced by ZGrab2.
- Show the results of the analysis through automatically generated charts and tables.

### Main features:
- **Certificate analysis**: extracts the relevant data from the certificates and stores it in a database for further analysis. The JSON file is read in parallel on all CPU cores, and only once even when several certificate types are analysed.
- **Additional checks**: OCSP status, ZLint compliance checks (results stored in MongoDB) and chain validation with sslyze.
- **Charts of the results**: generates charts, LaTeX tables and captions that describe the analysed data.

---

## Quick Start

The installer sets up everything the program needs (Python 3.12 and its packages, ZLint and a MongoDB server) inside
the project folder, on Windows, macOS and Linux. It needs no administrator rights and changes nothing else on the
computer: to uninstall, delete the folder. **[INSTALL.md](INSTALL.md)** explains every step for people with no
computer experience, with the warnings you may see and how to fix problems.

1. **Install.**
   - **Windows:** download the ZIP file from GitHub (green **Code** button, **Download ZIP**), extract it to a short
     folder such as `C:\DCA`, and double-click **`install.bat`**. Or paste this line into PowerShell:
     ```powershell
     powershell -ExecutionPolicy Bypass -c "irm https://raw.githubusercontent.com/MagliariElio/DigitalCertiAnalytics/main/install.ps1 | iex"
     ```
   - **macOS and Linux:** paste this line into a terminal (it puts the project in `~/DigitalCertiAnalytics`):
     ```bash
     curl -fsSL https://raw.githubusercontent.com/MagliariElio/DigitalCertiAnalytics/main/install.sh | bash
     ```
     In a copy of the project you already have, run `sh install.sh` in its folder, or double-click
     `install.command` on macOS.
2. **Check** the installation: `./install.sh --check` (macOS, Linux) or `install.bat --check` (Windows).
3. **Add the scan file**: copy the ZGrab2 output to `res/certs_polito.json` (see [Dataset](#dataset)).
4. **Run** the program with the `dca` launcher: `./dca --leaf_analysis --plot_leaf_results` (macOS, Linux) or
   `dca.bat --leaf_analysis --plot_leaf_results` (Windows). You can also double-click `dca.command` (macOS) or `dca.bat`
   (Windows), which asks for the options.

Running the installer again is safe: it skips what is installed and repairs what is broken (for example after the
project folder was moved). Running the one-line command again, also inside a copy of the project, updates the code to
the newest version and keeps your data. Developers who prefer their own Python environment, MongoDB service or ZLint build will
find the manual steps in [INSTALL.md](INSTALL.md#10-manual-installation-for-developers).

## Usage Guide

### 1. Install the program
Follow the [Quick Start](#quick-start) above, or [INSTALL.md](INSTALL.md) for the detailed guide. The installer puts:

- ZLint, built from the exact version used by the analysis (commit `989baef`, Go pseudo-version
  `v3.6.5-0.20241104164204-989baefda32f`), in `.tools/zlint`;
- a portable MongoDB server in `.tools/mongodb`, which the program starts by itself when the ZLint results must be
  saved (see [the MongoDB section](#viewing-and-managing-the-mongodb-database));
- Python 3.12 in `.tools/python` and the packages of `requirements.txt` in the virtual environment `.venv`, with sslyze;
- the Certificate Transparency log list `res/log_list.json`, downloaded from Google only if it is missing or damaged
  (`--force` keeps a valid list; `--force --only log_list` replaces it and keeps the old one as `res/log_list.json.old`).

### 2. Run the program
The program runs from the terminal or the command line, with several options that control what it does. Start it with
the launcher in the project folder: `./dca` on macOS and Linux, `dca.bat` on Windows (`.\dca.bat` in PowerShell). The
launcher works from any folder and runs the program with the project's own Python; with no options it shows the help.

```bash
./dca --help
```

The input files are `res/certs_polito.json` (the ZGrab2 output, see [Dataset](#dataset)) and `res/log_list.json` (the list of the Certificate Transparency logs used to analyse the SCTs, available at https://www.gstatic.com/ct/log_list/v3/all_logs_list.json).

#### Available options:
- `--delete_all_db`: deletes all the existing databases before starting.
- `--delete_leaf_db`: deletes the leaf certificate database before starting.
- `--delete_intermediate_db`: deletes the intermediate certificate database before starting.
- `--delete_root_db`: deletes the root certificate database before starting.

- `--leaf_analysis`: analyses the leaf certificates (the existing leaf database is replaced).
- `--leaf_ocsp_analysis`: runs the OCSP analysis on the leaf certificates.
- `--leaf_zlint_check`: runs the ZLint analysis on the leaf certificates, to find vulnerabilities and misconfigurations according to the official requirements.
- `--leaf_chain_validation`: validates the chains of the leaf certificates, to check the compliance and reliability of the chain of trust.

- `--intermediate_analysis`: analyses the intermediate certificates (the existing intermediate database is replaced).
- `--intermediate_ocsp_analysis`: runs the OCSP analysis on the intermediate certificates.
- `--intermediate_zlint_check`: runs the ZLint analysis on the intermediate certificates, to find vulnerabilities and misconfigurations according to the official requirements.

- `--root_analysis`: analyses the root certificates (the existing root database is replaced).
- `--root_ocsp_analysis`: runs the OCSP analysis on the root certificates.

- `--plot_all_results`: generates the charts for all the analysed certificate data.
- `--plot_leaf_results`: generates the charts for the results of the leaf certificate analysis.
- `--plot_intermediate_results`: generates the charts for the results of the intermediate certificate analysis.
- `--plot_root_results`: generates the charts for the results of the root certificate analysis.

- `-v, --verbose`: enables verbose mode for detailed logging.
- `-h, --help`: shows the available options.

The OCSP, ZLint, chain validation and chart options work on a database created by an earlier analysis of the same certificate type (or in the same command). If a database is deleted with a `--delete_*` option and not analysed again, the other options for that certificate type are skipped.

The OCSP analysis and the chain validation contact servers on the internet. The ZLint options store their results in MongoDB: the program uses the MongoDB server that answers on `localhost:27017`, and starts the one included with the project when none is running.

#### Usage examples:
The examples use `./dca` (macOS, Linux); on Windows write `dca.bat` instead, with the same options.

1. **Run only the leaf certificate analysis**:
   ```bash
   ./dca --leaf_analysis
   ```

2. **Delete the intermediate certificate database and start the analysis**:
   ```bash
   ./dca --delete_intermediate_db --intermediate_analysis
   ```

3. **Run the OCSP analysis on the root certificates and generate the charts for the root certificates only**:
   ```bash
   ./dca --root_ocsp_analysis --plot_root_results
   ```

4. **Delete all the databases, analyse the leaf and intermediate certificates and generate all the charts**:
   ```bash
   ./dca --delete_all_db --leaf_analysis --intermediate_analysis --plot_all_results
   ```
5. **Enable verbose mode for detailed logging**:
   ```bash
   ./dca --delete_leaf_db --leaf_analysis -v
   ```
6. **Run the ZLint analysis on the leaf certificates and validate the chains**:
   ```bash
   ./dca --leaf_zlint_check --leaf_chain_validation
   ```

#### Running the program without the launcher (for developers)
The launcher runs `python -m analysis.main` from the `src/` folder with the Python of `.venv`, with `.venv`'s programs
first on the `PATH`. With an activated virtual environment (yours or the project's `.venv`), the same commands can be
run directly from `src/`:

```bash
cd src
python -m analysis.main --leaf_analysis
```

This is why the help text starts with `usage: python -m analysis.main`.

#### Parallel reading of the JSON file

The ZGrab2 JSON file is read only once, even when several analyses are requested (leaf, intermediate and root). Worker processes (one per CPU core, minus the one used by the main process) parse blocks of lines and write the rows of every database to temporary SQLite files in a staging folder, `src/analysis/<type>/ingestion_staging_*`. The main process stays the only writer of the databases and copies the rows in the order of the file, so the databases are the same as with a sequential reading. A file that fits in a single block is read without worker processes. The staging folder, next to the database of the first analysed type (leaf, then intermediate, then root), is deleted at the end of the analysis; if the program is killed, the next analysis of that certificate type deletes it.

#### Parallelism of the other stages

- **OCSP**: up to 200 concurrent requests over reused (keep-alive) connections; each issuer certificate is downloaded once per URL.
- **ZLint**: up to 100 certificates per ZLint run, with one run per CPU core at a time.
- **Chain validation**: up to 100 domains per sslyze run, with 16 runs in parallel.
- **Charts**: the statistics are computed from one parallel read of each table and the charts are drawn in parallel processes (details, measured times and memory in `Plot Description.md`).

### 3. File Structure

- `INSTALL.md`: step-by-step installation guide for Windows, macOS and Linux, with troubleshooting.
- `install.sh`: installer for macOS and Linux (`sh install.sh`, or `curl -fsSL https://raw.githubusercontent.com/MagliariElio/DigitalCertiAnalytics/main/install.sh | bash` without a copy of the project). It installs uv, Python 3.12 and `.venv`, then runs `scripts/install_tools.py`. `--check` shows the status of every component; `--skip`, `--only` and `--force` select what to install.
- `install.command`: double-clickable installer for macOS (runs `install.sh` and keeps the window open).
- `install.ps1`: installer for Windows (PowerShell 5.1 or newer), also usable without a copy of the project as `powershell -ExecutionPolicy Bypass -c "irm https://raw.githubusercontent.com/MagliariElio/DigitalCertiAnalytics/main/install.ps1 | iex"`, which downloads the project into `%USERPROFILE%\DigitalCertiAnalytics` first.
- `install.bat`: double-clickable installer for Windows (runs `install.ps1` for this run only with `-ExecutionPolicy Bypass`; it accepts the same options, such as `install.bat --check`).
- `dca`, `dca.bat`: launchers of the program for macOS/Linux and Windows (`./dca --help`, `dca.bat --help`).
- `dca.command`: double-clickable launcher for macOS, which asks for the options.
- `scripts/install_tools.py`: the cross-platform part of the installer, run with the `.venv` Python: it installs ZLint, the MongoDB server and the CT log list (pinned versions, every download verified with SHA-256, the log list with Google's signature) and prints the status table of `--check`.
- `.tools/` (created by the installer, not in git): `uv/` (the uv program), `python/` (Python 3.12), `zlint/` (ZLint), `mongodb/` (the MongoDB server, `bin/mongod`), `cache/` (download and package caches, temporary files), `manifest.json` (what is installed, with versions and checksums) and `install.log` (the output of the last installation).
- `.venv/` (created by the installer, not in git): the virtual environment with the packages of `requirements.txt`.
- `data/` (created by the installer, not in git): `data/mongodb/` holds the database files of the bundled MongoDB server, and `data/mongodb.log` its log (moved to `data/mongodb.log.old` above 50 MB).
- `requirements.txt`: the pinned Python packages. `environment.yml`: the same packages for conda (Python 3.10), used by the conda GitHub Action.
- `zlint/`: legacy location of a ZLint built by hand (`zlint/v3/zlint`), still searched by the program; the installer puts ZLint in `.tools/zlint`.
- `.github/workflows/install.yml`: GitHub Action that runs the installer on Linux, macOS (Apple Silicon and Intel) and Windows, then `--check`, the tests, flake8 and a short analysis of a generated scan file. `.github/workflows/python-package-conda.yml` runs flake8 and the tests in the conda environment.
- `res/queries.sql`: SQL file with analysis queries on the relational databases.
- `res/queries_big_query.sql`: SQL file with the query used to get a list of European domains from Google's BigQuery service.
- `res/log_list.json`: JSON file with the list of Certificate Transparency logs used by the program to analyse the SCTs.
- `res/certs_polito.json`: JSON file with the certificates to analyse: the output of the ZGrab2 scan run on the list of input domains (not in git; put it there before running the `--*_analysis` options).
- `res/README.md`: notes on the names of the input files.
- `src/analysis/`: folder with the databases and the other analysis files.
- `src/analysis/leaf/leaf_certificates.db`: SQLite database with the results of the leaf certificate analysis.
- `src/analysis/intermediate/intermediate_certificates.db`: SQLite database with the results of the intermediate certificate analysis.
- `src/analysis/root/root_certificates.db`: SQLite database with the results of the root certificate analysis.
- `src/analysis/leaf/ocsp_certificates_backup.csv`: CSV backup file with the results of the OCSP analysis of the leaf certificates.
- `src/analysis/intermediate/ocsp_certificates_backup.csv`: CSV backup file with the results of the OCSP analysis of the intermediate certificates.
- `src/analysis/root/ocsp_certificates_backup.csv`: CSV backup file with the results of the OCSP analysis of the root certificates.
- `src/analysis/<type>/ocsp_check_results_temp.csv`: temporary file with the OCSP results not yet saved in the database, used to resume an interrupted OCSP analysis.
- `src/analysis/leaf/plots`: folder with the charts of the leaf certificates.
- `src/analysis/intermediate/plots`: folder with the charts of the intermediate certificates.
- `src/analysis/root/plots`: folder with the charts of the root certificates. Each `plots` folder contains, for every chart,
  the figure (`.png` at 300 dpi and vector `.pdf`), the plotted data (`.csv`) and the LaTeX table (`.tex`);
  the `captions.tex` file contains a ready `figure` environment with the caption of every chart. The charts are
  described in `Plot Description.md`.
- `src/analysis/<type>/ingestion_staging_*`: temporary files of the parallel reading of the JSON file, deleted at the end
  of the analysis (if the program is killed, the next analysis of the same certificate type deletes them).
- `src/analysis/zlint_analysis/reading_zlint_results.py`: Python script that extracts the data from the MongoDB (non-relational) database, used for detailed analyses of the stored certificate data. It writes three CSV files (`zlint_results.csv`, `issuer_ranking_by_result.csv` and `certificates_result_summary.csv`) to the folder where it is run, and starts and stops the bundled MongoDB server when no server is running. The name of the database to read can be passed as an argument (default `Leaf_Zlint_Checks_Google_3`, the database written by the ZLint analysis of the leaf certificates). Run it with the `.venv` Python from the project folder: `.venv/bin/python src/analysis/zlint_analysis/reading_zlint_results.py` (Windows: `.venv\Scripts\python.exe src\analysis\zlint_analysis\reading_zlint_results.py`).
- `src/db/schema_db.sql`: SQL script that creates the schema of the leaf, intermediate and root databases (described in `Database Description.md`).
- `src/db/mongo_server.py`: starts the MongoDB server included with the project when no server answers on `localhost:27017`, reuses one left running by an interrupted run, and stops it cleanly when the program ends.
- `src/scan/`: folder with an exploratory scan script for the JSON file (`.venv/bin/python src/scan/scan_certificate_collection.py --help`, from the repository root, for the available commands; on Windows `.venv\Scripts\python.exe src\scan\scan_certificate_collection.py --help`).
- `src/analysis/main.py`: entry point (`python -m analysis.main`, run by the `dca` launcher), runs the analysis and handles `Ctrl+C`.
- `src/analysis/certificates_analysis.py`: command line and orchestration of the analyses. The ZGrab2 JSON file is read only once even when several analyses are requested (leaf, intermediate and root).
- `src/analysis/ingestion.py`: parallel reading of the JSON file on all CPU cores; the main process stays the only writer of the databases, in the order of the file.
- `src/bean/certificate.py`: X.509 certificate loaded from the raw ZGrab2 format (base64 DER).
- `src/dao/certificate_dao.py` and `src/db/`: access to the SQLite and MongoDB databases.
- `src/dao/statistics_dao.py`: statistical queries used for the charts.
- `src/dao/statistics_facts.py`: computes the chart statistics from one parallel read of each table, with the same results as the statistical queries (used for large databases; see `Plot Description.md`).
- `src/utils/chain_utils.py`: traversal of the certificate chains, signature checks and chain validation with sslyze (several domains per sslyze run, in parallel). sslyze is looked for on the `PATH`, then next to the running Python (the `.venv`), then run as `python -m sslyze`.
- `src/utils/ocsp_utils.py`: OCSP analysis (concurrent requests over reused connections, resumed from the temporary and backup CSV files).
- `src/utils/zlint_utils.py`: ZLint analysis run in parallel (many certificates per ZLint run), with the results saved in MongoDB. ZLint is looked for in the file named by the `DCA_ZLINT_PATH` environment variable, then in `.tools/zlint/zlint`, then in `zlint/v3/zlint`, then on the `PATH` (`zlint.exe` on Windows).
- `src/utils/graph_plotter.py` and `src/utils/plotter_utils.py`: generation of the charts, tables and captions, in parallel.
- `src/utils/process_utils.py`: management of the worker processes (stopped with `Ctrl+C`, and closed if the main process ends).
- `src/utils/utils.py`: logging setup, progress bars and the command-line help format.
- `tests/`: automated tests (pytest), also run by the GitHub Actions together with the flake8 check.

### 4. Log
The program writes the `app.log` log file, which records the progress of the application and any errors. The log is written in the folder where the program is run: the `dca` launcher runs it from `src/`, so the file is `src/app.log`. The installer writes its output to `.tools/install.log`, and the bundled MongoDB server writes its log to `data/mongodb.log`.

Stopping the program with `Ctrl+C` closes the connections and the worker processes in an orderly way, and the process exits with exit code `130`: the data already saved stay in the databases, and the OCSP analysis can be resumed from where it stopped. If the main process is killed, its worker processes exit on their own. The bundled MongoDB server is not interrupted by `Ctrl+C`: it finishes saving the ZLint results and is then stopped cleanly. On macOS and Linux, closing the terminal window (SIGHUP) or a `kill` (SIGTERM) during the ZLint stage or `reading_zlint_results.py` is handled in the same way, so the bundled server is never left running. On Windows, `cmd` then asks *"Terminate batch job (Y/N)?"*; either answer is fine.

### 5. Tests
The automated tests need no network, MongoDB, ZLint or sslyze (they are simulated with small shell scripts), and run on macOS and Linux (on Windows, in WSL). From the project's root folder, with the `.venv` created by the installer:

```bash
UV_CACHE_DIR=.tools/cache/uv .tools/uv/uv pip install --python .venv/bin/python pytest flake8
.venv/bin/python -m pytest
.venv/bin/python -m flake8 --extend-exclude .tools,data
```

With an environment of your own, activate it and run `pip install pytest flake8`, `pytest` and `flake8 --extend-exclude .tools,data`. The `--extend-exclude` option keeps flake8 out of the tools installed in `.tools`. If the installer used a `uv` already installed on the computer, `.tools/uv` does not exist: use `uv` instead.

The tests cover the ingestion pipeline and the databases, the command line and `Ctrl+C` handling, the OCSP and ZLint analyses, chain and signature validation, the worker processes, the statistical queries and the charts, the installer (`tests/test_install_tools.py`, also `install.sh` and `dca.command`) and the bundled MongoDB server (`tests/test_mongo_server.py`, also the closing of the terminal window).

## Viewing and Managing the MongoDB Database

The ZLint results are stored in MongoDB, in the databases named in `ZLINT_DB_NAMES` (`src/db/MongoDbDatabase.py`): `Leaf_Zlint_Checks_Google_3` and `Intermediate_Zlint_Checks_Google_3`.

### The MongoDB server included with the project
The installer puts a portable MongoDB Community server in `.tools/mongodb` (version 8.0.34; 7.0.45 on systems where 8.0 has no build). You do not need to install or start MongoDB yourself:

- When a ZLint option (or `reading_zlint_results.py`) needs MongoDB and no server answers on `localhost:27017`, the program starts the bundled server on `127.0.0.1:27017`, so it accepts connections only from this computer. Its data are in `data/mongodb` and its log in `data/mongodb.log`.
- At the end of the ZLint stage, and at the latest when the program exits (also after `Ctrl+C`), the program stops the server cleanly. A server left running by a program that was killed is reused by the next run and then stopped.
- If another program is connected to the bundled server (another analysis, or MongoDB Compass), the server is left running with a warning, and the last analysis that uses it stops it.
- A MongoDB server that you run yourself on `localhost:27017` (a service, Docker, ...) is used instead and is never stopped. Install with `sh install.sh --skip mongodb` (or `install.bat --skip mongodb`) to leave the bundled server out.
- If port 27017 is used by a program that is not MongoDB, the program says so: close that program and run the analysis again.

To use other tools with the bundled server (MongoDB Compass, `mongodump`), start it by hand in a terminal, from the project folder, and leave that window open:

```bash
.tools/mongodb/bin/mongod --dbpath data/mongodb --bind_ip 127.0.0.1 --port 27017 --nounixsocket
```

On Windows: `.tools\mongodb\bin\mongod.exe --dbpath data\mongodb --bind_ip 127.0.0.1 --port 27017`. Press `Ctrl+C` in that window to stop it when you have finished. Do not start it while an analysis is running. An analysis started while it runs uses it and may stop it at the end, when no other program is connected.

### MongoDB Compass
To view and manage the MongoDB database easily, a MongoDB management tool with a graphical interface is recommended, such as **MongoDB Compass**. Compass lets you explore the data, run queries, analyse the structure of the database, and much more.

1. Go to the official MongoDB Compass website: [MongoDB Compass](https://www.mongodb.com/products/compass).
2. Download and install the version for your operating system (Windows, macOS, Linux).
3. Start the MongoDB server (see above), open Compass and connect to `mongodb://localhost:27017` (the bundled server has no user name or password).

Compass offers an easy-to-use interface to view the data, analyse the collections and edit the documents.

### How to dump a MongoDB database (optional)

To create a backup (dump) of a MongoDB database, use the **`mongodump`** command, while the server is running (see above). It copies the data of the database into a given folder. `mongodump` is not included with the project: it is part of the [MongoDB Database Tools](https://www.mongodb.com/try/download/database-tools), a separate download. Once installed, `mongodump --version` prints its version.

1. **For the "Leaf_Zlint_Checks_Google_3" database**:
   ```bash
   mongodump --db Leaf_Zlint_Checks_Google_3 --out Leaf_Zlint_Checks_Google_3
   ```

2. **For the "Intermediate_Zlint_Checks_Google_3" database**:
   ```bash
   mongodump --db Intermediate_Zlint_Checks_Google_3 --out Intermediate_Zlint_Checks_Google_3
   ```

These commands copy the data of each database into the folder given with `--out`. You can then use these dump files to restore the data (with `mongorestore`, also part of the Database Tools) or to analyse it. To keep the whole database of the bundled server instead, you can also copy the `data/mongodb` folder while the server is stopped.
