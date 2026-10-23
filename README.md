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

## Installation Requirements

The following software is needed to run the program:

### 1. Python 3.10 - 3.12
Download and install Python from the [official website](https://www.python.org/). The versions pinned in `requirements.txt` can be installed on Python 3.10 - 3.12 (the GitHub Action uses 3.10); the code also works on Python 3.13 and 3.14, with newer versions of the libraries.

### 2. **ZLint**
**ZLint** is an analysis tool for TLS/SSL certificates that checks their compliance and security. Before running the program, ZLint must be installed and its executable must be in the **DigitalCertiAnalytics** project folder. It is therefore best to do this step after cloning the project's GitHub repository (see the "Usage Guide" section).

#### **Installing ZLint:**

1. **Clone the ZLint repository**:
   ZLint can be downloaded from its official GitHub repository:
   ```bash
   git clone https://github.com/zmap/zlint
   ```

2. **Build ZLint**:
   After cloning the repository, enter the ZLint project folder and build it:
   ```bash
   cd zlint
   make
   ```
   *Note: this step requires a working **Go** installation. For more information, see the **README** file in the official ZLint GitHub repository.*

3. **Location of the executable**:
   Once the build is complete, the ZLint executable is in the `zlint/v3/zlint` folder. Make sure that its path matches the value expected by the program, which looks for the executable in:
   ```python
   # src/utils/zlint_utils.py
   ZLINT_PATH = Path(__file__).resolve().parents[2] / "zlint" / "v3" / "zlint"
   ```

4. **Check that ZLint is installed correctly**:
   You can check that ZLint works by running the following command in the terminal:
   ```bash
   ./zlint/v3/zlint --help
   ```

   If everything is set up correctly, you will see the list of ZLint options.

5. **Set the ZLint path**:
   Make sure that the ZLint executable is in the `zlint/v3/` folder, as set in the code. If the path is wrong, the program cannot run the ZLint analysis. If needed, change the `ZLINT_PATH` constant in `src/utils/zlint_utils.py` to the actual location.

### 3. **MongoDB**
MongoDB must be installed on your computer to save the ZLint results. Before running options such as `--leaf_zlint_check` or `--intermediate_zlint_check`, which use MongoDB, make sure that the MongoDB service is running.

#### **Checking and starting MongoDB on Linux:**

1. **Check the status of MongoDB**:
   You can check whether the MongoDB service is running with the command:
   ```bash
   sudo systemctl status mongod
   ```

   If the service is running, the output says that MongoDB is active.

2. **Start MongoDB if it is not running**:
   If MongoDB is not running, start the service with the command:
   ```bash
   sudo systemctl start mongod
   ```

3. **Check that MongoDB is running**:
   After starting the service, check its status again with:
   ```bash
   sudo systemctl status mongod
   ```

4. **Start MongoDB automatically**:
   You can also make MongoDB start automatically when the system boots with:
   ```bash
   sudo systemctl enable mongod
   ```

### 4. Python Libraries
Install the required Python libraries with `pip`, using the `requirements.txt` file. Follow these steps:

1. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv env
   source env/bin/activate   # On Windows use: env\Scripts\activate
   ```

2. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage Guide

### 1. Clone the repository
Clone the project repository with Git:

```bash
git clone git@github.com:MagliariElio/DigitalCertiAnalytics.git
cd DigitalCertiAnalytics
```

### 2. Run the program
The program runs from the terminal or the command line, with several options that control what it does. The commands must be run from the `src/` folder:

```bash
cd src
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

#### Usage examples:

1. **Run only the leaf certificate analysis**:
   ```bash
    python -m analysis.main --leaf_analysis
   ```

2. **Delete the intermediate certificate database and start the analysis**:
   ```bash
    python -m analysis.main --delete_intermediate_db --intermediate_analysis
   ```

3. **Run the OCSP analysis on the root certificates and generate the charts for the root certificates only**:
   ```bash
    python -m analysis.main --root_ocsp_analysis --plot_root_results
   ```

4. **Delete all the databases, analyse the leaf and intermediate certificates and generate all the charts**:
   ```bash
    python -m analysis.main --delete_all_db --leaf_analysis --intermediate_analysis --plot_all_results
   ```
5. **Enable verbose mode for detailed logging**:
   ```bash
    python -m analysis.main --delete_leaf_db --leaf_analysis -v
   ```
6. **Run the ZLint analysis on the leaf certificates and validate the chains**:
   ```bash
    python -m analysis.main --leaf_zlint_check --leaf_chain_validation
   ```

#### Parallel reading of the JSON file

The ZGrab2 JSON file is read only once, even when several analyses are requested (leaf, intermediate and root). Worker processes (one per CPU core, minus the one used by the main process) parse blocks of lines and write the rows of every database to temporary SQLite files in a staging folder, `src/analysis/<type>/ingestion_staging_*`. The main process stays the only writer of the databases and copies the rows in the order of the file, so the databases are the same as with a sequential reading. A file that fits in a single block is read without worker processes. The staging folder, next to the database of the first analysed type (leaf, then intermediate, then root), is deleted at the end of the analysis; if the program is killed, the next analysis of that certificate type deletes it.

#### Parallelism of the other stages

- **OCSP**: up to 200 concurrent requests over reused (keep-alive) connections; each issuer certificate is downloaded once per URL.
- **ZLint**: up to 100 certificates per ZLint run, with one run per CPU core at a time.
- **Chain validation**: up to 100 domains per sslyze run, with 16 runs in parallel.
- **Charts**: the statistics are computed from one parallel read of each table and the charts are drawn in parallel processes (details, measured times and memory in `Plot Description.md`).

### 3. File Structure

- `res/queries.sql`: SQL file with analysis queries on the relational databases.
- `res/queries_big_query.sql`: SQL file with the query used to get a list of European domains from Google's BigQuery service.
- `res/log_list.json`: JSON file with the list of Certificate Transparency logs used by the program to analyse the SCTs.
- `res/certs_polito.json`: JSON file with the certificates to analyse: the output of the ZGrab2 scan run on the list of input domains.
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
- `src/analysis/zlint_analysis/reading_zlint_results.py`: Python script that extracts the data from the MongoDB (non-relational) database, used for detailed analyses of the stored certificate data. The name of the database to read can be passed as an argument (default `Leaf_Zlint_Checks_Google_3`, the database written by the ZLint analysis of the leaf certificates).
- `src/db/schema_db.sql`: SQL script that creates the schema of the leaf, intermediate and root databases (described in `Database Description.md`).
- `src/scan/`: folder with an exploratory scan script for the JSON file (`python src/scan/scan_certificate_collection.py --help`, from the repository root, for the available commands).
- `src/analysis/main.py`: entry point (`python -m analysis.main`), runs the analysis and handles `Ctrl+C`.
- `src/analysis/certificates_analysis.py`: command line and orchestration of the analyses. The ZGrab2 JSON file is read only once even when several analyses are requested (leaf, intermediate and root).
- `src/analysis/ingestion.py`: parallel reading of the JSON file on all CPU cores; the main process stays the only writer of the databases, in the order of the file.
- `src/bean/certificate.py`: X.509 certificate loaded from the raw ZGrab2 format (base64 DER).
- `src/dao/certificate_dao.py` and `src/db/`: access to the SQLite and MongoDB databases.
- `src/dao/statistics_dao.py`: statistical queries used for the charts.
- `src/dao/statistics_facts.py`: computes the chart statistics from one parallel read of each table, with the same results as the statistical queries (used for large databases; see `Plot Description.md`).
- `src/utils/chain_utils.py`: traversal of the certificate chains, signature checks and chain validation with sslyze (several domains per sslyze run, in parallel).
- `src/utils/ocsp_utils.py`: OCSP analysis (concurrent requests over reused connections, resumed from the temporary and backup CSV files).
- `src/utils/zlint_utils.py`: ZLint analysis run in parallel (many certificates per ZLint run), with the results saved in MongoDB.
- `src/utils/graph_plotter.py` and `src/utils/plotter_utils.py`: generation of the charts, tables and captions, in parallel.
- `src/utils/process_utils.py`: management of the worker processes (stopped with `Ctrl+C`, and closed if the main process ends).
- `src/utils/utils.py`: logging setup, progress bars and the command-line help format.
- `tests/`: automated tests (pytest), also run by the GitHub Action together with the flake8 check.

### 4. Log
The program writes the `app.log` log file, which records the progress of the application and any errors. The log is written in the folder where the program is run.

Stopping the program with `Ctrl+C` closes the connections and the worker processes in an orderly way, and the process exits with exit code `130`: the data already saved stay in the databases, and the OCSP analysis can be resumed from where it stopped. If the main process is killed, its worker processes exit on their own.

### 5. Tests
The automated tests need no network, MongoDB, ZLint or sslyze (they are simulated). From the project's root folder:

```bash
pip install pytest flake8
pytest
flake8
```

The tests cover the ingestion pipeline and the databases, the command line and `Ctrl+C` handling, the OCSP and ZLint analyses, chain and signature validation, the worker processes, the statistical queries and the charts.

## Viewing and Managing the MongoDB Database

To view and manage the MongoDB database easily, a MongoDB management tool with a graphical interface is recommended, such as **MongoDB Compass**. Compass lets you explore the data, run queries, analyse the structure of the database, and much more.

### How to install MongoDB Compass:
1. Go to the official MongoDB Compass website: [MongoDB Compass](https://www.mongodb.com/products/compass).
2. Download and install the version for your operating system (Windows, macOS, Linux).
3. Once installed, start Compass and connect to your MongoDB server with the appropriate credentials.

Compass offers an easy-to-use interface to view the data, analyse the collections and edit the documents. You can easily explore your database and interact with it through the graphical interface.

### How to dump a MongoDB database

To create a backup (dump) of the MongoDB database, use the **`mongodump`** command. It copies the data of the database into a given folder. Make sure that **`mongodump`** is installed on your system; if it is not, you can download it with MongoDB or as part of the MongoDB Database Tools.

#### The commands to dump the databases are the following:

The database names are defined in `ZLINT_DB_NAMES` (`src/db/MongoDbDatabase.py`).

1. **For the "Leaf_Zlint_Checks_Google_3" database**:
   ```bash
   mongodump --db Leaf_Zlint_Checks_Google_3 --out Leaf_Zlint_Checks_Google_3
   ```

2. **For the "Intermediate_Zlint_Checks_Google_3" database**:
   ```bash
   mongodump --db Intermediate_Zlint_Checks_Google_3 --out Intermediate_Zlint_Checks_Google_3
   ```

These commands copy the data of each database into the folder given with `--out`. You can then use these dump files to restore the data or to analyse it.

### Making sure that `mongodump` is installed:

To run the `mongodump` commands, MongoDB and its command-line tools must be installed on your system. Here is how:

1. If you do not have MongoDB yet, download it from the official website: [Download MongoDB](https://www.mongodb.com/try/download/community).
2. If you already have MongoDB but not the command-line tools, you can download the tools package separately. You can find it in the "MongoDB Database Tools" section of the same MongoDB download page.
3. Once installed, make sure that the `mongodump` command is in your system **PATH**. You can check it by running `mongodump --version` in the terminal and seeing whether it prints a version.
