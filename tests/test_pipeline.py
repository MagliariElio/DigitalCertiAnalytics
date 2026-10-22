"""End-to-end CLI tests on a copy of the project with synthetic zgrab2 output."""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import Pki, success_row

PROJECT_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def project(tmp_path_factory):
    """Copy of src/ and res/log_list.json plus a synthetic certs_polito.json (valid, error and invalid rows)."""
    root = tmp_path_factory.mktemp("project")
    ignore = shutil.ignore_patterns("__pycache__", "*.db", "*.csv", "plots", "app.log")
    shutil.copytree(PROJECT_DIR / "src", root / "src", ignore=ignore)
    (root / "res").mkdir()
    shutil.copy(PROJECT_DIR / "res" / "log_list.json", root / "res" / "log_list.json")
    with open(root / "res" / "certs_polito.json", "w") as certs_file:
        for row in Pki().rows(8):
            certs_file.write(json.dumps(row) + "\n")
        certs_file.write(json.dumps(success_row("null.example.test", None, [])) + "\n")
        certs_file.write("not json\n")
    return root


def run_cli(project, *flags):
    env = {**os.environ, "COLUMNS": "160"}
    return subprocess.run([sys.executable, "-m", "analysis.main", *flags], cwd=project / "src",
                          capture_output=True, text=True, timeout=600, env=env)


def count(database_path, table):
    with sqlite3.connect(database_path) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_analysis_and_plots(project):
    result = run_cli(project, "--leaf_analysis", "--intermediate_analysis", "--root_analysis", "--plot_all_results")
    assert result.returncode == 0, result.stdout + result.stderr

    analysis = project / "src" / "analysis"
    assert count(analysis / "leaf" / "leaf_certificates.db", "Certificates") == 8
    assert count(analysis / "leaf" / "leaf_certificates.db", "Errors") == 2
    assert count(analysis / "intermediate" / "intermediate_certificates.db", "Certificates") == 8
    assert count(analysis / "root" / "root_certificates.db", "Certificates") == 4
    for db_type, minimum in (("leaf", 20), ("intermediate", 15), ("root", 15)):
        assert len(list((analysis / db_type / "plots").glob("*.png"))) >= minimum

    log = (project / "src" / "app.log").read_text()
    assert "Errore nel parsing della riga 12" in log
    assert "certificato del server nullo" in log
    assert "Errore nella generazione del grafico" not in log


def test_delete_without_analysis_skips_other_stages(project):
    result = run_cli(project, "--delete_root_db", "--plot_root_results")
    assert result.returncode == 0
    assert not (project / "src" / "analysis" / "root" / "root_certificates.db").exists()
    assert "non vengono eseguite" in (project / "src" / "app.log").read_text()


def test_missing_database(project):
    result = run_cli(project, "--root_ocsp_analysis")
    assert result.returncode == 0
    assert "Il database root non è stato trovato" in (project / "src" / "app.log").read_text()
