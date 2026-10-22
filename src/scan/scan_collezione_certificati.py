from __future__ import annotations

import argparse
import json
import os
import shutil
from collections import Counter
from collections.abc import Iterator
from contextlib import suppress
from itertools import islice

# Admin: Anuar Elio Magliari
# Politecnico di Torino

# Standalone script, run from the repository root: python src/scan/scan_collezione_certificati.py [command]
SCAN_DIR = "src/scan"
DEFAULT_INPUT_FILE = "res/certs_polito.json"
SEPARATOR = "------------------------------------------------------------------\n"

# Example rows saved per status
EXAMPLE_LIMITS = {"success": 5, "connection-timeout": 1, "unknown-error": 1, "io-timeout": 1}

# tls keys every non-success row must have
ERROR_ROW_TLS_KEYS = ("status", "protocol", "timestamp", "error")

# (root reached, has an intermediate) -> description, in output order; None = empty chain
CHAIN_CATEGORIES = {
    (True, True): "hanno almeno un intermediate e un root nella catena",
    (True, False): "hanno un root ma nessun intermediate nella catena",
    (False, True): "hanno un intermediate ma nessun root nella catena",
    (False, False): "non hanno nè un intermediate e nè un root nella catena",
    None: "non hanno una catena",
}


class JsonRows:
    """Iterates valid JSON lines as (line number, data); invalid lines are reported and skipped."""

    def __init__(self, input_file: str, last_line: int | None = None):
        self.input_file = input_file
        self.last_line = last_line      # stop reading at this line, if set
        self.line_count = 0             # lines read, invalid ones included

    def __iter__(self) -> Iterator[tuple[int, dict]]:
        with open(self.input_file, 'r') as reader:
            for line_num, row in enumerate(islice(reader, self.last_line), start=1):
                self.line_count = line_num
                try:
                    yield line_num, json.loads(row)
                except json.JSONDecodeError:
                    print(f"Errore nel parsing della riga: {row}")


def _tls(json_row: dict) -> dict:
    return json_row.get("data", {}).get("tls", {})


def _status(json_row: dict) -> str:
    return _tls(json_row).get("status", "")


def _successful_rows(input_file: str) -> Iterator[tuple[int, dict, dict]]:
    """Yield (line number, data, server_certificates) for rows with status success."""
    for line_num, json_row in JsonRows(input_file):
        if _status(json_row) == "success":
            tls = _tls(json_row)
            yield line_num, json_row, tls.get("result", {}).get("handshake_log", {}).get("server_certificates", {})


def _is_self_signed(cert: dict) -> bool:
    return bool(cert.get("parsed", {}).get("signature", {}).get("self_signed", {}))


def _is_root(cert: dict) -> bool:
    parsed = cert.get("parsed", {})
    return _is_self_signed(cert) and parsed.get("subject_dn", "") == parsed.get("issuer_dn", "")


def _walk_chain(server_certificates: dict) -> Iterator[dict]:
    """Yield each issuer up the chain from the server certificate; stops at the root or a missing issuer.

    Standalone on purpose (the script runs outside src/): it keeps the legacy removal of the previous
    certificate, so the reports stay comparable with earlier runs; utils.chain_utils.walk_chain differs on cycles.
    """
    remaining = list(server_certificates.get("chain", []))
    current = server_certificates.get("certificate")
    while remaining and not _is_root(current):
        issuer_dn = current.get("parsed", {}).get("issuer_dn", "")
        issuer = next((cert for cert in remaining if cert.get("parsed", {}).get("subject_dn", "") == issuer_dn), None)
        if issuer is None:
            return
        yield issuer
        with suppress(ValueError):
            remaining.remove(current)
        current = issuer


def _dump_json(path: str, json_row: dict) -> None:
    with open(path, 'w') as writer:
        json.dump(json_row, writer, indent=4)


def count_status(input_file: str) -> None:
    """Count rows by TLS status."""
    rows = JsonRows(input_file)
    status_dict = dict(Counter(_status(json_row) for _, json_row in rows))
    status_count = sum(status_dict.values())

    print("Status: ", status_dict)
    print("Sum of all values: ", status_count)
    print("Total Number of values: ", rows.line_count)
    print("Number of rows excluded from the computation: ", rows.line_count - status_count)


def create_dir(out_dir: str, rm_dir: bool = True) -> bool:
    """Create out_dir (removing it first if rm_dir); return True on success."""
    if rm_dir and os.path.exists(out_dir):
        shutil.rmtree(out_dir)
        print(f"Directory esistente rimossa: {out_dir}")

    try:
        os.makedirs(out_dir)
    except OSError as e:
        print(f"Errore durante la creazione della directory: {e}")
        return False
    print(f"Directory creata: {out_dir}")
    return True


def _example_file_name(status: str, index: int) -> str:
    return f"success{index}.json" if status == "success" else f"{status.replace('-', '_')}.json"


def save_an_example_status(file: str) -> None:
    """Save up to EXAMPLE_LIMITS example rows per status to src/scan/example."""
    out_dir = os.path.join(SCAN_DIR, "example")
    if not create_dir(out_dir, True):
        return

    saved = Counter()
    for _, json_row in JsonRows(file):
        status = _status(json_row)
        if saved[status] < EXAMPLE_LIMITS.get(status, 0):
            _dump_json(os.path.join(out_dir, _example_file_name(status, saved[status])), json_row)
            saved[status] += 1
            if all(saved[name] == limit for name, limit in EXAMPLE_LIMITS.items()):
                break


def controlla_struttura(json_data: dict) -> bool:
    """Check that the row has 'domain' and all ERROR_ROW_TLS_KEYS."""
    data = json_data.get("data", {})
    return 'domain' in json_data and 'tls' in data and all(key in data['tls'] for key in ERROR_ROW_TLS_KEYS)


def check_error_rows(input_file: str) -> None:
    """Check that every non-success row has the same structure."""
    for _, json_data in JsonRows(input_file):
        if _status(json_data) != "success" and not controlla_struttura(json_data):
            print(json_data)

    print("Ogni riga di errore ha la stessa struttura")


def download_json_domain(input_file: str, domain: str | None, line_num: int | None) -> None:
    """Save the row of `domain` (or the one at `line_num`) to src/scan/<domain>.json."""
    if domain is None and line_num is None:
        return

    for line_number, json_data in JsonRows(input_file, last_line=line_num):
        domain_data = json_data.get("domain", "")
        if domain_data == domain:
            print(f"Dominio trovato alla riga {line_number} del file.")
            break
        if line_number == line_num:
            print(f"Dominio {domain_data} trovato alla riga {line_number} del file.")
            break
    else:
        print("Dominio non trovato")
        return

    # When searching by line number, the domain comes from the matched row
    file_domain = os.path.join(SCAN_DIR, f"{json_data.get('domain', domain)}.json")
    _dump_json(file_domain, json_data)
    print(f"File creato con successo: {file_domain}")


def check_chain_certificates(input_file: str) -> None:
    """Check that every successful row has at least one certificate in its chain."""
    domains = [json_row.get("domain", "") for _, json_row, server_certificates in _successful_rows(input_file)
               if not server_certificates.get("chain", [])]

    if not domains:
        print("Ogni dominio ha almeno un certificato nella catena")
    else:
        print("Ci sono dei domini che non hanno una catena")
        print(domains)


def count_root_cert_chain(input_file: str) -> None:
    """Count domains with several self-signed chain certs and self-signed leaves (src/scan/count_root_certs_chain.log)."""
    count_leaf_self_signed = 0
    domains_report = []
    for line_num, json_row, server_certificates in _successful_rows(input_file):
        count_leaf_self_signed += _is_self_signed(server_certificates.get("certificate", {}))
        count_self_signed = sum(map(_is_self_signed, server_certificates.get("chain", [])))
        if count_self_signed > 1:
            domains_report.append(f"{SEPARATOR}Il dominio {json_row.get('domain', '')} ha esattamente "
                                  f"{count_self_signed} self signed.\n"
                                  f"Certificato presente alla riga numero {line_num} dell'input file.\n")

    with open(os.path.join(SCAN_DIR, "count_root_certs_chain.log"), 'w') as writer:
        writer.write(f"Numero totale di certificati che hanno certificati self signed nella catena: {len(domains_report)}\n")
        writer.write(f"Numero totale di certificati leaf che sono self signed: {count_leaf_self_signed}\n\n")
        writer.writelines(domains_report)
        writer.write(SEPARATOR)


def _chain_category(server_certificates: dict) -> tuple[bool, bool] | None:
    """(root reached, has an intermediate), or None for an empty chain."""
    if not server_certificates.get("chain", []):
        return None
    issuers = list(_walk_chain(server_certificates))
    last_certificate = issuers[-1] if issuers else server_certificates.get("certificate")
    return _is_root(last_certificate), any(not _is_root(cert) for cert in issuers)


def count_certs_chain(input_file: str) -> None:
    """Count chains by root/intermediate presence (src/scan/count_certs_chain.log)."""
    counts = Counter(_chain_category(server_certificates) for _, _, server_certificates in _successful_rows(input_file))

    with open(os.path.join(SCAN_DIR, "count_certs_chain.log"), 'w') as writer:
        for category, description in CHAIN_CATEGORIES.items():
            writer.write(f"Numero totale di certificati che {description}: {counts[category]}\n")
        writer.write(f"Totale (deve corrispondere al numero di success): {sum(counts.values())}\n")


def check_sct_intermediate_certs_chain(input_file: str) -> None:
    """Report the first row whose chain has an intermediate certificate with an SCT."""
    for line_num, _, server_certificates in _successful_rows(input_file):
        if any(cert.get("parsed", {}).get("extensions", {}).get("signed_certificate_timestamps", [])
               for cert in _walk_chain(server_certificates)):
            print(f"Esiste un certificato intermedio con un SCT alla riga {line_num}")
            return


COMMANDS = {command.__name__: command for command in (
    count_status, save_an_example_status, check_error_rows, check_chain_certificates, download_json_domain,
    count_root_cert_chain, count_certs_chain, check_sct_intermediate_certs_chain,
)}
DEFAULT_COMMANDS = ("count_root_cert_chain", "count_certs_chain")


def main(argv: list[str] | None = None) -> None:
    """Run the requested analysis on the Zgrab2 JSON file (DEFAULT_COMMANDS if none given)."""
    parser = argparse.ArgumentParser(description="Analisi esplorative del file JSON prodotto da Zgrab2 "
                                                 "(da eseguire dalla root del repository).")
    parser.add_argument("command", nargs="?", choices=COMMANDS, metavar="comando",
                        help=f"Analisi da eseguire, una tra: {', '.join(COMMANDS)} "
                             f"(default: {' e '.join(DEFAULT_COMMANDS)}).")
    parser.add_argument("--input", default=DEFAULT_INPUT_FILE,
                        help="File JSON di Zgrab2 da analizzare (default: %(default)s).")
    parser.add_argument("--domain", help="Dominio da salvare con download_json_domain (es. canada.ca).")
    parser.add_argument("--line", type=int, help="Numero di riga da salvare con download_json_domain (es. 9718401).")
    args = parser.parse_args(argv)
    input_file = os.path.abspath(args.input)

    if args.command == "download_json_domain":
        if args.domain is None and args.line is None:
            parser.error("download_json_domain richiede --domain oppure --line.")
        download_json_domain(input_file, args.domain, args.line)
        return

    for command in [args.command] if args.command else DEFAULT_COMMANDS:
        COMMANDS[command](input_file)


if __name__ == "__main__":
    main()
