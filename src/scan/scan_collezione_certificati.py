import json
import os, shutil

# Admin: Anuar Elio Magliari 
# Politecnico di Torino

def count_status(input_file):
    status_dict = {}
    line_num = 0
    
    with open(input_file, 'r') as reader:
        for row in reader:
            line_num += 1
            try:
                json_data = json.loads(row)
                
                status = json_data["data"]["tls"]["status"]
                
                if status not in status_dict:
                    status_dict[status] = 1
                else:
                    status_dict[status] += 1
            except json.JSONDecodeError:
                print(f"Errore nel parsing della riga: {row}")
    
    status_count = sum(status_dict.values())
    
    print("Status: ", status_dict)
    print("Sum of all values: ", status_count)
    print("Total Number of values: ", line_num)
    print("Number of rows excluded from the computation: ", line_num - status_count)
    return

def create_dir(out_dir, rm_dir=True):
    if(rm_dir == True and os.path.exists(out_dir)):
        shutil.rmtree(out_dir)
        print(f"Directory esistente rimossa: {out_dir}")
    
    try:
        os.makedirs(out_dir)  
        print(f"Directory creata: {out_dir}")
        return True
    except Exception as e:
        print(f"Errore durante la creazione della directory: {e}")
        return False

def save_an_example_status(file):
    out_dir = "src/scan/example"
    file_success = lambda index: f"success{index}.json"
    file_connection_timeout = os.path.join(out_dir, "connection_timeout.json")
    file_unknown_error = os.path.join(out_dir, "unknown_error.json")
    file_io_timeout = os.path.join(out_dir, "io_timeout.json")
    
    if(create_dir(out_dir, True) == False):
        return

    count_success = 0
    count_unknown_error = 0
    count_connection_timeout = 0
    count_io_timeout = 0
    
    with open(file, 'r') as reader:
        for row in reader:
            try:
                json_data = json.loads(row)
                
                status = json_data.get("data", {}).get("tls", {}).get("status", "")
                
                if(count_success < 5 and status == "success"):
                    with open(os.path.join(out_dir, file_success(count_success)), 'w') as writer:
                        json.dump(json_data, writer, indent=4)
                        count_success += 1
                
                if(count_connection_timeout == 0 and status == "connection-timeout"):
                    with open(file_connection_timeout, 'w') as writer:
                        json.dump(json_data, writer, indent=4)
                        count_connection_timeout += 1
                        
                if(count_unknown_error == 0 and status == "unknown-error"):
                    with open(file_unknown_error, 'w') as writer:
                        json.dump(json_data, writer, indent=4)
                        count_unknown_error += 1
                
                if(count_io_timeout == 0 and status == "io-timeout"):
                    with open(file_io_timeout, 'w') as writer:
                        json.dump(json_data, writer, indent=4)
                        count_io_timeout += 1
                    
                if(count_success == 5 and count_connection_timeout == 1 and count_unknown_error == 1 and count_io_timeout == 1):
                    break
                
            except json.JSONDecodeError:
                print(f"Errore nel parsing della riga: {row}")


def controlla_struttura(json_data):
    """Controlla la presenza delle chiavi richieste"""
    tls = json_data.get("data", {}).get("tls", {})
    return (
        'domain' in json_data and
        'data' in json_data and
        'tls' in json_data.get('data', {}) and
        'status' in tls and
        'protocol' in tls and
        'timestamp' in tls and
        'error' in tls
    )

def check_error_rows(input_file):
    """ Controlla che ogni riga con status diverso da success abbia la stessa struttura """
    with open(input_file, 'r') as reader:
        for row in reader:
            try:
                json_data = json.loads(row)
                status = json_data.get("data", {}).get("tls", {}).get("status", "")
                
                if(status == "success"):
                    continue
                
                if(status == "connection-timeout"):
                    check = controlla_struttura(json_data)
                    
                if(status == "unknown-error"):
                    check = controlla_struttura(json_data)
                
                if(status == "io-timeout"):
                    check = controlla_struttura(json_data)
                
                if(check == False):
                    print(json_data)
            
            except json.JSONDecodeError:
                print(f"Errore nel parsing della riga: {row}")
    
    print("Ogni riga di errore ha la stessa struttura")

def download_json_domain(input_file, domain: str, line_num: int):
    """
        Scarica i dati JSON di un dominio specificato da un file di input.
        Analizza il file e crea un nuovo file JSON per il dominio trovato
        o restituisce un messaggio se il dominio non è presente.
    """
    
    if(domain is None and line_num is None):
        return
    
    domain_json_data = None
    
    with open(input_file, 'r') as reader:
        for line_number, row in enumerate(reader, start=1):
            if(line_num is not None and line_num < line_number):
                continue
            
            try:
                json_data = json.loads(row)
                domain_data = json_data.get("domain", "")
                
                if(domain_data == domain):
                    domain_json_data = json_data
                    break
                
                if(line_num == line_number):
                    domain_json_data = json_data
                    break
            
            except json.JSONDecodeError:
                print(f"Errore nel parsing della riga: {row}")
    
    if(domain_json_data is not None):
        file_domain = os.path.join("src/scan/", f"{domain}.json")
    
        with open(file_domain, 'w') as writer:
            json.dump(json_data, writer, indent=4)
            print(f"File creato con successo: {file_domain}")
    else:
        print("Dominio non trovato")
        
    return

def check_chain_certificates(input_file):
    """ Controlla che ogni riga con status success abbia almeno un certificato nella catena """
    
    domains = []
    with open(input_file, 'r') as reader:
        for row in reader:
            try:
                json_data = json.loads(row)
                tls = json_data.get("data", {}).get("tls", {})
                status = tls.get("status", "")
                if(status == "success"):
                    chain = tls.get("result", {}).get("handshake_log", {}).get("server_certificates", {}).get("chain", [])
                    if(len(chain) == 0):
                        domain = json_data.get("domain", "")
                        domains.append(domain)
                
            except json.JSONDecodeError:
                print(f"Errore nel parsing della riga: {row}")
    
    if(len(domains) == 0):
        print("Ogni dominio ha almeno un certificato nella catena")
    else:
        print("Ci sono dei domini che non hanno una catena")
        print(domains)
    return

def count_root_cert_chain(input_file):
    """
        Conta i certificati self-signed nella catena.
        Analizza un file JSON di certificati TLS e registra i domini con certificati self-signed.
    """
    out_file = "src/scan/count_root_certs_chain.log"
    count_certs = 0
    count_leaf_self_signed = 0
    
    with open(input_file, 'r') as reader, open(out_file, 'w+') as writer:
        for line_num, row in enumerate(reader, start=1):
            try:
                json_row = json.loads(row)
                
                status = json_row.get("data", {}).get("tls", {}).get("status", "")
                
                count_self_signed = 0
                if status == "success":
                    handshake_log = json_row.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {})
                    server_certificates = handshake_log.get("server_certificates", {})
                    is_leaf_self_signed = server_certificates.get("certificate", {}).get("parsed", {}).get("signature", {}).get("self_signed", {})
                    chain = server_certificates.get("chain", [])
                    
                    if(is_leaf_self_signed):
                        count_leaf_self_signed += 1
                    
                    for cert in chain:
                        is_self_signed = cert.get("parsed", {}).get("signature", {}).get("self_signed", {})
                        if(is_self_signed):
                            count_self_signed += 1
                    
                    if(count_self_signed > 1):
                        count_certs += 1
                        domain = json_row.get("domain", "")
                        writer.write("------------------------------------------------------------------\n")
                        writer.write(f"Il dominio {domain} ha esattamente {count_self_signed} self signed.\n")
                        writer.write(f"Certificato presente alla riga numero {line_num} dell'input file.\n")
                       
            except json.JSONDecodeError:
                print(f"Errore nel parsing della riga: {row}")
        
    with open(out_file, 'r') as reader:
        original_content = reader.readlines()

    with open(out_file, 'w') as writer:
        writer.write(f"Numero totale di certificati che hanno certificati self signed nella catena: {count_certs}\n")
        writer.write(f"Numero totale di certificati leaf che sono self signed: {count_leaf_self_signed}\n\n")
        writer.writelines(original_content)
        writer.write("------------------------------------------------------------------\n")
    return

def count_certs_chain(input_file):
    """ 
        Conta le catene di certificati in base alla presenza di root e intermediate.
        Analizza un file JSON di certificati TLS e registra i risultati delle catene.
    """
    out_file = "src/scan/count_certs_chain.log"
    no_chain_count = 0
    chain_with_root_count = 0
    chain_without_root_count = 0
    chain_without_intermediate_and_root_count = 0
    
    with open(input_file, 'r') as reader:
        for line_num, row in enumerate(reader, start=1):
            try:
                json_row = json.loads(row)
                
                status = json_row.get("data", {}).get("tls", {}).get("status", "")
                
                if status == "success":
                    handshake_log = json_row.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {})
                    server_certificates = handshake_log.get("server_certificates", {})
                    chain: list = server_certificates.get("chain", [])
                    current_cert = server_certificates.get("certificate")
                    is_intermediate_found = False   # Rivela se almeno un intermediate è presente nella catena
                    
                    if len(chain) > 0:
                        while True:
                            subject_dn = current_cert.get("parsed", {}).get("subject_dn", "")
                            issuer_dn = current_cert.get("parsed", {}).get("issuer_dn", "")
                            is_self_signed = current_cert.get("parsed", {}).get("signature", {}).get("self_signed", {})
                            
                            # Controlla se siamo arrivati al root
                            if is_self_signed and subject_dn == issuer_dn:
                                chain_with_root_count += 1
                                break
                            
                            # Cerca il certificato successivo nella catena
                            next_cert = next((cert for cert in chain if cert.get("parsed", {}).get("subject_dn", "") == issuer_dn), None)
                            
                            if next_cert:
                                is_intermediate_found = True
                                try:
                                    chain.remove(current_cert)
                                except ValueError:
                                    pass
                                current_cert = next_cert
                            else:
                                if(is_intermediate_found):
                                    chain_without_root_count += 1
                                else:
                                    chain_without_intermediate_and_root_count += 1
                                break
                    else:
                        no_chain_count += 1         
            except json.JSONDecodeError:
                print(f"Errore nel parsing della riga: {row}")

    with open(out_file, 'w') as writer:
        writer.write(f"Numero totale di certificati che hanno almeno un intermediate e un root nella catena: {chain_with_root_count}\n")
        writer.write(f"Numero totale di certificati che hanno un intermediate ma nessun root nella catena: {chain_without_root_count}\n")
        writer.write(f"Numero totale di certificati che non hanno nè un intermediate e nè un root nella catena: {chain_without_intermediate_and_root_count}\n")
        writer.write(f"Numero totale di certificati che non hanno una catena: {no_chain_count}\n")
        writer.write(f"Totale (deve corrispondere al numero di success): {chain_with_root_count+chain_without_root_count+chain_without_intermediate_and_root_count+no_chain_count}\n")
    return

def check_sct_intermediate_certs_chain(input_file):
    """ Controlla se esiste un certificato intermediate che ha almeno un SCT"""

    with open(input_file, 'r') as reader:
        for line_num, row in enumerate(reader, start=1):
            try:
                json_row = json.loads(row)
                
                status = json_row.get("data", {}).get("tls", {}).get("status", "")
                
                if status == "success":
                    handshake_log = json_row.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {})
                    server_certificates = handshake_log.get("server_certificates", {})
                    chain: list = server_certificates.get("chain", [])
                    current_cert = server_certificates.get("certificate")
                    
                    if len(chain) > 0:
                        while True:
                            subject_dn = current_cert.get("parsed", {}).get("subject_dn", "")
                            issuer_dn = current_cert.get("parsed", {}).get("issuer_dn", "")
                            is_self_signed = current_cert.get("parsed", {}).get("signature", {}).get("self_signed", {})
                            
                            # Controlla se siamo arrivati al root
                            if is_self_signed and subject_dn == issuer_dn:
                                break
                            
                            # Cerca il certificato successivo nella catena
                            next_cert = next((cert for cert in chain if cert.get("parsed", {}).get("subject_dn", "") == issuer_dn), None)
                            
                            if next_cert:
                                is_sct = next_cert.get("parsed", {}).get("extensions", {}).get("signed_certificate_timestamps", [])
                                if(len(is_sct) > 0):
                                    print(f"Esiste un certificato intermedio con un SCT alla riga {line_num}")
                                    return
                                try:
                                    chain.remove(current_cert)
                                except ValueError:
                                    pass
                                current_cert = next_cert
            except json.JSONDecodeError:
                print(f"Errore nel parsing della riga: {row}")

    return

def main():
    result_json_file = os.path.abspath('res/certs_polito.json')
    
    # count_status(result_json_file)
    # save_an_example_status(result_json_file)
    
    # check_error_rows(result_json_file)

    # check_chain_certificates(result_json_file)

    download_json_domain(result_json_file, "semrush.com", None)
    # download_json_domain(result_json_file, None, 1505)

    # count_root_cert_chain(result_json_file)
    # count_certs_chain(result_json_file)
    
    # check_sct_intermediate_certs_chain(result_json_file)

if __name__ == "__main__":
    main()
