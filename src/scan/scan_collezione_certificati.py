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
                
                status = json_data["data"]["tls"]["status"]
                
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
    # Controlla la presenza delle chiavi richieste
    return (
        'domain' in json_data and
        'data' in json_data and
        'tls' in json_data['data'] and
        'status' in json_data['data']['tls'] and
        'protocol' in json_data['data']['tls'] and
        'timestamp' in json_data['data']['tls'] and
        'error' in json_data['data']['tls']
    )

def check_error_rows(input_file):
    """ Controlla che ogni riga con status diverso da success abbia la stessa struttura """
    with open(input_file, 'r') as reader:
        for row in reader:
            try:
                json_data = json.loads(row)
                status = json_data["data"]["tls"]["status"]
                
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
    
def main():
    result_json_file = os.path.abspath('res/certs_polito_windows_2.json')
    
    count_status(result_json_file)
    # save_an_example_status(result_json_file)
    
    # check_error_rows(result_json_file)

    # check_chain_certificates(result_json_file)

    # download_json_domain(result_json_file, "terrafly.com", None)
    # download_json_domain(result_json_file, None, 112200)

if __name__ == "__main__":
    main()
