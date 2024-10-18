# Analisi dei Certificati Digitali con ZGrab2

## Descrizione del Progetto

Questo progetto ha l'obiettivo di analizzare i certificati digitali di 10 milioni di domini utilizzando lo strumento open-source [ZGrab2](https://github.com/zmap/zgrab2?tab=readme-ov-file). Il processo prevede uno scan di ciascun dominio per ottenere il certificato digitale del server e, ove disponibile, quelli della sua catena di certificati intermedi. L'output generato viene analizzato e inserito in un database per ulteriori verifiche e controlli.

## Tool Utilizzato: ZGrab2

ZGrab2 è uno strumento di scanning di livello applicativo, progettato per raccogliere informazioni da server remoti tramite protocolli di rete. In questo progetto, è stato utilizzato per contattare i server su porta 443 (TLS) e raccogliere i certificati digitali associati.

Il comando utilizzato per eseguire il tool è stato il seguente:

```bash
zgrab2 tls --port 443 -f input_file.txt --output-file=certs_polito.json --timeout=30
```

Dove:
- `--port 443` specifica la porta da contattare (TLS/SSL).
- `-f input_file.txt` indica il file contenente i domini da analizzare, che devono essere esclusivamente domini senza ulteriori dettagli, come descritto nella documentazione ufficiale di ZGrab2.
- `--output-file=certs_polito.json` definisce il file di output che contiene i risultati dell’analisi.
- `--timeout=30` imposta un timeout di 30 secondi per ogni richiesta.

## Dataset Utilizzato

Per questo scan è stato utilizzato il file *Top 10 Million Domains* scaricato da [DomCop](https://www.domcop.com/files/top/top10milliondomains.csv.zip). La scansione ha richiesto circa 17 ore per completare l'analisi di 10 milioni di domini.

### Tipologie di Errori Riscontrati
Gli errori rilevati durante l'esecuzione dello scan sono stati categorizzati come segue:
- `connection-timeout`: timeout della connessione.
- `unknown-error`: errore sconosciuto.
- `io-timeout`: timeout di input/output.

### Esempi di Output

#### Risposta di Errore
Una risposta di errore ha la seguente struttura:

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

#### Risposta di Successo
Una risposta di successo ha la seguente struttura:

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
                        // Proprietà del TLS handshake
                    },
                    "server_certificates": {
                        // Dettagli del certificato del server e catena
                    }
                }
            },
            "timestamp": "2024-10-06T00:44:30+02:00"
        }
    }
}
```

## Analisi dei Certificati

I risultati estratti sono stati salvati in un file JSON di circa 80 GB. Un software aggiuntivo è stato sviluppato per leggere questo file e inserire i dati in un database SQLite3. Il software esegue verifiche come la validità dell'OCSP, il controllo delle estensioni critiche e altre operazioni di validazione. Questi controlli sono stati effettuati per ogni certificato della catena: leaf, intermedi e root.

## Utilizzo del Software di Analisi

Nella cartella di output è presente un programma che consente di analizzare ulteriormente i dati, verificare proprietà specifiche dei certificati e ottenere informazioni aggiuntive.

## Risultati

- **Domini Totali Scansionati**: 10.000.000
- **Successi**: 6.545.217 (65% di successo)
- **Fallimenti**: 3.454.783

# DigitalCertiAnalytics

## Descrizione

Il **DigitalCertiAnalytics** è uno strumento progettato per analizzare i certificati digitali e generare una serie di analisi dettagliate in base ai dati estratti. Il programma consente di:

- Analizzare i certificati leaf contenuti in un file JSON.
- Visualizzare i risultati dell'analisi tramite grafici generati automaticamente.

### Funzionalità principali:
- **Analisi dei certificati leaf**: estrae dati rilevanti dai certificati e li memorizza in un database per una successiva analisi.
- **Visualizzazione grafica dei risultati**: genera grafici che rappresentano i dati analizzati.

---

## Requisiti di Installazione

Per eseguire il programma, è necessario avere i seguenti software installati:

### 1. Python 3.x
Scarica e installa l'ultima versione di Python dal [sito ufficiale](https://www.python.org/).

### 2. Librerie Python
Assicurati di installare le seguenti librerie Python utilizzando il comando `pip`. Puoi installare i pacchetti necessari utilizzando il file `requirements.txt`. Segui questi passi:

1. Crea un ambiente virtuale (opzionale ma consigliato):
   ```bash
   python -m venv env
   source env/bin/activate   # Su Windows usa: env\Scripts\activate
   ```

2. Installa le dipendenze:
   ```bash
   pip install -r requirements.txt
   ```

## Guida all'Uso

### 1. Clonare il repository
Clona il repository del progetto utilizzando Git:

```bash
git clone git@github.com:MagliariElio/DigitalCertiAnalytics.git
cd DigitalCertiAnalytics
```

### 2. Eseguire il programma
Il programma può essere eseguito tramite il terminale o la riga di comando. Sono disponibili diversi flag che controllano l'esecuzione del programma.

### Opzioni disponibili:
- `--delete_db`: elimina il database esistente prima di iniziare l'analisi.
- `--leaf_analysis`: esegue l'analisi dei certificati leaf.
- `--plot_results`: genera e visualizza grafici dai dati analizzati.

#### Esempi di utilizzo:

1. **Eseguire solo l'analisi dei certificati leaf**:
   ```bash
   python analysis.main -m --leaf_analysis
   ```

2. **Eliminare il database e analizzare i certificati**:
   ```bash
   python analysis.main -m --delete_db --leaf_analysis
   ```

3. **Generare e visualizzare i grafici dai dati**:
   ```bash
   python analysis.main -m --plot_results
   ```

4. **Eseguire tutte le operazioni (elimina DB, analizza certificati e visualizza grafici)**:
   ```bash
   python analysis.main -m --delete_db --leaf_analysis --plot_results
   ```

### 3. Struttura dei File

- `certs_polito.json`: file JSON contenente i certificati da analizzare.
- `leaf_certificates.db`: file di database SQLite dove sono memorizzati i risultati dell'analisi.
- `schema_leaf_db.sql`: script SQL per creare lo schema del database.
- `analysis/`: directory contenente il database e altri file di analisi.
- `analysis/plots`: directory dove sono memorizzati i risultati grafici.
- `scan/`: directory contenente un file di scan sul file JSON.

### 4. Log
Il programma genera un file di log `app.log` che registra l'andamento dell'applicazione e eventuali errori. Il log sarà disponibile nella directory di esecuzione del programma.
