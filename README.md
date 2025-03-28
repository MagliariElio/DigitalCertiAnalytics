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

### 2. **Zlint**
**Zlint** è uno strumento di analisi per certificati TLS/SSL che verifica la conformità e la sicurezza dei certificati. Prima di eseguire il programma, è fondamentale installare Zlint e assicurarsi che l'eseguibile sia presente nella cartella del progetto **DigitalCertiAnalytics**. Pertanto, si consiglia di seguire questo passaggio dopo aver clonato il repository GitHub del progetto (consultare la sezione "Guida all'uso" per sapere come procedere).

#### **Installazione di Zlint:**

1. **Clona il repository di Zlint**:
   Zlint può essere scaricato dal suo repository GitHub ufficiale:
   ```bash
   git clone https://github.com/zmap/zlint
   ```

2. **Compilazione di Zlint**:
   Dopo aver clonato il repository, entra nella cartella del progetto Zlint e compila il progetto:
   ```bash
   cd zlint
   make
   ```
   *Attenzione per eseguire questa azione è necessario che **Go** sia stato installato correttamente, per maggiori informazioni affidarsi al file **README** presente nel repository GitHub ufficiale del progetto Zlint.*

3. **Posizione dell'eseguibile**:
   Una volta completata la compilazione, l'eseguibile di Zlint sarà disponibile nella cartella `zlint/v3/zlint`. Assicurati che il percorso dell'eseguibile corrisponda al valore previsto nel programma, che cercherà l'eseguibile in:
   ```python
   base_dir = os.path.dirname(os.path.abspath(__file__))
   zlint_path = os.path.join(base_dir, "../../zlint/v3/zlint")
   ```

4. **Verifica che Zlint sia correttamente installato**:
   Puoi testare che Zlint funzioni correttamente eseguendo il seguente comando nel terminale:
   ```bash
   ./zlint/v3/zlint --help
   ```

   Se tutto è stato configurato correttamente, dovresti vedere l'output delle opzioni di Zlint.

5. **Impostare il percorso di Zlint**:
   Assicurati che l'eseguibile Zlint sia nella cartella `zlint/v3/`, come specificato nel codice. Se il percorso non è corretto, il programma non riuscirà a eseguire l'analisi Zlint. Se necessario, puoi modificare il percorso nel codice Python dove è definito `zlint_path` per riflettere la posizione esatta.

### 3. **MongoDB**
Per utilizzare il programma con il salvataggio dei dati, è necessario installare MongoDB sul proprio computer. Inoltre, prima di eseguire comandi come `--leaf_zlint_check` o `--intermediate_zlint_check`, che richiedono l'interazione con MongoDB, è importante assicurarsi che il servizio di MongoDB sia avviato e funzionante.

#### **Verifica e avvio di MongoDB su Linux:**

1. **Verificare lo stato di MongoDB**:
   Puoi controllare se il servizio MongoDB è attivo eseguendo il comando:
   ```bash
   sudo systemctl status mongod
   ```

   Se il servizio è attivo, vedrai un messaggio che indica che MongoDB è in esecuzione.

2. **Avviare MongoDB se non è attivo**:
   Se MongoDB non è attivo, puoi avviare il servizio con il comando:
   ```bash
   sudo systemctl start mongod
   ```

3. **Verifica che MongoDB sia attivo**:
   Dopo aver avviato il servizio, verifica di nuovo lo stato con:
   ```bash
   sudo systemctl status mongod
   ```

4. **Abilitare l'avvio automatico di MongoDB**:
   Puoi anche configurare MongoDB per avviarsi automaticamente al riavvio del sistema con:
   ```bash
   sudo systemctl enable mongod
   ```

### 4. Librerie Python
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
Il programma può essere eseguito tramite il terminale o la riga di comando, con diverse opzioni per controllare l'esecuzione del programma.

#### Opzioni disponibili:
- `--delete_all_db`: elimina tutti i database esistenti prima di iniziare l'analisi.
- `--delete_leaf_db`: elimina il database dei certificati leaf prima di iniziare l'analisi.
- `--delete_intermediate_db`: elimina il database dei certificati intermedi prima di iniziare l'analisi.
- `--delete_root_db`: elimina il database dei certificati root prima di iniziare l'analisi.
  
- `--leaf_analysis`: esegue l'analisi dei certificati leaf.
- `--leaf_ocsp_analysis`: esegue l'analisi OCSP per i certificati leaf.
- `--leaf_zlint_check`: esegue l'analisi Zlint sui certificati leaf per verificare eventuali vulnerabilità e configurazioni errate secondo determinati requisiti ufficiali.
- `--leaf_chain_validation`: esegue la validazione della catena dei certificati leaf per verificare la conformità e l'affidabilità della catena di trust.

- `--intermediate_analysis`: esegue l'analisi dei certificati intermedi.
- `--intermediate_ocsp_analysis`: esegue l'analisi OCSP per i certificati intermedi.
- `--intermediate_zlint_check`: esegue l'analisi Zlint sui certificati intermedi per verificare eventuali vulnerabilità e configurazioni errate secondo determinati requisiti ufficiali.

- `--root_analysis`: esegue l'analisi dei certificati root.
- `--root_ocsp_analysis`: esegue l'analisi OCSP per i certificati root.

- `--plot_all_results`: genera e visualizza i grafici per tutti i dati analizzati sui certificati.
- `--plot_leaf_results`: genera e visualizza i grafici per i risultati dell'analisi dei certificati leaf.
- `--plot_intermediate_results`: genera e visualizza i grafici per i risultati dell'analisi dei certificati intermedi.
- `--plot_root_results`: genera e visualizza i grafici per i risultati dell'analisi dei certificati root.

- `-v, --verbose`: attiva la modalità verbose per una registrazione dettagliata.

#### Esempi di utilizzo:

1. **Eseguire solo l'analisi dei certificati leaf**:
   ```bash
    python -m analysis.main --leaf_analysis
   ```

2. **Eliminare il database dei certificati intermedi e avviare l'analisi**:
   ```bash
    python -m analysis.main --delete_intermediate_db --intermediate_analysis
   ```

3. **Eseguire analisi OCSP per certificati root e generare grafici solo per i certificati root**:
   ```bash
    python -m analysis.main --root_ocsp_analysis --plot_root_results
   ```

4. **Eliminare tutti i database, analizzare i certificati leaf e intermedi e visualizzare tutti i grafici**:
   ```bash
    python -m analysis.main --delete_all_db --leaf_analysis --intermediate_analysis --plot_all_results
   ```
5. **Attivare la modalità verbose per una registrazione dettagliata**:
   ```bash
    python -m analysis.main --delete_leaf_db --leaf_analysis -v
   ```
6. **Eseguire l'analisi Zlint sui certificati leaf e validare la catena**:
   ```bash
    python -m analysis.main --leaf_zlint_check --leaf_chain_validation
   ```

### 3. Struttura dei File

- `res/queries.sql`: file SQL utilizzato per eseguire delle query di analisi sui database relazionali.
- `res/queries_big_query.sql`: file SQL contenente la query utilizzata per ottenere un elenco di domini europei dal servizio BigQuery di Google.
- `res/log_list.json`: file JSON che contiene l'elenco dei logger utilizzati dal programma per analizzare gli SCT.
- `res/certs_polito.json`: file JSON contenente i certificati da analizzare, output del file Zgrab2 dell'analisi eseguita a partire dalla lista dei domini dati come input.
- `src/analysis/`: directory contenente il database e altri file di analisi.
- `src/analysis/leaf/leaf_certificates.db`: file di database SQLite dove sono memorizzati i risultati dell'analisi dei certificati leaf.
- `src/analysis/intermediate/intermediate_certificates.db`: file di database SQLite dove sono memorizzati i risultati dell'analisi dei certificati intermediate.
- `src/analysis/root/root_certificates.db`: file di database SQLite dove sono memorizzati i risultati dell'analisi dei certificati root.
- `src/analysis/leaf/ocsp_certificates_backup.db`: file di backup in CSV dove sono memorizzati i risultati dell'analisi OCSP dei certificati leaf.
- `src/analysis/intermediate/ocsp_certificates_backup.db`: file di backup in CSV dove sono memorizzati i risultati dell'analisi OCSP dei certificati intermediate.
- `src/analysis/root/ocsp_certificates_backup.db`: file di backup in CSV dove sono memorizzati i risultati dell'analisi OCSP dei certificati root.
- `src/analysis/leaf/plots`: directory dove sono memorizzati i risultati grafici dei certificati leaf.
- `src/analysis/intermediate/plots`: directory dove sono memorizzati i risultati grafici dei certificati intermediate.
- `src/analysis/root/plots`: directory dove sono memorizzati i risultati grafici dei certificati root.
- `zlint_analysis/reading_zlint_results.py`: script Python progettato per estrarre i dati dal database non relazionale MongoDB e strumentale per eseguire analisi dettagliate sui dati dei certificati memorizzati.
- `src/db/schema_db.sql`: script SQL per creare lo schema dei database leaf, intermediate e root.
- `src/scan/`: directory contenente un file di scan sul file JSON.

### 4. Log
Il programma genera un file di log `app.log` che registra l'andamento dell'applicazione e eventuali errori. Il log sarà disponibile nella directory di esecuzione del programma.

## Visualizzare e Gestire il Database MongoDB

Per visualizzare e gestire facilmente il database MongoDB, è consigliato utilizzare uno strumento di gestione MongoDB con un interfaccia grafica, come **MongoDB Compass**. Compass ti consente di esplorare i dati del database, eseguire query, analizzare la struttura del database, e molto altro.

### Come installare MongoDB Compass:
1. Vai al sito ufficiale di MongoDB Compass: [MongoDB Compass](https://www.mongodb.com/products/compass).
2. Scarica e installa la versione compatibile con il tuo sistema operativo (Windows, macOS, Linux).
3. Una volta installato, avvia Compass e connettiti al tuo server MongoDB utilizzando le credenziali appropriate.

Compass offre un'interfaccia facile da usare per visualizzare i dati, analizzare le collezioni, e modificare i documenti. Puoi esplorare facilmente il tuo database e interagire con esso tramite l'interfaccia grafica.

### Come eseguire il dump di un database MongoDB

Se desideri creare un backup (dump) del database MongoDB, puoi farlo utilizzando il comando **`mongodump`**. Questo comando crea una copia dei dati del database in una directory specificata. Assicurati di avere **`mongodump`** installato sul tuo sistema. Se non lo hai, puoi scaricarlo insieme a MongoDB o come parte della distribuzione degli strumenti di MongoDB.

#### I comandi per eseguire il dump dei database sono i seguenti:

1. **Per il database "Leaf_Zlint_Checks"**:
   ```bash
   mongodump --db Leaf_Zlint_Checks --out Leaf_Zlint_Checks
   ```

2. **Per il database "Intermediate_Zlint_Checks"**:
   ```bash
   mongodump --db Intermediate_Zlint_Checks --out Intermediate_Zlint_Checks
   ```

Questi comandi creeranno una copia dei dati dei rispettivi database nella directory indicata come `--out`. Puoi quindi utilizzare questi file di dump per ripristinare i dati o per fare delle analisi.

### Assicurarsi che `mongodump` sia installato:

Per eseguire i comandi `mongodump`, devi avere MongoDB e gli strumenti di linea di comando installati sul tuo sistema. Ecco come fare:

1. Se non hai già MongoDB, puoi scaricarlo dal sito ufficiale: [Download MongoDB](https://www.mongodb.com/try/download/community).
2. Se hai già MongoDB, ma non gli strumenti di linea di comando, puoi scaricare il pacchetto degli strumenti separatamente. Puoi trovarlo nella sezione "MongoDB Database Tools" sulla stessa pagina di download di MongoDB.
3. Una volta installato, assicurati che il comando `mongodump` sia disponibile nel tuo **PATH** di sistema. Puoi verificarlo eseguendo il comando `mongodump --version` nel terminale per vedere se viene restituita una versione.
