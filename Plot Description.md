# Query SQL per l'Analisi dei Certificati Digitali

Questo documento descrive le varie query SQL eseguite per analizzare i certificati digitali e fornisce il tipo di grafico suggerito per visualizzare i risultati.

---

## Emissione dei Certificati da Parte degli Issuer
- **Descrizione**: Conta il numero di certificati emessi da ciascun Issuer.
- **Grafico Consigliato**: Bar Chart per visualizzare i primi Issuer e un gruppo "Others" per quelli meno rappresentati.

---

## Numero di Certificati Emessi in Diversi Paesi
- **Descrizione**: Conta quanti certificati sono stati emessi per ciascun paese.
- **Grafico Consigliato**: Bar Chart o Mappa Geografica per visualizzare la distribuzione geografica.

---

## Distribuzione della Durata di Validità
- **Descrizione**: Mostra la distribuzione delle durate di validità dei certificati.
- **Grafico Consigliato**: Histogram per rappresentare la distribuzione della durata.

---

## Trend di Scadenza dei Certificati
- **Descrizione**: Rappresenta il numero di certificati che scadranno nel tempo.
- **Grafico Consigliato**: Line Chart per visualizzare il trend delle scadenze dei certificati.

---

## Algoritmi di Firma Utilizzati
- **Descrizione**: Mostra la distribuzione degli algoritmi di firma utilizzati.
- **Grafico Consigliato**: Bar Chart per confrontare i diversi algoritmi di firma.

---

## Distribuzione degli Algoritmi di Chiave e Lunghezza
- **Descrizione**: Visualizza la combinazione di key_algorithm e key_length utilizzati nei certificati.
- **Grafico Consigliato**: Stacked Bar Chart o Multi-Bar Chart per confrontare la combinazione di algoritmi di chiave e lunghezza.

---

## Stato OCSP dei Certificati
- **Descrizione**: Mostra la distribuzione degli stati OCSP come "Good", "Revoked", ecc.
- **Grafico Consigliato**: Pie Chart o Bar Chart per visualizzare la distribuzione degli stati OCSP.

---

## Certificati Auto-Firmati vs CA-Firmati
- **Descrizione**: Rappresenta la proporzione di certificati auto-firmati rispetto a quelli firmati da una CA.
- **Grafico Consigliato**: Pie Chart per confrontare le proporzioni.

---

## Livelli di Validazione dei Certificati
- **Descrizione**: Mostra la distribuzione dei diversi validation_level dei certificati.
- **Grafico Consigliato**: Bar Chart per rappresentare i diversi livelli di validazione.

---

## Estensioni Critiche vs Non Critiche dell'AIA
- **Descrizione**: Conta il numero di certificati che hanno implementato estensioni critiche rispetto a quelle non critiche dell'AIA.
- **Grafico Consigliato**: Bar Chart per visualizzare il numero di certificati in ciascuna categoria (critici vs non critici).

---

## Distribuzione delle Versioni dei Certificati
- **Descrizione**: Mostra la distribuzione delle versioni dei certificati (es. v1, v2, v3).
- **Grafico Consigliato**: Pie Chart o Bar Chart per visualizzare la distribuzione delle versioni.

---

## Validità delle Firme dei Certificati
- **Descrizione**: Rappresenta la proporzione di firme valide rispetto a quelle non valide.
- **Grafico Consigliato**: Pie Chart per visualizzare la validità delle firme.

---

## Analisi Status Certificati
- **Descrizione**: Mostra il numero di Success dei certificati e la frequenza dei diversi tipi di errori nei certificati.
- **Grafico Consigliato**: Bar Chart per mostrare la distribuzione degli errori.

---

## Utilizzo del Key Usage nelle Estensioni
- **Descrizione**: Mostra quali key_usage sono più comunemente utilizzati nei certificati.
- **Grafico Consigliato**: Bar Chart per visualizzare l'uso delle chiavi.

---

## Estensioni Critiche vs Non Critiche del Key Usage nelle Estensioni
- **Descrizione**: Mostra la proporzione di key_usage critici rispetto a quelli non critici.
- **Grafico Consigliato**: Pie Chart o Bar Chart per confrontare estensioni critiche e non critiche.

---

## Utilizzo dell'Extended Key Usage nelle Estensioni
- **Descrizione**: Visualizza quali extended_key_usage sono più comuni nei certificati.
- **Grafico Consigliato**: Bar Chart per mostrare l'uso delle chiavi estese.

---

## Estensioni Critiche vs Non Critiche dell'Extended Key Usage nelle Estensioni
- **Descrizione**: Mostra la proporzione di extended_key_usage critici rispetto a quelli non critici.
- **Grafico Consigliato**: Pie Chart o Bar Chart per confrontare estensioni critiche e non critiche.

---

## Distribuzione del Basic Constraints nelle Estensioni
- **Descrizione**: Mostra la distribuzione dei Basic Constraints nei certificati.
- **Grafico Consigliato**: Bar Chart per rappresentare i vari Basic Constraints.

---

## Estensioni Critiche vs Non Critiche del CRL Distribution
- **Descrizione**: Mostra la proporzione di estensioni CRL critical vs non critical.
- **Grafico Consigliato**: Pie Chart o Bar Chart per visualizzare la differenza.

---

## Trend dei Signed Certificate Timestamps (SCT) per Mese e Anno
- **Descrizione**: Mostra la distribuzione temporale per mese e anno dei Signed Certificate Timestamps.
- **Grafico Consigliato**: Line Chart per rappresentare il trend dei Signed Certificate Timestamps.

---

## Numero dei Signed Certificate Timestamps (SCT) per Certificato
- **Descrizione**: Conta quanti certificati hanno 1 SCT, 2 SCT, e così via.
- **Grafico Consigliato**: Bar Chart per visualizzare la distribuzione del numero di SCT.

---

## Top SCT Logs
- **Descrizione**: Mostra quali log di SCT sono stati usati più spesso.
- **Grafico Consigliato**: Bar Chart per rappresentare i principali Log di SCT.

---

## Top SCT Log Operators
- **Descrizione**: Conta i log di SCT per ogni operatore, mostrando quelli più utilizzati.
- **Grafico Consigliato**: Bar Chart per rappresentare i principali operatori di log.

---

## Estensioni Critiche vs Non Critiche delle Subject Alternative Name
- **Descrizione**: Mostra la proporzione di estensioni critiche vs non critiche nelle Subject Alternative Name.
- **Grafico Consigliato**: Pie Chart per visualizzare la proporzione di estensioni critiche.

---

## Estensioni Critiche vs Non Critiche del Certificate Policies
- **Descrizione**: Mostra la proporzione di certificate policies critici rispetto a quelli non critici.
- **Grafico Consigliato**: Pie Chart o Bar Chart per confrontare estensioni critiche e non critiche.

---