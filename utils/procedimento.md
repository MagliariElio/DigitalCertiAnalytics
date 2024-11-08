### **Analisi dei Certificati con Zgrab2**

#### **Top 10 Million Domains - DomCop10M**
Impostando un timeout di 30 secondi, **Zgrab2** ha impiegato **7 ore e 33 minuti** per scaricare i certificati SSL/TLS di **10 milioni di domini** a partire dall'elenco **DomCop10M**.

- **Totale certificati scaricati con successo**: 7.045.024
- **Totale certificati con errore**: 2.954.976

  **Tipologie di errore rilevate**:
  - **Connection timeout**: 2.604.347
  - **I/O timeout**: 146.147
  - **Unknown error**: 204.482

#### **Tempi di analisi e dimensione del database**:
- **Leaf Certificates**:
  - Tempo analisi: **21 ore e 20 minuti** (27 ore con indici)
  - Dimensione del database senza indici: **45 GB**
  
- **Intermediate Certificates**:
  - Tempo analisi: **14 ore e 47 minuti**
  - Dimensione del database senza indici: **50 GB**

- **Root Certificates**:
  - Tempo analisi: **2 ore**
  - Dimensione del database con indici: **2 GB**

#### **Analisi della Catena dei Certificati**:
- **Certificati con almeno un intermediate e root nella catena**: **371.697**
- **Certificati con un intermediate ma senza root nella catena**: **6.507.964**
- **Certificati senza né intermediate né root nella catena**: **9.484**
- **Certificati senza catena**: **155.879**

---

### **Domini Europei da Google**

I **domini europei** sono stati estratti utilizzando una query su un sistema di **big data** di Google, interrogando il **Chrome User Experience Report (CrUX)**, disponibile tramite **Google Cloud**. In particolare, è stata eseguita una query SQL sui domini di settembre, estraendo i primi **10 milioni di domini più popolari** in Europa, classificati per **experimental.popularity.rank**.

Il risultato è stato scaricato da **Google Cloud** come file e poi analizzato con **Zgrab2** per scaricare i certificati.

Impostando un timeout di 30 secondi, **Zgrab2** ha impiegato **4 ore e 56 minuti** per scaricare i certificati da **10 milioni di domini europei**.

- **Totale certificati scaricati con successo**: **9.440.561**
- **Totale certificati con errore**: **559.440**

