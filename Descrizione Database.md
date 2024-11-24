### Descrizione del database per l'analisi dei certificati digitali (Leaf, Intermediate, Root)

Questo schema di database è progettato per supportare l'analisi dei certificati digitali nelle tre principali tipologie di certificati: **Leaf**, **Intermediate** e **Root**. In base al tipo di database utilizzato, alcune colonne e tabelle possono essere rimosse per adattarsi meglio al tipo di certificato in analisi.

### Tabelle principali

#### 1. **Issuers**
La tabella `Issuers` conserva i dettagli sugli **emittenti** dei certificati (autorità di certificazione, CA). Ogni riga rappresenta un'entità che ha emesso un certificato, e i dati forniti sono utili per tracciare la catena di fiducia.

- **issuer_id**: Identificatore univoco per l'emittente.
- **common_name**: Nome comune dell'emittente.
- **organization**: Nome dell'organizzazione dell'emittente.
- **issuer_dn**: Distinct Name (DN) dell'emittente.
- **country, province, locality**: Dettagli geografi dell'emittente (paese, provincia, città).
- **organizational_unit**: Unità organizzativa dell'emittente.
- **authority_key_id**: ID della chiave pubblica dell'autorità di certificazione.
- **raw**: Dati grezzi del certificato dell'emittente.

#### 2. **Subjects**
La tabella `Subjects` memorizza i dettagli sui **soggetti** dei certificati, cioè le entità a cui è stato emesso un certificato. Un soggetto può essere una persona, un'organizzazione o un server.

- **subject_id**: Identificatore univoco per il soggetto.
- **common_name**: Nome comune del soggetto.
- **subject_dn**: Distinct Name (DN) del soggetto.
- **subject_key_id**: ID della chiave pubblica del soggetto.
- **subject_alt_name**: Nome alternativo del soggetto, utile in contesti con certificati multi-dominio.
- **subject_alt_name_is_critical**: Indica se il nome alternativo del soggetto è critico.

#### 3. **Certificates**
La tabella `Certificates` è la tabella centrale che memorizza i dettagli di ogni certificato digitale. Le informazioni includono dettagli sulla validità, sull'emittente e sul soggetto, nonché eventuali estensioni critiche.

- **certificate_id**: Identificatore univoco del certificato.
- **serial_number**: Numero seriale del certificato.
- **leaf_domain**: Dominio associato al certificato (nei certificati intermediate e root si riferisce sempre al dominio leaf).
- **issuer_id**: Riferimento all'emittente del certificato (tabella `Issuers`).
- **subject_id**: Riferimento al soggetto del certificato (tabella `Subjects`).
- **version**: Versione del certificato (ad esempio v3).
- **signature_algorithm**: Algoritmo utilizzato per firmare il certificato.
- **key_algorithm**: Algoritmo della chiave pubblica.
- **key_length**: Lunghezza della chiave pubblica.
- **validity_start**: Data di inizio validità del certificato.
- **validity_end**: Data di scadenza del certificato.
- **validity_length**: Durata in giorni del certificato.
- **SAN (Subject Alternative Name)**: Elenco di nomi alternativi (solo per certificati che li supportano).
- **domain_matches_san**: Indica se il dominio del certificato corrisponde a uno dei SAN.
- **authority_info_access_is_critical**: Se l'accesso alle informazioni dell'autorità è critico.
- **authority_info_access**: Dettagli su come ottenere informazioni aggiuntive sull'autorità (ad esempio URL OCSP).
- **ocsp_check**: Stato della verifica del certificato tramite OCSP (Online Certificate Status Protocol).
- **validation_level**: Livello di validazione del certificato (base, avanzato, ecc.).
- **signature_valid**: Stato della validità della firma.
- **self_signed**: Se il certificato è autofirmato (certificato root).
- **redacted**: Se il certificato è stato redatto.
- **certificates_emitted_up_to**: Numero di certificati emessi fino a questo certificato (solo per `Intermediate` e `Root`).
- **certificates_up_to_root_count**: Numero di certificati intermedi e root fino a questo certificato (solo per `Leaf` e `Intermediate`).
- **has_root_certificate**: Se nella catena dei certificati è presente un certificato root (solo per `Leaf` e `Intermediate`).
- **download_date**: Data di download del certificato.
- **raw**: Dati grezzi del certificato.

**Rimozione delle colonne per tipo di certificato:**
- **LEAF**: La colonna `certificates_emitted_up_to` è rimosso, poiché i certificati leaf non emettono altri certificati.
- **INTERMEDIATE**: Le colonne `ocsp_stapling`, `ocsp_must_stapling`, `signature_valid`, `SAN`, e `domain_matches_san` vengono rimosse, poiché non sono necessarie per la gestione dei certificati intermedi.
- **ROOT**: Le colonne `ocsp_stapling`, `ocsp_must_stapling`, `certificates_up_to_root_count`, `has_root_certificate`, `SAN`, e `domain_matches_san` sono rimosse, poiché non applicabili ai certificati root.

#### 4. **Extensions**
La tabella `Extensions` memorizza le estensioni dei certificati, che includono informazioni aggiuntive come l'uso della chiave, i vincoli di base, la distribuzione delle liste CRL (revoca), e altre informazioni specifiche.

- **extension_id**: Identificatore univoco per ogni estensione.
- **certificate_id**: Riferimento al certificato associato.
- **key_usage**: Uso della chiave specificato nelle estensioni.
- **extended_key_usage**: Uso esteso della chiave.
- **basic_constraints**: Restrizioni sui certificati, come la validità come autorità di certificazione.
- **max_path_length**: Lunghezza massima della catena di certificati.
- **crl_distribution_points**: Punti di distribuzione delle liste CRL.
- **crl_distr_point_is_critical**: Indica se i punti di distribuzione CRL sono critici.

#### 5. **CertificatePolicies**
La tabella `CertificatePolicies` memorizza le politiche del certificato, inclusi i qualificatori della politica, i riferimenti alla CPS (Certificate Policy Statement) e se la politica è critica.

- **policy_id**: Identificatore univoco della politica.
- **extension_id**: Riferimento all'estensione del certificato.
- **policy_identifier**: Identificatore della politica del certificato.
- **cps**: URL del Certficate Policy Statement (CPS).
- **policy_qualifiers**: Ulteriori qualificatori della politica.
- **is_cp_critical**: Indica se la politica è critica.

#### 6. **Errors**
La tabella `Errors` tiene traccia degli errori relativi ai certificati, come ad esempio la mancata validazione o problemi di protocollo (es. OCSP).

- **error_id**: Identificatore univoco dell'errore.
- **domain**: Dominio associato all'errore.
- **status**: Stato dell'errore.
- **protocol**: Protocollo utilizzato (ad esempio OCSP, CRL).
- **error_message**: Descrizione dell'errore.
- **timestamp**: Data e ora dell'errore.

#### 7. **LogsOperators** e **Logs**
Le tabelle `LogsOperators` e `Logs` memorizzano informazioni sugli **operatori** che gestiscono i certificati e i log delle operazioni effettuate.

- **operator_id** (in `Logs`): Riferimento all'operatore.
- **log_id** (in `Logs`): Identificatore univoco del log.
- **description**: Descrizione dell'operazione.
- **temporal_start**, **temporal_end**: Periodo in cui l'operazione è stata registrata.

**Rimozione delle tabelle non utilizzate per tipo di certificato:**
- **INTERMEDIATE** e **ROOT**: Le tabelle `Errors`, `SignedCertificateTimestamps`, `Logs` e `LogsOperators` vengono rimosse, poiché non sono necessarie per il tipo di database relativo ai certificati intermedi e root.

---

### Utilizzo del Database per le 3 Tipologie di Certificati

Il database è strutturato in modo tale da supportare le analisi delle tre tipologie di certificati:
1. **Leaf**: Certificati finali che sono associati a un dominio specifico. Contengono informazioni complete sui soggetti, SAN, validità e firma.
2. **Intermediate**: Certificati intermedi che collegano i certificati leaf ai certificati root. Questi certificati sono utilizzati principalmente per formare la catena di fiducia tra un certificato root e un certificato leaf.
3. **Root**: Certificati di livello superiore che fungono da base per la fiducia in tutta la catena di certificati. I certificati root sono autosigned e non necessitano di ulteriori certificati per essere validi. Sono stati inclusi nell'analisi solo i certificati root che sono stati inviati durante la richiesta TLS, quindi `presenti nella catena`.