### 1. **Crittografia e chiave**
   - **`e_rsa_mod_less_than_2048_bits`**: Verifica se la dimensione della chiave RSA è inferiore a 2048 bit, requisito critico di sicurezza.
   - **`e_dsa_improper_modulus_or_divisor_size`**: Controlla che le dimensioni del modulo DSA siano corrette.
   - **`e_key_usage_and_extended_key_usage_inconsistent`**: Indica incoerenze tra uso chiave e uso esteso della chiave.

### 2. **Politiche e vincoli di certificati**
   - **`e_cert_policy_explicit_text_ia5_string`**: Verifica problemi con il formato del testo esplicito nelle politiche.
   - **`e_sub_cert_certificate_policies_missing`**: Indica l’assenza di politiche certificate nei certificati subordinati.
   - **`e_ext_cert_policy_disallowed_any_policy_qualifier`**: Controlla che non siano presenti qualificatori di politica non consentiti.
   - **`e_invalid_ca_certificate_policies`**: Identifica problemi nelle politiche del certificato CA.

### 3. **Estensioni critiche e CRL**
   - **`e_ext_crl_distribution_marked_critical`**: Verifica se la distribuzione CRL è contrassegnata come critica.
   - **`e_ext_key_usage_cert_sign_without_ca`**: Controlla l’uso della chiave di certificazione senza una CA, potenzialmente problematico.

### 4. **Validità e conformità del certificato**
   - **`e_cert_sig_alg_not_match_tbs_sig_alg`**: Verifica la coerenza dell’algoritmo di firma.
   - **`e_invalid_certificate_version`**: Controlla se la versione del certificato è supportata.
   - **`e_validity_time_not_positive`**: Indica se il periodo di validità del certificato non è positivo.
   - **`e_tls_server_cert_valid_time_longer_than_397_days`**: Verifica che la validità del certificato non superi 397 giorni per ridurre rischi di sicurezza.

### 5. **Problemi con il Subject o Common Name (CN)**
   - **`e_subject_common_name_max_length`**: Verifica se il Common Name supera la lunghezza massima consentita.
   - **`e_subject_country_not_iso`**: Controlla che il codice del paese sia conforme agli standard ISO.

### 6. **Attacchi e vulnerabilità**
   - **`e_rsa_exp_negative`**: Indica un problema potenziale con l'esponente RSA.
   - **`e_incorrect_ku_encoding`**: Verifica codifica errata dell’uso della chiave.

### 7. **DNS e SAN (Subject Alternative Name)**
   - **`e_dnsname_bad_character_in_label`**: Indica caratteri non validi nei nomi di dominio.
   - **`e_dnsname_wildcard_only_in_left_label`**: Verifica l’uso corretto del carattere jolly (*) nei DNS.
   - **`e_ext_san_contains_reserved_ip`**: Controlla se l’IP nel SAN è riservato.
   - **`e_ext_san_dns_not_ia5_string`**: Verifica che il DNS nel SAN sia una stringa IA5 valida.

### 8. **Configurazioni aggiuntive e politiche di sicurezza**
   - **`e_ev_business_category_missing`**: Controlla la presenza di una categoria aziendale nei certificati EV.
   - **`e_ext_name_constraints_not_in_ca`**: Verifica che i vincoli sui nomi non siano presenti nella CA.

### **Stato dei test**
   - **Pass**: Il test è superato; il certificato è conforme alla specifica.
   - **NE (Non conforme)**: Il certificato non soddisfa il requisito.
   - **NA (Non applicabile)**: Il test non è applicabile al tipo o alla configurazione del certificato.
   - **Info**: Nota informativa che può essere non critica ma rilevante. 

### **Totale dei campi disponibili per l'analisi**: 361