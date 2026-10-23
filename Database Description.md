### Database for the analysis of digital certificates (Leaf, Intermediate, Root)

This database schema supports the analysis of the three main types of digital certificates: **Leaf**, **Intermediate** and **Root**. Depending on the database type, some columns and tables are removed to better fit the type of certificate being analysed. The schema is defined in `src/db/schema_db.sql`.

### Main tables

#### 1. **Issuers**
The `Issuers` table stores the details of the certificate **issuers** (certificate authorities, CAs). Each row is an entity that issued a certificate, and its data help to trace the chain of trust.

- **issuer_id**: Unique identifier of the issuer.
- **common_name**: Common name of the issuer.
- **organization**: Name of the issuer's organization.
- **issuer_dn**: Distinguished Name (DN) of the issuer.
- **country, province, locality**: Geographic details of the issuer (country, province, city).
- **organizational_unit**: Organizational unit of the issuer.
- **authority_key_id**: ID of the certificate authority's public key.
- **raw**: Raw data of the issuer's certificate.

#### 2. **Subjects**
The `Subjects` table stores the details of the certificate **subjects**, that is the entities a certificate was issued to. A subject can be a person, an organization or a server.

- **subject_id**: Unique identifier of the subject.
- **common_name**: Common name of the subject.
- **subject_dn**: Distinguished Name (DN) of the subject.
- **subject_key_id**: ID of the subject's public key.
- **subject_alt_name**: Subject alternative name, useful for multi-domain certificates.
- **subject_alt_name_is_critical**: Whether the subject alternative name extension is critical.

#### 3. **Certificates**
The `Certificates` table is the central table, with the details of every digital certificate. They include the validity, the issuer and the subject, as well as the criticality of some extensions.

- **certificate_id**: Unique identifier of the certificate.
- **serial_number**: Serial number of the certificate.
- **leaf_domain**: Domain associated with the certificate (for intermediate and root certificates it is always the domain of the leaf).
- **issuer_id**: Reference to the issuer of the certificate (`Issuers` table).
- **subject_id**: Reference to the subject of the certificate (`Subjects` table).
- **version**: Version of the certificate (for example v3).
- **signature_algorithm**: Algorithm used to sign the certificate.
- **key_algorithm**: Algorithm of the public key.
- **key_length**: Length of the public key.
- **validity_start**: Start date of the certificate's validity.
- **validity_end**: Expiry date of the certificate.
- **validity_length**: Validity period of the certificate in seconds (the `validity.length` field of zgrab2).
- **SAN (Subject Alternative Name)**: List of alternative names (only for certificates that support them).
- **domain_matches_san**: Whether the domain of the certificate matches one of the SANs.
- **authority_info_access_is_critical**: Whether the Authority Information Access extension is critical.
- **authority_info_access**: Where to get additional information about the authority (for example the OCSP URL).
- **ocsp_check**: Result of the certificate check through OCSP (Online Certificate Status Protocol).
- **ocsp_stapling**: Whether the server sent an OCSP response during the TLS handshake (`Leaf` only).
- **ocsp_must_stapling**: Whether the certificate requires OCSP stapling through the TLS Feature extension (`Leaf` only).
- **validation_level**: Validation level of the certificate (DV, OV, EV, ...).
- **signature_valid**: Validity of the signature (for `Leaf` certificates, updated with sslyze by `--leaf_chain_validation`).
- **self_signed**: Whether the certificate is self-signed (root certificate).
- **redacted**: Whether the certificate is redacted.
- **certificates_emitted_up_to**: Number of certificates issued up to this certificate (`Intermediate` and `Root` only).
- **certificates_up_to_root_count**: Number of intermediate and root certificates up to this certificate (`Leaf` and `Intermediate` only).
- **has_root_certificate**: Whether the certificate chain contains a root certificate (`Leaf` and `Intermediate` only).
- **download_date**: Download date of the certificate.
- **raw**: Raw data of the certificate.

**Columns removed for each certificate type:**
- **LEAF**: The `certificates_emitted_up_to` column is removed, since leaf certificates do not issue other certificates.
- **INTERMEDIATE**: The `ocsp_stapling`, `ocsp_must_stapling`, `signature_valid`, `SAN` and `domain_matches_san` columns are removed, since they are not needed for intermediate certificates.
- **ROOT**: The `ocsp_stapling`, `ocsp_must_stapling`, `certificates_up_to_root_count`, `has_root_certificate`, `SAN` and `domain_matches_san` columns are removed, since they do not apply to root certificates.

#### 4. **Extensions**
The `Extensions` table stores the certificate extensions, which include additional information such as the key usage, the basic constraints, the CRL (revocation list) distribution points and other specific information.

- **extension_id**: Unique identifier of each extension.
- **certificate_id**: Reference to the associated certificate.
- **key_usage**: Key usage given in the extensions.
- **key_usage_is_critical**: Whether the key usage extension is critical.
- **extended_key_usage**: Extended key usage.
- **extended_key_usage_is_critical**: Whether the extended key usage extension is critical.
- **basic_constraints**: Constraints on the certificate, such as whether it is valid as a certificate authority.
- **max_path_length**: Maximum length of the certificate chain.
- **crl_distribution_points**: Distribution points of the CRLs.
- **crl_distr_point_is_critical**: Whether the CRL distribution points are critical.
- **crl_revocation_status**: Revocation status through the CRLs. The check is not run: the value is always `No Request Done` (the column is kept for schema compatibility).

#### 5. **CertificatePolicies**
The `CertificatePolicies` table stores the certificate policies, including the policy qualifiers, the references to the CPS (Certification Practice Statement) and whether the policy is critical.

- **policy_id**: Unique identifier of the policy.
- **extension_id**: Reference to the certificate extension.
- **policy_identifier**: Identifier of the certificate policy.
- **cps**: URL of the Certification Practice Statement (CPS).
- **policy_qualifiers**: Additional qualifiers of the policy.
- **is_cp_critical**: Whether the policy is critical.

#### 6. **Errors**
The `Errors` table records the domains whose scan failed, with the error returned by zgrab2 (for example a connection timeout).

- **error_id**: Unique identifier of the error.
- **domain**: Domain associated with the error.
- **status**: Status of the scan (for example `connection-timeout`, `io-timeout`, `unknown-error`).
- **protocol**: Protocol used (`tls`).
- **error_message**: Description of the error.
- **timestamp**: Date and time of the error.
- **download_date**: Date of the scan.

#### 7. **SignedCertificateTimestamps**
The `SignedCertificateTimestamps` table stores the Signed Certificate Timestamps (SCTs) of each certificate.

- **certificate_id**: Reference to the certificate.
- **log_id**: Reference to the Certificate Transparency log that issued the SCT (`id` in the `Logs` table); a log missing from the list is added under the `unknown` operator.
- **timestamp**, **version**, **signature**: Timestamp, version and signature of the SCT.

#### 8. **LogsOperators** and **Logs**
The `LogsOperators` and `Logs` tables store the **operators** of the Certificate Transparency logs and their logs, read from `res/log_list.json`.

- **name**, **email** (in `LogsOperators`): Name and contacts of the operator.
- **operator_id** (in `Logs`): Reference to the operator.
- **log_id** (in `Logs`): Unique identifier of the log.
- **description**: Description of the log.
- **temporal_start**, **temporal_end**: Expiry interval of the certificates accepted by the log (`temporal_interval` in the log list).

**Tables removed for each certificate type:**
- **INTERMEDIATE** and **ROOT**: The `Errors` table is removed, since the connection errors are recorded only in the leaf certificate database.

---

### Using the Database for the 3 Certificate Types

The database is structured to support the analysis of the three certificate types:
1. **Leaf**: End-entity certificates associated with a specific domain. They contain complete information about the subjects, SANs, validity and signature.
2. **Intermediate**: Certificates that link the leaf certificates to the root certificates. They are mainly used to build the chain of trust between a root certificate and a leaf certificate.
3. **Root**: Top-level certificates that are the basis of trust for the whole certificate chain. Root certificates are self-signed and need no other certificate to be valid. Only the root certificates sent during the TLS handshake, that is `present in the chain`, were included in the analysis.
