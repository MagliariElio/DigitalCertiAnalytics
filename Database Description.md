### Database for the analysis of digital certificates (Leaf, Intermediate, Root)

This database schema supports the analysis of the three main types of digital certificates: **Leaf**, **Intermediate** and **Root**. Each type has its own SQLite file: `src/analysis/leaf/leaf_certificates.db`, `src/analysis/intermediate/intermediate_certificates.db` and `src/analysis/root/root_certificates.db`. Depending on the type, some columns and tables are left out to better fit the certificates being analysed. The schema is created by `src/db/schema.py` (`ddl(db_type)` returns its exact SQL).

The schema is **version 2**. A scan sees the same certificate many times: in 10 million lines, the same few thousand intermediate certificates appear millions of times, and many leaf certificates are served by several domains. Version 2 therefore stores **each distinct certificate once**, together with the list of its **occurrences** (one per scanned domain and position in the chain), and keeps repeated values (issuers, policies, dates, algorithm names, ...) in small lookup tables. The raw certificates are stored compressed. The results of every analysis are the same as with the first version, and the databases are many times smaller (for 1 million scan lines: leaf 0.7 GB instead of 2.9 GB, intermediate 24 MB instead of 1.8 GB, root 12 MB instead of 0.4 GB).

- **For reading**, the database offers the tables of the first version as **views** with the same names, columns, column order and values: `Certificates`, `Subjects`, `Issuers`, `Extensions`, `CertificatePolicies`, `SignedCertificateTimestamps` and `Errors`. Queries written for the first version keep working on them (see `res/queries.sql`), also in DB Browser for SQLite and the `sqlite3` program, which need no extension.
- **For writing** (`UPDATE`, `DELETE`, `CREATE INDEX`), use the base tables described below: views cannot be updated or indexed.

**Databases of older versions** must be recreated: the program recognises them and stops with the message *"The leaf database '...' was created by an older version of DigitalCertiAnalytics: run the analysis again with --leaf_analysis to recreate it."* (the same for intermediate and root; `reading_zlint_results.py` prints the same message). A database of the current version has `PRAGMA application_id` = `1145258290` (`0x44434132`, "DCA2") and `PRAGMA user_version` = `2`.

---

### The views (the tables of the first version)

In every view, `certificate_id` is the **occurrence id**: the position of the certificate in the scan file, numbered from 1 in file order, the same numbers as in the first version. `subject_id`, `issuer_id`, `extension_id` (and `Extensions.certificate_id`) are equal to it, as in the first version (one subject, issuer and extension row per certificate).

#### 1. **Certificates**
The central view, with one row per certificate occurrence: the validity, the issuer and the subject, as well as the criticality of some extensions.

- **certificate_id**: Unique identifier of the certificate (the occurrence id).
- **serial_number**: Serial number of the certificate.
- **leaf_domain**: Domain associated with the certificate (for intermediate and root certificates it is always the domain of the leaf).
- **issuer_id**: Reference to the issuer of the certificate (`Issuers` view).
- **subject_id**: Reference to the subject of the certificate (`Subjects` view).
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
- **ocsp_check**: Result of the certificate check through OCSP (Online Certificate Status Protocol): one of `No Request Done` (not checked yet), `Good`, `Revoked`, `Unknown`, `Impossible Retrieve OCSP Information`, `Not Ok OCSP Response`, `No Issuer Url Found`, `No OCSP Url Found`.
- **ocsp_stapling**: Whether the server sent an OCSP response during the TLS handshake (`Leaf` only).
- **ocsp_must_stapling**: Whether the certificate requires OCSP stapling through the TLS Feature extension (`Leaf` only).
- **validation_level**: Validation level of the certificate (DV, OV, EV, ...).
- **signature_valid**: Validity of the signature: `Valid`, `Not Valid`, `Error` or `Unsupported Key Type` (for `Leaf` certificates, updated with sslyze by `--leaf_chain_validation`).
- **self_signed**: Whether the certificate is self-signed (root certificate).
- **redacted**: Whether the certificate is redacted.
- **certificates_emitted_up_to**: Number of certificates issued up to this certificate (`Intermediate` and `Root` only).
- **certificates_up_to_root_count**: Number of intermediate and root certificates up to this certificate (`Leaf` and `Intermediate` only).
- **has_root_certificate**: Whether the certificate chain contains a root certificate (`Leaf` and `Intermediate` only).
- **download_date**: Download date of the certificate.
- **raw**: The certificate as stored: usually its DER bytes compressed with zstd (a `BLOB`), see [Raw certificates](#raw-certificates) to read them back.

**Columns removed for each certificate type:**
- **LEAF**: The `certificates_emitted_up_to` column is removed, since leaf certificates do not issue other certificates.
- **INTERMEDIATE**: The `ocsp_stapling`, `ocsp_must_stapling`, `signature_valid`, `SAN` and `domain_matches_san` columns are removed, since they are not needed for intermediate certificates.
- **ROOT**: The `ocsp_stapling`, `ocsp_must_stapling`, `certificates_up_to_root_count`, `has_root_certificate`, `SAN` and `domain_matches_san` columns are removed, since they do not apply to root certificates.

#### 2. **Issuers**
The details of the certificate **issuers** (certificate authorities, CAs), one row per certificate occurrence (`issuer_id` = `certificate_id`), as in the first version.

- **issuer_id**: Identifier of the issuer row (the occurrence id).
- **common_name**: Common name of the issuer.
- **organization**: Name of the issuer's organization.
- **issuer_dn**: Distinguished Name (DN) of the issuer.
- **country, province, locality**: Geographic details of the issuer (country, province, city).
- **organizational_unit**: Organizational unit of the issuer.
- **authority_key_id**: ID of the certificate authority's public key.
- **raw**: The issuer's certificate as stored (see [Raw certificates](#raw-certificates)).

#### 3. **Subjects**
The details of the certificate **subjects**, the entities a certificate was issued to (a person, an organization or a server).

- **subject_id**: Identifier of the subject row (the occurrence id).
- **common_name**: Common name of the subject.
- **subject_dn**: Distinguished Name (DN) of the subject.
- **subject_key_id**: ID of the subject's public key.
- **subject_alt_name**: Subject alternative name, useful for multi-domain certificates.
- **subject_alt_name_is_critical**: Whether the subject alternative name extension is critical.

#### 4. **Extensions**
The certificate extensions: key usage, basic constraints, CRL (revocation list) distribution points and other specific information.

- **extension_id**: Identifier of the extension row (the occurrence id).
- **certificate_id**: Reference to the associated certificate.
- **key_usage**: Key usage given in the extensions.
- **key_usage_is_critical**: Whether the key usage extension is critical.
- **extended_key_usage**: Extended key usage.
- **extended_key_usage_is_critical**: Whether the extended key usage extension is critical.
- **basic_constraints**: Constraints on the certificate, such as whether it is valid as a certificate authority.
- **max_path_length**: Maximum length of the certificate chain.
- **crl_distribution_points**: Distribution points of the CRLs.
- **crl_distr_point_is_critical**: Whether the CRL distribution points are critical.
- **crl_revocation_status**: Revocation status through the CRLs. The check is not run: the value is always `No Request Done` (the column is kept for compatibility).

#### 5. **CertificatePolicies**
The certificate policies, including the policy qualifiers, the references to the CPS (Certification Practice Statement) and whether the policy is critical.

- **policy_id**: Unique identifier of the policy row (see below).
- **extension_id**: Reference to the certificate extension (the occurrence id).
- **policy_identifier**: Identifier of the certificate policy.
- **cps**: URL of the Certification Practice Statement (CPS).
- **policy_qualifiers**: Additional qualifiers of the policy.
- **is_cp_critical**: Whether the policy is critical.

#### 6. **SignedCertificateTimestamps**
The Signed Certificate Timestamps (SCTs) of each certificate.

- **id**: Unique identifier of the SCT row (see below).
- **certificate_id**: Reference to the certificate.
- **log_id**: Reference to the Certificate Transparency log that issued the SCT (`id` in the `Logs` table, as text like in the first version); a log missing from the list is added under the `unknown` operator.
- **timestamp**, **version**, **signature**: Timestamp, version and signature of the SCT.

`CertificatePolicies.policy_id` and `SignedCertificateTimestamps.id` are `occurrence id * 1048576 + position + 1`, where position is the place of the policy or SCT in its certificate (from 0): they are unique and in the same order as in the first version, but they are not consecutive numbers.

#### 7. **Errors** (`Leaf` only)
The domains whose scan failed, with the error returned by zgrab2 (for example a connection timeout).

- **error_id**: Unique identifier of the error (in file order).
- **domain**: Domain associated with the error.
- **status**: Status of the scan (for example `connection-timeout`, `io-timeout`, `unknown-error`).
- **protocol**: Protocol used (`tls`).
- **error_message**: Description of the error.
- **timestamp**: Date and time of the error.
- **download_date**: Date of the scan (the same value as `timestamp`).

#### 8. **LogsOperators** and **Logs** (tables)
The **operators** of the Certificate Transparency logs and their logs, read from `res/log_list.json`. They are ordinary tables, the same as in the first version.

- **name**, **email** (in `LogsOperators`): Name and contacts of the operator.
- **operator_id** (in `Logs`): Reference to the operator.
- **log_id** (in `Logs`): Unique identifier of the log.
- **description**: Description of the log.
- **temporal_start**, **temporal_end**: Expiry interval of the certificates accepted by the log (`temporal_interval` in the log list).

**Views removed for each certificate type:**
- **INTERMEDIATE** and **ROOT**: The `Errors` view (and its `ErrorData` table) is removed, since the connection errors are recorded only in the leaf certificate database.

---

### The base tables (how the data are stored)

| Table | One row per | Main columns |
|---|---|---|
| `Occurrences` | certificate occurrence (scanned domain and position in the chain) | `occurrence_id` (the `certificate_id` of the views), `certificate_id` (-> `CertificateData`), `issuer_id` (-> `IssuerData`), `leaf_domain`, `domain_matches_san`, `ocsp_check` (code), `ocsp_stapling`, `signature_valid` (code), `certificates_emitted_up_to`, `certificates_up_to_root_count`, `has_root_certificate`, `download_date` (-> `NumericValues`); the columns removed for the type are left out, as in the views |
| `CertificateData` | distinct certificate | the certificate columns of the views that do not depend on the occurrence, the subject columns (`subject_common_name`, `subject_dn`, ...) and the extension columns, `raw_id` (-> `RawCertificates`), `policy_set_id` (-> `PolicySets`) |
| `IssuerData` | distinct issuer (the 8 issuer columns and its raw certificate) | `issuer_id`, `common_name`, `organization`, `issuer_dn`, `country`, `province`, `locality`, `organizational_unit`, `authority_key_id`, `raw_id` |
| `RawCertificates` | raw certificate | `raw_id`, `der_zstd` (the DER bytes compressed with zstd) or `raw` (the original value, when it is not a valid base64 certificate) |
| `RawDictionaries` | at most one row | `zstd_dictionary`: the zstd dictionary that compresses every `der_zstd` of the database (trained on the first certificates of the scan) |
| `SctData` | SCT of a distinct certificate | `certificate_id`, `position`, `log_id` (-> `Logs.id`), `timestamp`, `version`, `signature` |
| `PolicyData`, `PolicySets`, `PolicySetMembers` | distinct policy; distinct ordered list of policies; its members | `policy_identifier`, `cps`, `policy_qualifiers`, `is_cp_critical`; `policy_count`; `policy_set_id`, `position`, `policy_id` |
| `TextValues`, `NumericValues` | distinct repeated value | `value_id`, `value`: the algorithm names, criticality flags, key usages, validation levels, download dates, error statuses, ... (columns of type `INTEGER` in `CertificateData`, `Occurrences` and `ErrorData` that refer to them) |
| `OcspStatuses`, `SignatureValidities` | fixed code (filled when the database is created) | `code`, `name`: the values of `ocsp_check` and `signature_valid` listed above |
| `ErrorData` (`Leaf` only) | error line of the scan | `error_id`, `domain`, `status`, `protocol` (-> `TextValues`), `timestamp` (-> `NumericValues`), `error_message` |
| `SchemaInfo` | setting | `schema_version` (2), `database_type`, `raw_dictionary_id` |

The views join these tables back: for example `Certificates` is `Occurrences` joined with `CertificateData`, the lookups, the codes and `RawCertificates`. Every value keeps the type it had in the first version (the lookup tables have the same column affinity as the columns they replace), so comparisons and sorting give the same results.

A query that only counts or groups is faster on the base tables, because a view always joins all its lookups. To change values, update the base tables: for example the OCSP result of every occurrence of a certificate is `UPDATE Occurrences SET ocsp_check = (SELECT code FROM OcspStatuses WHERE name = 'Good') WHERE certificate_id = ...`. The only indexes are the primary keys and the `UNIQUE` lookups: create others on the base tables if your own queries need them (examples in `res/queries.sql`).

#### Raw certificates
A raw certificate whose value is a valid base64 DER certificate (almost all of them) is stored as `der_zstd`, its DER bytes compressed with zstd and the dictionary of `RawDictionaries`; any other value (empty, wrapped or invalid text) is kept unchanged in `raw`. The `raw` column of the views shows the stored value. To get the original base64 text back:

- in Python, with the project's modules (`src/` on the path): `RawCodec.for_connection(conn).decode(der_zstd, raw)` from `db.raw_codec` returns the original value, and `.der(der_zstd, raw)` the DER bytes; `register_sql_functions(conn)` adds the SQL function `dca_raw(der_zstd, raw)`, so that `SELECT dca_raw(der_zstd, raw) FROM RawCertificates` works on that connection;
- with the `zstd` command: save the dictionary (`SELECT writefile('raw.dict', zstd_dictionary) FROM RawDictionaries` in the `sqlite3` program) and a certificate (`SELECT writefile('cert.zst', der_zstd) FROM RawCertificates WHERE raw_id = 1`), then `zstd -d -D raw.dict cert.zst -o cert.der` and `openssl x509 -inform der -in cert.der -noout -text`. For a very small scan `RawDictionaries` is empty (no dictionary was trained): then leave out `-D raw.dict`.

---

### ZLint results (tables in the same database)

`--leaf_zlint_check` and `--intermediate_zlint_check` store the ZLint results in the database of the certificate type (there is no separate database server). The tables are created by the first ZLint check and replaced by the next one. Each distinct certificate is linted once, and its result applies to all its occurrences.

| Table or view | Content |
|---|---|
| `ZlintResults` | one row per linted raw certificate: `raw_id` (-> `RawCertificates`; 0 for certificates without a raw value), `body_id` (-> `ZlintBodies`) or, when ZLint failed, `error_message` and `error_timestamp` |
| `ZlintBodies` | each distinct ZLint output once: `body_id`, `sha256` of the JSON text, `body_zstd` (the compact JSON output of ZLint, compressed with zstd and the dictionary of `ZlintDictionaries`) |
| `ZlintDictionaries` | the zstd dictionary of the bodies (the first body of the run) |
| `ZlintIssuers` | the issuer common name, organization and DN of every issuer row when ZLint ran |
| `ZlintRun` | `zlint_version`, `started`, `units` (number of linted certificates), `state` (`running`, `finished`, `interrupted` or `failed`) and `ended` |
| `ZlintDocuments` (view) | one row per certificate occurrence that was linted: `certificate_id` (occurrence id), `leaf_domain`, `issuer_common_name`, `issuer_organization`, `issuer_dn`, `body_id`, `error_message`, `error_timestamp` |

`src/analysis/zlint_analysis/reading_zlint_results.py [leaf|intermediate|root] [--db PATH]` summarises them into three CSV files; in Python, `ZlintReader(conn).body(body_id)` from `db.zlint_store` returns the ZLint output of a body as parsed JSON.

---

### Using the Database for the 3 Certificate Types

The database is structured to support the analysis of the three certificate types:
1. **Leaf**: End-entity certificates associated with a specific domain. They contain complete information about the subjects, SANs, validity and signature.
2. **Intermediate**: Certificates that link the leaf certificates to the root certificates. They are mainly used to build the chain of trust between a root certificate and a leaf certificate.
3. **Root**: Top-level certificates that are the basis of trust for the whole certificate chain. Root certificates are self-signed and need no other certificate to be valid. Only the root certificates sent during the TLS handshake, that is `present in the chain`, were included in the analysis.
