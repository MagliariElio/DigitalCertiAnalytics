-- Admin: Anuar Elio Magliari 
-- Politecnico di Torino

BEGIN TRANSACTION;

-- -----------------------------------------------------
-- Table `certificates_db`.`Issuers`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Issuers`;

CREATE TABLE IF NOT EXISTS Issuers (
    issuer_id INTEGER PRIMARY KEY AUTOINCREMENT,    
    common_name VARCHAR,
    organization VARCHAR,
    issuer_dn TEXT,
    country VARCHAR,
    province VARCHAR, 
    locality VARCHAR,
    organizational_unit VARCHAR,
    authority_key_id VARCHAR,
    raw BLOB DEFAULT NULL
);

-- -----------------------------------------------------
-- Table `certificates_db`.`Subjects`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Subjects`;

CREATE TABLE IF NOT EXISTS Subjects (
    subject_id INTEGER PRIMARY KEY AUTOINCREMENT,    
    common_name VARCHAR,
    subject_dn TEXT,
    subject_key_id VARCHAR,
    subject_alt_name TEXT,
    subject_alt_name_is_critical VARCHAR(12) CHECK (subject_alt_name_is_critical IN ('Critical', 'Not Critical', 'Not Found', 'Error'))
);

-- -----------------------------------------------------
-- Table `certificates_db`.`Certificates`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Certificates`;

CREATE TABLE IF NOT EXISTS Certificates (
    certificate_id INTEGER PRIMARY KEY AUTOINCREMENT,    
    serial_number VARCHAR,
    leaf_domain VARCHAR,
    issuer_id INT,
    subject_id INT,
    version INT,
    signature_algorithm VARCHAR,
    key_algorithm VARCHAR,
    key_length INT,
    validity_start TIMESTAMP,
    validity_end TIMESTAMP,
    validity_length INT,
    SAN TEXT,
    domain_matches_san BOOLEAN DEFAULT FALSE,
    authority_info_access_is_critical VARCHAR(12) CHECK (authority_info_access_is_critical IN ('Critical', 'Not Critical', 'Not Found', 'Error')),
    authority_info_access TEXT,
    ocsp_check VARCHAR(36) DEFAULT 'No Request Done' CHECK (ocsp_check IN ('Good', 'Revoked', 'Unknown', 'Impossible Retrieve OCSP Information', 'Not Ok OCSP Response', 'No Issuer Url Found', 'No OCSP Url Found', 'No Request Done')),
    ocsp_stapling INT,
    ocsp_must_stapling VARCHAR(9) DEFAULT 'Not Found' CHECK (ocsp_must_stapling IN ('Enabled', 'Not Found', 'Error')),
    validation_level VARCHAR,
    signature_valid VARCHAR(20) DEFAULT 'Error' CHECK (signature_valid IN ('Valid', 'Not Valid', 'Error', 'Unsupported Key Type')),
    self_signed BOOLEAN,
    redacted BOOLEAN,
    certificates_emitted_up_to INT DEFAULT 0,
    certificates_up_to_root_count INT DEFAULT 0,
    has_root_certificate BOOLEAN DEFAULT FALSE,
    download_date TIMESTAMP,
    raw BLOB,
    FOREIGN KEY (issuer_id) REFERENCES Issuers(issuer_id),
    FOREIGN KEY (subject_id) REFERENCES Subjects(subject_id)
);

-- -----------------------------------------------------
-- Table `certificates_db`.`Extensions`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Extensions`;

CREATE TABLE IF NOT EXISTS Extensions (
    extension_id INTEGER PRIMARY KEY AUTOINCREMENT,    
    certificate_id INT,
    key_usage JSONB,
    key_usage_is_critical VARCHAR(12) CHECK (key_usage_is_critical IN ('Critical', 'Not Critical', 'Not Found', 'Error')),
    extended_key_usage JSONB,
    extended_key_usage_is_critical VARCHAR(12) CHECK (extended_key_usage_is_critical IN ('Critical', 'Not Critical', 'Not Found', 'Error')),
    basic_constraints JSONB,
    max_path_length INT DEFAULT NULL,
    crl_distribution_points TEXT[],
    crl_distr_point_is_critical VARCHAR(12) CHECK (crl_distr_point_is_critical IN ('Critical', 'Not Critical', 'Not Found', 'Error')),
    FOREIGN KEY (certificate_id) REFERENCES Certificates(certificate_id)
);

-- -----------------------------------------------------
-- Table `certificates_db`.`SignedCertificateTimestamps`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `SignedCertificateTimestamps`;

CREATE TABLE SignedCertificateTimestamps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER NOT NULL, 
    log_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    version INTEGER NOT NULL,        
    signature TEXT NOT NULL,
    FOREIGN KEY (certificate_id) REFERENCES Certificates(certificate_id)
    FOREIGN KEY (log_id) REFERENCES Logs(id)
);

-- -----------------------------------------------------
-- Table `certificates_db`.`CertificatePolicies`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `CertificatePolicies`;

CREATE TABLE IF NOT EXISTS CertificatePolicies (
    policy_id INTEGER PRIMARY KEY AUTOINCREMENT,
    extension_id INT,
    policy_identifier VARCHAR,
    cps TEXT[],
    policy_qualifiers TEXT,
    is_cp_critical BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (extension_id) REFERENCES Extensions(extension_id)
);

-- -----------------------------------------------------
-- Table `certificates_db`.`Errors`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Errors`;

CREATE TABLE Errors (
    error_id INTEGER PRIMARY KEY AUTOINCREMENT,    
    domain VARCHAR,
    status VARCHAR,
    protocol VARCHAR,
    timestamp TIMESTAMP,
    error_message TEXT,
    download_date TIMESTAMP
);

-- -----------------------------------------------------
-- Table `certificates_db`.`LogsOperators`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `LogsOperators`;
CREATE TABLE LogsOperators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) NOT NULL,
    email TEXT
);

-- -----------------------------------------------------
-- Table `certificates_db`.`Logs`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Logs`;
CREATE TABLE Logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id INT NOT NULL,
    description VARCHAR(255) NOT NULL,
    log_id VARCHAR(255) UNIQUE NOT NULL,
    key TEXT NOT NULL,
    url TEXT NOT NULL,
    mmd INT NOT NULL,
    state_usable_timestamp TIMESTAMPTZ,
    state_retired_timestamp TIMESTAMPTZ,
    state_qualified_timestamp TIMESTAMPTZ,
    temporal_start TIMESTAMPTZ NOT NULL,
    temporal_end TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (operator_id) REFERENCES Operators(id)
);


PRAGMA foreign_keys = ON;

COMMIT;