-- Admin: Anuar Elio Magliari 
-- Politecnico di Torino

BEGIN TRANSACTION;

-- -----------------------------------------------------
-- Table `leaf_certificates_db`.`Issuers`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Issuers`;

CREATE TABLE IF NOT EXISTS Issuers (
    issuer_id INTEGER PRIMARY KEY AUTOINCREMENT,    
    common_name VARCHAR,
    organization VARCHAR,
    issuer_dn TEXT UNIQUE,
    country VARCHAR,
    province VARCHAR, 
    locality VARCHAR,
    organizational_unit VARCHAR,
    authority_key_id VARCHAR,
    authority_info_access_is_critical VARCHAR(12) CHECK (authority_info_access_is_critical IN ('Critical', 'Not Critical', 'Not Found', 'Error')),
    authority_info_access TEXT,
    ocsp_check VARCHAR(36) DEFAULT 'No Request Done' CHECK (ocsp_check IN ('Good', 'Revoked', 'Unknown', 'Impossible Retrieve OCSP Information', 'Not Ok OCSP Response', 'No Issuer Url Found', 'No Request Done'))
);

-- -----------------------------------------------------
-- Table `leaf_certificates_db`.`Subjects`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Subjects`;

CREATE TABLE IF NOT EXISTS Subjects (
    subject_id INTEGER PRIMARY KEY AUTOINCREMENT,    
    common_name VARCHAR,
    subject_dn TEXT UNIQUE,
    subject_key_id VARCHAR,
    subject_alt_name TEXT,
    subject_alt_name_is_critical VARCHAR(12) CHECK (subject_alt_name_is_critical IN ('Critical', 'Not Critical', 'Not Found', 'Error'))
);

-- -----------------------------------------------------
-- Table `leaf_certificates_db`.`Certificates`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Certificates`;

CREATE TABLE IF NOT EXISTS Certificates (
    certificate_id INTEGER PRIMARY KEY AUTOINCREMENT,    
    serial_number VARCHAR UNIQUE,
    domain VARCHAR,
    issuer_id INT,
    subject_id INT,
    version INT,
    signature_algorithm VARCHAR,
    key_algorithm VARCHAR,
    key_length INT,
    validity_start TIMESTAMP,
    validity_end TIMESTAMP,
    validity_length INT,
    ocsp_stapling INT,
    ocsp_must_stapling VARCHAR(9) DEFAULT 'Not Found' CHECK (ocsp_must_stapling IN ('Enabled', 'Not Found', 'Error')),
    validation_level VARCHAR,
    signature_valid BOOLEAN,
    self_signed BOOLEAN,
    redacted BOOLEAN,
    download_date TIMESTAMP,
    raw BLOB,
    FOREIGN KEY (issuer_id) REFERENCES Issuers(issuer_id),
    FOREIGN KEY (subject_id) REFERENCES Subjects(subject_id)
);

-- -----------------------------------------------------
-- Table `leaf_certificates_db`.`Extensions`
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
    crl_distribution_points TEXT[],
    crl_distr_point_is_critical VARCHAR(12) CHECK (crl_distr_point_is_critical IN ('Critical', 'Not Critical', 'Not Found', 'Error')),
    FOREIGN KEY (certificate_id) REFERENCES Certificates(certificate_id)
);

-- -----------------------------------------------------
-- Table `leaf_certificates_db`.`SignedCertificateTimestamps`
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
);

-- -----------------------------------------------------
-- Table `leaf_certificates_db`.`CertificatePolicies`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `CertificatePolicies`;

CREATE TABLE IF NOT EXISTS CertificatePolicies (
    policy_id INTEGER PRIMARY KEY AUTOINCREMENT,
    extension_id INT,
    policy_identifier VARCHAR,
    cps TEXT[],
    policy_qualifiers TEXT,
    is_critical BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (extension_id) REFERENCES Extensions(extension_id)
);

-- -----------------------------------------------------
-- Table `leaf_certificates_db`.`Errors`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `Errors`;

CREATE TABLE Errors (
    error_id INTEGER PRIMARY KEY AUTOINCREMENT,    
    domain VARCHAR UNIQUE,
    status VARCHAR,
    protocol VARCHAR,
    timestamp TIMESTAMP,
    error_message TEXT,
    download_date TIMESTAMP
);

PRAGMA foreign_keys = ON;

COMMIT;