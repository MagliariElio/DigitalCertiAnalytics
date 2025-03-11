SELECT COUNT(*) FROM Certificates;

SELECT COUNT(DISTINCT leaf_domain) FROM Certificates;

SELECT COUNT(DISTINCT(s.subject_key_id)) 
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id;

SELECT COUNT(*) FROM Errors;

SELECT COUNT(DISTINCT(s.subject_key_id)) 
FROM Certificates AS c INNER JOIN Extensions AS e ON c.certificate_id = e.certificate_id INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE key_usage IS NOT NULL;

SELECT 
    CASE 
        WHEN authority_info_access = '{}' AND json_array_length(crl_distribution_points) = 0 THEN 'Without Crl Distr. Point and OCSP Uri'
        WHEN (authority_info_access LIKE '%ocsp_urls%' OR authority_info_access LIKE '%issuer_urls%') AND json_array_length(crl_distribution_points) > 0 THEN 'Crl Distr. Point and OCSP Uri'
        WHEN (authority_info_access LIKE '%ocsp_urls%' OR authority_info_access LIKE '%issuer_urls%') AND json_array_length(crl_distribution_points) = 0 THEN 'OCSP Uri Only'
        WHEN json_array_length(crl_distribution_points) > 0 AND authority_info_access = '{}' THEN 'Crl Distr. Point Only'
        ELSE 'Other'
    END AS aia_category,
    COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c JOIN Extensions AS e ON c.certificate_id = e.certificate_id INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY aia_category;

SELECT c.certificate_id, c.leaf_domain
FROM Certificates AS c LEFT JOIN SignedCertificateTimestamps AS s ON c.certificate_id = s.certificate_id
WHERE s.certificate_id IS NULL;

SELECT ocsp_check, COUNT(DISTINCT(subject_dn)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY ocsp_check;

SELECT COUNT(*) AS count, ocsp_check, authority_info_access
FROM Certificates
WHERE ocsp_check = 'No Request Done' AND (authority_info_access LIKE '{}' OR NOT authority_info_access LIKE '%ocsp_urls%')
GROUP BY ocsp_check;

SELECT COUNT(*) AS count
FROM Certificates
WHERE (authority_info_access LIKE '{}' OR NOT authority_info_access LIKE '%ocsp_urls%')

SELECT COUNT(*) AS count, *
FROM Certificates AS c INNER JOIN Issuers AS i ON c.issuer_id = i.issuer_id
WHERE (NOT c.authority_info_access LIKE '{}' AND NOT c.authority_info_access LIKE '%issuer_urls%' AND i.raw IS NULL)

UPDATE Certificates
SET ocsp_check = 'No Issuer Url Found'
WHERE NOT authority_info_access LIKE '{}' 
  AND NOT authority_info_access LIKE '%issuer_urls%' 
  AND issuer_id IN (
      SELECT issuer_id
      FROM Issuers
      WHERE raw IS NULL
  );

SELECT COUNT(*) AS count
FROM Certificates
WHERE NOT (authority_info_access LIKE '{}' OR NOT authority_info_access LIKE '%ocsp_urls%')

SELECT COUNT(*) AS count, ocsp_check, authority_info_access
FROM Certificates
WHERE (authority_info_access LIKE '{}' OR NOT authority_info_access LIKE '%ocsp_urls%')
GROUP BY ocsp_check, authority_info_access;

UPDATE Certificates
SET ocsp_check = 'No Request Done';

SELECT SAN, domain_matches_san, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY domain_matches_san
ORDER BY count;

SELECT SAN, domain_matches_san, LENGTH(SAN) AS count_san, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY count_san, domain_matches_san
ORDER BY count_san, domain_matches_san;

SELECT e.crl_distr_point_is_critical, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS c INNER JOIN Extensions AS e ON c.certificate_id = e.certificate_id INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY e.crl_distr_point_is_critical
ORDER BY count DESC;

SELECT ocsp_stapling, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY ocsp_stapling
ORDER BY count;

SELECT ocsp_must_stapling, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY ocsp_must_stapling
ORDER BY count;

SELECT
    SUBSTR(
        subject_dn,
        INSTR(subject_dn, 'O=') + 2,
        INSTR(SUBSTR(subject_dn, INSTR(subject_dn, 'O=') + 2), ',') - 1
    ) AS organization,
	(COUNT(*) * 100.0 / 9428980) AS percentage,
	COUNT(*) AS certificate_count
FROM
    Subjects
WHERE
    subject_dn LIKE '%O=%'
GROUP BY
    organization
ORDER BY
    certificate_count DESC;

SELECT COUNT(*) AS count
FROM Issuers;

SELECT COUNT(*) AS count
FROM Subjects
WHERE subject_key_id IS NULL OR subject_key_id = '';

SELECT COUNT(*) AS count
FROM Subjects
WHERE subject_key_id IS NOT NULL AND subject_key_id <> '';

SELECT COUNT(DISTINCT(serial_number)) AS count
FROM Subjects AS s INNER JOIN Certificates AS c ON s.subject_id = c.subject_id
WHERE subject_key_id IS NULL OR subject_key_id = '';

SELECT COUNT(DISTINCT(serial_number)) AS count
FROM Subjects AS s INNER JOIN Certificates AS c ON s.subject_id = c.subject_id;

SELECT COUNT(DISTINCT(serial_number)) AS count
FROM Issuers AS i INNER JOIN Certificates AS c ON i.issuer_id = c.issuer_id
WHERE authority_key_id IS NULL OR authority_key_id = '';

SELECT COUNT(DISTINCT(serial_number)) AS count
FROM Issuers AS i INNER JOIN Certificates AS c ON i.issuer_id = c.issuer_id
WHERE authority_key_id IS NOT NULL AND authority_key_id <> '';

SELECT COUNT(DISTINCT(subject_key_id)) AS count
FROM Subjects AS s INNER JOIN Certificates AS c ON s.subject_id = c.subject_id 
LEFT JOIN Extensions AS e ON c.certificate_id = e.certificate_id
WHERE extended_key_usage IS NOT NULL OR extended_key_usage <> '';

-- Conta quanti certificati hanno l'estensione e se è non critical o meno
SELECT 
    COALESCE(crl_distr_point_is_critical, 'No Extension') AS crl_distr_point_is_critical, 
    COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c
LEFT JOIN Extensions AS e ON c.certificate_id = e.certificate_id
INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY crl_distr_point_is_critical







-- Conta il numero di certificati con serial number duplicato
SELECT serial_number, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY serial_number
HAVING count > 1
ORDER BY count DESC;

-- Conta il numero di certificati con serial number negativo
SELECT serial_number, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY serial_number
ORDER BY serial_number;

-- Conta il numero di certificati che hanno un serial number positivo con più di 20 byte
SELECT COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE serial_number >= 0 AND (LENGTH(printf('%X', serial_number)) / 2) > 20
GROUP BY serial_number
ORDER BY count DESC;

-- Conta il numero di certificati con il serial number
SELECT COUNT(DISTINCT(serial_number))
FROM Certificates

-- Distribuzione del numero di certificati intermedi nella catena
SELECT certificates_up_to_root_count, COUNT(DISTINCT(subject_dn)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY certificates_up_to_root_count
ORDER BY count DESC;

-- Distribuzione delle Signature Algorithm tra i certificati 
SELECT signature_algorithm, COUNT(DISTINCT(subject_dn)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY signature_algorithm;

-- Conta il numero di policy comuni tra tutti i certificati univoci
SELECT policy_identifier, validation_level, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS cc INNER JOIN Subjects AS s ON cc.subject_id = s.subject_id
LEFT JOIN Extensions AS e ON cc.certificate_id = e.certificate_id 
LEFT JOIN CertificatePolicies AS c ON c.extension_id = e.extension_id
GROUP BY policy_identifier, validation_level
ORDER BY count DESC;

-- Conta il numero di certificati con almeno una policy
SELECT COUNT(DISTINCT s.subject_key_id) AS certificates_with_policy
FROM Certificates AS cc INNER JOIN Subjects AS s ON cc.subject_id = s.subject_id
LEFT JOIN Extensions AS e ON cc.certificate_id = e.certificate_id
LEFT JOIN CertificatePolicies AS c ON c.extension_id = e.extension_id
WHERE c.policy_identifier IS NOT NULL;

-- Conta il numero di policy identifier per ogni tipologia di validation come richiesto dal CA/B Forum
WITH CertificatePoliciesData AS (
    SELECT 
        cc.certificate_id, 
        s.subject_key_id,
        c.policy_identifier,
        cc.validation_level
    FROM Certificates AS cc INNER JOIN Subjects AS s ON cc.subject_id = s.subject_id
    LEFT JOIN Extensions AS e ON cc.certificate_id = e.certificate_id
    LEFT JOIN CertificatePolicies AS c ON c.extension_id = e.extension_id
),
PolicyCounts AS (
    SELECT 
        subject_key_id,
        validation_level,
        MAX(CASE WHEN policy_identifier = '2.23.140.1.2.1' THEN 1 ELSE 0 END) AS has_policy_2_23_140_1_2_1,  -- DV
        MAX(CASE WHEN policy_identifier = '2.23.140.1.2.2' THEN 1 ELSE 0 END) AS has_policy_2_23_140_1_2_2,  -- OV
        MAX(CASE WHEN policy_identifier = '2.23.140.1.1' THEN 1 ELSE 0 END) AS has_policy_2_23_140_1_1,  -- EV
		
        MAX(CASE WHEN policy_identifier != '2.23.140.1.2.1' AND policy_identifier IS NOT NULL THEN 1 ELSE 0 END) AS has_other_policy_dv,
		MAX(CASE WHEN policy_identifier != '2.23.140.1.2.2' AND policy_identifier IS NOT NULL THEN 1 ELSE 0 END) AS has_other_policy_ov,
		MAX(CASE WHEN policy_identifier != '2.23.140.1.1' AND policy_identifier IS NOT NULL THEN 1 ELSE 0 END) AS has_other_policy_ev,
		
        COUNT(DISTINCT CASE WHEN policy_identifier IS NULL THEN subject_key_id END) AS count_without_any_policy
    FROM CertificatePoliciesData AS cpd
    GROUP BY subject_key_id, validation_level
)
SELECT 
    validation_level,
    
    -- Contare i certificati con solo la policy associata al livello di validazione (DV, OV, EV)
    COUNT(DISTINCT CASE 
        WHEN validation_level = 'DV' AND has_policy_2_23_140_1_2_1 = 1 AND has_other_policy_dv = 0 THEN subject_key_id 
        WHEN validation_level = 'OV' AND has_policy_2_23_140_1_2_2 = 1 AND has_other_policy_ov = 0 THEN subject_key_id 
        WHEN validation_level = 'EV' AND has_policy_2_23_140_1_1 = 1 AND has_other_policy_ev = 0 THEN subject_key_id 
        END) AS count_with_only_own_policy,
    
	-- Contare i certificati con own policy_identifier e altri policy_identifier
    COUNT(DISTINCT CASE  
		WHEN validation_level = 'DV' AND has_policy_2_23_140_1_2_1 = 1 THEN subject_key_id 
        WHEN validation_level = 'OV' AND has_policy_2_23_140_1_2_2 = 1 THEN subject_key_id 
        WHEN validation_level = 'EV' AND has_policy_2_23_140_1_1 = 1 THEN subject_key_id 
		END) AS count_with_other_policy,

    -- Contare i certificati senza own policy_identifier ma con altre policy
    COUNT(DISTINCT CASE 
		WHEN validation_level = 'DV' AND has_policy_2_23_140_1_2_1 = 0 AND has_other_policy_dv = 1 THEN subject_key_id 
        WHEN validation_level = 'OV' AND has_policy_2_23_140_1_2_2 = 0 AND has_other_policy_ov = 1 THEN subject_key_id 
        WHEN validation_level = 'EV' AND has_policy_2_23_140_1_1 = 0 AND has_other_policy_ev = 1 THEN subject_key_id 
		END) AS count_without_own_policy,
    	
	-- Contare i certificati senza alcuna policy
    COUNT(DISTINCT CASE 
        WHEN count_without_any_policy > 0 THEN subject_key_id 
        END) AS count_without_any_policy
FROM PolicyCounts
GROUP BY validation_level;

-- Conta il numero di issuer con una determinata lunghezza AKI
SELECT LENGTH(DISTINCT authority_key_id) AS key_length, COUNT(DISTINCT issuer_key_id) AS key_count
FROM Issuers
GROUP BY key_length
ORDER BY key_length;

-- Conta il numero di subjects con una determinata lunghezza SKI
SELECT LENGTH(DISTINCT subject_key_id) AS key_length, COUNT(DISTINCT subject_dn) AS key_count
FROM Subjects
GROUP BY key_length
ORDER BY key_length;

-- Controsenso tra max_path_length pari a 0 e la presenza di certificati intermedi emessi dal certificato nella catena (CONTROLLARE, SI PUÒ FARE UN GRAFICO).
SELECT c.certificate_id, e.max_path_length, c.certificates_emitted_up_to, c.has_root_certificate, e.basic_constraints
FROM Certificates AS c INNER JOIN Extensions AS e ON c.certificate_id = e.certificate_id
WHERE max_path_length = 0 AND c.certificates_emitted_up_to > 0;

-- Indici per la tabella Certificates
CREATE INDEX IF NOT EXISTS idx_certificates_issuer_id ON Certificates(issuer_id);
CREATE INDEX IF NOT EXISTS idx_certificates_subject_id ON Certificates(subject_id);
CREATE INDEX IF NOT EXISTS idx_certificates_version ON Certificates(version);
CREATE INDEX IF NOT EXISTS idx_certificates_validity_end ON Certificates(validity_end);
CREATE INDEX IF NOT EXISTS idx_certificates_ocsp_check ON Certificates(ocsp_check);
CREATE INDEX IF NOT EXISTS idx_certificates_signature_valid ON Certificates(signature_valid);
CREATE INDEX IF NOT EXISTS idx_certificates_self_signed ON Certificates(self_signed);

-- Indici per la tabella Issuers
CREATE INDEX IF NOT EXISTS idx_issuers_common_name ON Issuers(common_name);
CREATE INDEX IF NOT EXISTS idx_issuers_organization ON Issuers(organization);

-- Indici per la tabella Subjects
CREATE INDEX IF NOT EXISTS idx_subjects_subject_dn ON Subjects(subject_dn);
CREATE INDEX IF NOT EXISTS idx_subjects_common_name ON Subjects(common_name);

-- Indici per la tabella Extensions
CREATE INDEX IF NOT EXISTS idx_extensions_certificate_id ON Extensions(certificate_id);
CREATE INDEX IF NOT EXISTS idx_extensions_key_usage ON Extensions(key_usage);
CREATE INDEX IF NOT EXISTS idx_extensions_extended_key_usage ON Extensions(extended_key_usage);

-- Indici per la tabella SignedCertificateTimestamps
CREATE INDEX IF NOT EXISTS idx_signed_cert_timestamps_certificate_id ON SignedCertificateTimestamps(certificate_id);
CREATE INDEX IF NOT EXISTS idx_signed_cert_timestamps_log_id ON SignedCertificateTimestamps(log_id);

-- Indici per la tabella Errors
CREATE INDEX IF NOT EXISTS idx_errors_domain ON Errors(domain);
CREATE INDEX IF NOT EXISTS idx_errors_status ON Errors(status);

-- Indici per la tabella Logs
CREATE INDEX IF NOT EXISTS idx_logs_operator_id ON Logs(operator_id);
CREATE INDEX IF NOT EXISTS idx_logs_log_id ON Logs(log_id);







--------------

-- Check OCSP Status for certificates
SELECT c.certificate_id, c.authority_info_access, i.common_name, i.raw AS issuer_cert_raw, c.raw AS leaf_cert_raw
FROM certificates AS c 
INNER JOIN Issuers AS i ON c.issuer_id = i.issuer_id
WHERE c.ocsp_check = 'No Request Done'
LIMIT 1000

--------------
-- Query per il plot dei risultati

-- Conta quanti Issuer hanno emesso un certificato
WITH IssuersCounts AS (
	SELECT Issuers.organization, COUNT(*) AS certificate_count
	FROM Certificates 
	INNER JOIN Issuers ON Certificates.issuer_id = Issuers.issuer_id 
	WHERE Issuers.organization IS NOT NULL AND TRIM(Issuers.organization) <> ''
	GROUP BY Issuers.organization
	ORDER BY certificate_count DESC
),
TopIssuers AS (
	SELECT organization, certificate_count
	FROM IssuersCounts
	LIMIT 20
),
Others AS (
	SELECT 'Others' AS organization, SUM(certificate_count) AS certificate_count
	FROM IssuersCounts 
	WHERE organization NOT IN (SELECT organization FROM TopIssuers)
)
SELECT * FROM TopIssuers
UNION ALL
SELECT * FROM Others;

-- Rinonima DigiCert
UPDATE Issuers
SET organization = 'DigiCert Inc'
WHERE organization = 'DigiCert, Inc.';

-- Numero di certificati emessi in diversi paesi
WITH IssuersCounts AS (
	SELECT Issuers.country, COUNT(*) AS country_count
	FROM Issuers
	WHERE TRIM(Issuers.country) <> '' AND TRIM(Issuers.country) <> '--'
	GROUP BY Issuers.country
	ORDER BY country_count DESC
),
TopCountry AS (
	SELECT country, country_count
	FROM IssuersCounts
	LIMIT 5
),
Others AS (
	SELECT 'Others' AS country, COALESCE(SUM(country_count), 0) AS country_count
	FROM IssuersCounts 
	WHERE country NOT IN (SELECT country FROM TopCountry)
)
SELECT * FROM TopCountry
UNION ALL
SELECT * FROM Others;

-- Mostra la distribuzione della durata di validità rispetto a 365 giorni
SELECT validity_length/31536000, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE validity_length < 0
UNION ALL
SELECT validity_length/31536000, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE c.validity_length IS NOT NULL AND validity_length >= 0
GROUP BY validity_length/31536000
HAVING count >= 0;

-- Conta il numero di certificati che hanno un periodo maggiore di 398 giorni dopo il 2 settembre 2020
SELECT validity_length/34387200, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE c.validity_length IS NOT NULL AND validity_length >= 0 AND validity_start > '2020-09-01T00:00:00Z'
GROUP BY validity_length/34387200;

-- Conta il numero di certificati che hanno un periodo maggiore di 39 mesi dopo il 1 aprile 2015 e prima del 2 settembre 2020
SELECT validity_length/101088000, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE c.validity_length IS NOT NULL AND validity_length >= 0 AND validity_start >= '2015-04-01T00:00:00Z' AND validity_start <= '2020-09-01T00:00:00Z'
GROUP BY validity_length/101088000;

-- Trend di Scadenza dei Certificati
SELECT strftime('%Y-%m', validity_end) AS month, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE validity_end IS NOT NULL
GROUP BY month
HAVING count > 0
ORDER BY month ASC;

-- Algoritmi di Firma Utilizzati
SELECT signature_algorithm, COUNT(DISTINCT(subject_key_id)) AS sign_algorithm_count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE signature_algorithm IS NOT NULL
GROUP BY signature_algorithm
ORDER BY sign_algorithm_count DESC;

-- Distribuzione degli Algoritmi di Chiave e Lunghezza
SELECT 
    key_algorithm, 
    key_length, 
    COUNT(DISTINCT(subject_key_id)) AS certificate_count
FROM 
    Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE 
    key_algorithm IS NOT NULL AND key_algorithm <> '' AND
    key_length IS NOT NULL AND key_length <> ''
GROUP BY 
    key_algorithm, 
    key_length
ORDER BY 
    key_algorithm, 
    key_length;
	
-- Stato OCSP dei Certificati
SELECT ocsp_check, COUNT(*) AS count
FROM Certificates
GROUP BY ocsp_check;

-- Estensioni Critiche vs Non Critiche dell'AIA
SELECT authority_info_access_is_critical, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY authority_info_access_is_critical
ORDER BY count DESC;

-- Certificati Auto-Firmati vs CA-Firmati
SELECT 
	CASE 
        WHEN self_signed = 1 THEN 'True' 
        ELSE 'False' 
    END AS is_self_signed,
    COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY self_signed;

-- Livelli di Validazione dei Certificati
SELECT validation_level, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY validation_level;

-- Distribuzione delle Versioni dei Certificati
SELECT version, COUNT(*) AS count
FROM Certificates
GROUP BY version;

-- Validità delle Firme dei Certificati
SELECT signature_valid AS is_valid_signature, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY signature_valid
ORDER BY count DESC;

-- Analisi Status Certificati
SELECT 'success', COUNT(*) AS count
FROM Certificates
UNION ALL
SELECT status, COUNT(*) AS count
FROM Errors
GROUP BY status;

-- Utilizzo del Key Usage nelle Estensioni con key algorithm (leaf)
SELECT e.key_usage, c.key_algorithm, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Extensions AS e JOIN Certificates AS c ON e.certificate_id = c.certificate_id 
JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY e.key_usage, c.key_algorithm
ORDER BY count DESC;

-- Utilizzo del Key Usage nelle Estensioni
SELECT e.key_usage, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Extensions AS e JOIN Certificates AS c ON e.certificate_id = c.certificate_id 
JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY e.key_usage
ORDER BY count DESC;

-- SELECT e.key_usage, COUNT(DISTINCT(s.subject_dn)) AS count
-- FROM Extensions AS e INNER JOIN Subjects AS s ON e.certificate_id = s.subject_id
-- GROUP BY e.key_usage
-- ORDER BY count DESC;

-- Estensioni Critiche vs Non Critiche del Key Usage nelle Estensioni
SELECT key_usage_is_critical, COUNT(DISTINCT(subject_key_id)) AS count
FROM Extensions AS e JOIN Certificates AS c ON e.certificate_id = c.certificate_id
JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY key_usage_is_critical
ORDER BY count DESC;

-- SELECT e.key_usage_is_critical, COUNT(DISTINCT(s.subject_dn)) AS count
-- FROM Extensions AS e INNER JOIN Subjects AS s ON e.certificate_id = s.subject_id
-- GROUP BY e.key_usage_is_critical
-- ORDER BY count DESC;

-- Utilizzo dell'Extended Key Usage nelle Estensioni
SELECT e.extended_key_usage, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id 
LEFT JOIN Extensions AS e ON e.certificate_id = c.certificate_id 
GROUP BY e.extended_key_usage
ORDER BY count DESC;

-- Numero di record che non hanno una EKU
SELECT COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS c 
INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
LEFT JOIN Extensions AS e ON e.certificate_id = c.certificate_id
WHERE e.certificate_id IS NULL;

-- SELECT e.extended_key_usage, COUNT(DISTINCT(s.subject_dn)) AS count
-- FROM Extensions AS e JOIN Subjects AS s ON e.certificate_id = s.subject_id 
-- GROUP BY e.extended_key_usage
-- ORDER BY count DESC;

-- Estensioni Critiche vs Non Critiche dell'Extended Key Usage nelle Estensioni
SELECT e.extended_key_usage_is_critical, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Extensions AS e JOIN Certificates AS c ON e.certificate_id = c.certificate_id 
JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY e.extended_key_usage_is_critical
ORDER BY count DESC;

-- SELECT e.extended_key_usage_is_critical, COUNT(DISTINCT(s.subject_dn)) AS count
-- FROM Extensions AS e JOIN Subjects AS s ON e.certificate_id = s.subject_id 
-- GROUP BY e.extended_key_usage_is_critical
-- ORDER BY count DESC;

-- Distribuzione del Basic Costraints nelle Estensioni
SELECT e.basic_constraints, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Extensions AS e JOIN Certificates AS c ON e.certificate_id = c.certificate_id
JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY e.basic_constraints
ORDER BY count DESC;

-- SELECT e.basic_constraints, COUNT(DISTINCT(s.subject_dn)) AS count
-- FROM Extensions AS e JOIN Subjects AS s ON e.certificate_id = s.subject_id
-- GROUP BY e.basic_constraints
-- ORDER BY count DESC;

-- Estensioni Critiche vs Non Critiche del CRL distribution nelle Estensioni
SELECT crl_distr_point_is_critical, COUNT(*) AS count
FROM Extensions
GROUP BY crl_distr_point_is_critical
ORDER BY count DESC;

-- Trend dei Signed Certificate Timestamps (SCT) per Mese e Anno
SELECT 
    strftime('%Y-%m', datetime(timestamp, 'unixepoch')) AS month_year, 
    COUNT(*) AS count
FROM SignedCertificateTimestamps
GROUP BY month_year
HAVING count > 10
ORDER BY month_year ASC;

-- Numero dei Signed Certificate Timestamps (SCT) per Certificato
SELECT count_sct, COUNT(*) AS certificate_count
FROM (
	SELECT COUNT(s.certificate_id) AS count_sct
	FROM Certificates AS c LEFT JOIN SignedCertificateTimestamps s
	ON s.certificate_id = c.certificate_id 
	GROUP BY c.certificate_id) AS sct_counts
GROUP BY count_sct
ORDER BY count_sct ASC;

-- SELECT average_count_sct, COUNT(*) AS certificate_count
-- FROM (
--	SELECT CAST(AVG(count_sct) AS INT) AS average_count_sct
--	FROM (
--		SELECT c.certificate_id, COUNT(c.certificate_id) AS count_sct
--		FROM Certificates AS c LEFT JOIN SignedCertificateTimestamps s ON s.certificate_id = c.certificate_id
--		GROUP BY c.certificate_id
--	) AS counts INNER JOIN Subjects AS su ON counts.certificate_id = su.subject_id
--	GROUP BY subject_dn
-- ) AS sct_counts
-- GROUP BY average_count_sct
-- ORDER BY average_count_sct ASC;

-- Top SCT Logs
SELECT l.description, COUNT(DISTINCT(subject_dn)) AS count
FROM SignedCertificateTimestamps AS s INNER JOIN Logs AS l ON s.log_id = l.id
INNER JOIN Certificates AS c ON s.certificate_id = c.certificate_id
INNER JOIN Subjects AS su ON c.subject_id = su.subject_id
GROUP BY l.description
HAVING count > 12000
ORDER BY count DESC;

-- Top SCT Log Operators
SELECT lo.name, COUNT(*) AS count
FROM SignedCertificateTimestamps AS s INNER JOIN Logs AS l ON s.log_id = l.id
INNER JOIN LogsOperators AS lo ON l.operator_id = lo.id
GROUP BY lo.name
ORDER BY count DESC;

-- Estensioni Critiche vs Non Critiche delle Subject Alternative Name nelle Subjects
SELECT 
    subject_alt_name_is_critical,
    COUNT(DISTINCT CASE WHEN subject_dn IS NULL OR subject_dn = '' THEN subject_key_id END) AS count_null_empty,
    COUNT(DISTINCT CASE WHEN subject_dn IS NOT NULL AND subject_dn <> '' THEN subject_key_id END) AS count_non_empty
FROM Subjects
GROUP BY subject_alt_name_is_critical;

-- Estensioni Critiche vs Non Critiche del Certificate Policies
SELECT 
    COALESCE(is_cp_critical, 'No CP') AS is_cp_critical, 
    COUNT(DISTINCT(s.subject_key_id)) AS count
FROM 
    Certificates AS cc
JOIN 
    Subjects AS s ON cc.subject_id = s.subject_id
LEFT JOIN 
    Extensions AS e ON e.certificate_id = cc.certificate_id
LEFT JOIN 
    CertificatePolicies AS c ON c.extension_id = e.extension_id
GROUP BY 
    is_cp_critical
ORDER BY 
    count DESC;