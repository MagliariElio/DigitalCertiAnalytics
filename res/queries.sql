SELECT COUNT(*) FROM Certificates;

SELECT COUNT(*) FROM Errors;

SELECT COUNT(*) FROM Extensions;

SELECT COUNT(*) AS count, *
FROM Certificates
GROUP BY ocsp_must_stapling

-- Controlla se esistono differenze tra i dati del subject e issuer (Query per i certificati ROOT)
-- Da eliminare la tabella Issuer una volta caricati tutti i root
SELECT COUNT(*)
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id 
INNER JOIN Issuers AS i ON c.issuer_id = i.issuer_id
WHERE s.common_name = i.common_name AND s.subject_dn = i.issuer_dn

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
	SELECT COUNT(*) AS certificate_count, Issuers.organization
	FROM Certificates 
	INNER JOIN Issuers ON Certificates.issuer_id = Issuers.issuer_id 
	WHERE Issuers.organization IS NOT NULL AND TRIM(Issuers.organization) <> ''
	GROUP BY Issuers.organization
	ORDER BY certificate_count DESC
),
TopIssuers AS (
	SELECT certificate_count, organization
	FROM IssuersCounts
	LIMIT 20
),
Others AS (
	SELECT SUM(certificate_count) AS certificate_count, 'Others' AS organization
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
	LIMIT 11
),
Others AS (
	SELECT 'Others' AS country, COALESCE(SUM(country_count), 0) AS country_count
	FROM IssuersCounts 
	WHERE country NOT IN (SELECT country FROM TopCountry)
)
SELECT * FROM TopCountry
UNION ALL
SELECT * FROM Others;

-- Mostra la distribuzione della durata di validità
SELECT validity_length, COUNT(*) AS count
FROM Certificates
WHERE validity_length IS NOT NULL AND validity_length >= 0 AND validity_length <= 630720000
GROUP BY validity_length
ORDER BY count DESC;

-- Trend di Scadenza dei Certificati
SELECT strftime('%Y-%m', validity_end) AS month, COUNT(*) AS count
FROM Certificates
WHERE validity_end IS NOT NULL
GROUP BY month
HAVING count > 10
ORDER BY month ASC;

-- Algoritmi di Firma Utilizzati
SELECT signature_algorithm, COUNT(*) AS sign_algorithm_count
FROM Certificates
WHERE signature_algorithm IS NOT NULL
GROUP BY signature_algorithm
ORDER BY sign_algorithm_count DESC;

-- Distribuzione degli Algoritmi di Chiave e Lunghezza
SELECT 
    key_algorithm, 
    key_length, 
    COUNT(*) AS certificate_count
FROM 
    Certificates
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

-- Estensioni Critiche vs Non Critiche dell'AIA negli Issuers
SELECT authority_info_access_is_critical, COUNT(*) AS count
FROM Certificates
GROUP BY authority_info_access_is_critical
ORDER BY count DESC;

-- Certificati Auto-Firmati vs CA-Firmati
SELECT 
	CASE 
        WHEN self_signed = 1 THEN 'True' 
        ELSE 'False' 
    END AS is_self_signed,
    COUNT(*) AS count
FROM Certificates
GROUP BY self_signed;

-- Livelli di Validazione dei Certificati
SELECT validation_level, COUNT(*) AS count
FROM Certificates
GROUP BY validation_level;

-- Distribuzione delle Versioni dei Certificati
SELECT version, COUNT(*) AS count
FROM Certificates
GROUP BY version;

-- Validità delle Firme dei Certificati
SELECT
	CASE 
        WHEN signature_valid = 1 THEN 'True' 
        ELSE 'False' 
    END AS is_valid_signature,
	COUNT(*) AS count
FROM Certificates
GROUP BY signature_valid;

-- Analisi Status Certificati
SELECT 'success', COUNT(*) AS count
FROM Certificates
UNION ALL
SELECT status, COUNT(*) AS count
FROM Errors
GROUP BY status;

-- Utilizzo del Key Usage nelle Estensioni
SELECT key_usage, COUNT(*) AS count
FROM Extensions
GROUP BY key_usage
ORDER BY count DESC;

-- Estensioni Critiche vs Non Critiche del Key Usage nelle Estensioni
SELECT key_usage_is_critical, COUNT(*) AS count
FROM Extensions
GROUP BY key_usage_is_critical
ORDER BY count DESC;

-- Utilizzo dell'Extended Key Usage nelle Estensioni
SELECT extended_key_usage, COUNT(*) AS count
FROM Extensions
GROUP BY extended_key_usage
ORDER BY count DESC;

-- Estensioni Critiche vs Non Critiche dell'Extended Key Usage nelle Estensioni
SELECT extended_key_usage_is_critical, COUNT(*) AS count
FROM Extensions
GROUP BY extended_key_usage_is_critical
ORDER BY count DESC;

-- Distribuzione del Basic Costraints nelle Estensioni
SELECT basic_constraints, COUNT(*) AS count
FROM Extensions
GROUP BY basic_constraints
ORDER BY count DESC;

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

-- Top SCT Logs
SELECT l.description, COUNT(*) AS count
FROM SignedCertificateTimestamps AS s INNER JOIN Logs AS l ON s.log_id = l.id
GROUP BY l.description
HAVING count > 5
ORDER BY count DESC;

-- Top SCT Log Operators
SELECT lo.name, COUNT(*) AS count
FROM SignedCertificateTimestamps AS s INNER JOIN Logs AS l ON s.log_id = l.id
INNER JOIN LogsOperators AS lo ON l.operator_id = lo.id
GROUP BY lo.name
ORDER BY count DESC;

-- Estensioni Critiche vs Non Critiche delle Subject Alternative Name nelle Subjects
SELECT subject_alt_name_is_critical, COUNT(*) AS count
FROM Subjects
GROUP BY subject_alt_name_is_critical
ORDER BY count DESC;

-- Estensioni Critiche vs Non Critiche del Certificate Policies
SELECT is_cp_critical, COUNT(*) AS count
FROM CertificatePolicies
GROUP BY is_cp_critical
ORDER BY count DESC;
