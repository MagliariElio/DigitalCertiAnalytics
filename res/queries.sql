-- Queries on the SQLite databases of DigitalCertiAnalytics (schema version 2, see "Database Description.md").
--
-- The queries read the views Certificates, Subjects, Issuers, Extensions, CertificatePolicies,
-- SignedCertificateTimestamps and Errors, which have the names, columns and values of the tables of the first
-- version (certificate_id is the occurrence id, the position in the scan file). The views cannot be changed:
-- the UPDATE statements and the indexes below work on the base tables (Occurrences, CertificateData, IssuerData,
-- SctData, ...). The raw columns hold the certificates compressed with zstd: see "Database Description.md" to read
-- them back. Run one statement at a time (for example in DB Browser for SQLite, or the sqlite3 program).

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
WHERE (authority_info_access LIKE '{}' OR NOT authority_info_access LIKE '%ocsp_urls%');

SELECT COUNT(*) AS count, *
FROM Certificates AS c INNER JOIN Issuers AS i ON c.issuer_id = i.issuer_id
WHERE (NOT c.authority_info_access LIKE '{}' AND NOT c.authority_info_access LIKE '%issuer_urls%' AND i.raw IS NULL);

-- The OCSP result is stored per occurrence, as a code of the OcspStatuses table
UPDATE Occurrences
SET ocsp_check = (SELECT code FROM OcspStatuses WHERE name = 'No Issuer Url Found')
WHERE occurrence_id IN (
      SELECT certificate_id
      FROM Certificates
      WHERE NOT authority_info_access LIKE '{}' 
        AND NOT authority_info_access LIKE '%issuer_urls%' 
        AND issuer_id IN (
            SELECT issuer_id
            FROM Issuers
            WHERE raw IS NULL
        )
  );

SELECT COUNT(*) AS count
FROM Certificates
WHERE NOT (authority_info_access LIKE '{}' OR NOT authority_info_access LIKE '%ocsp_urls%');

SELECT COUNT(*) AS count, ocsp_check, authority_info_access
FROM Certificates
WHERE (authority_info_access LIKE '{}' OR NOT authority_info_access LIKE '%ocsp_urls%')
GROUP BY ocsp_check, authority_info_access;

UPDATE Occurrences
SET ocsp_check = (SELECT code FROM OcspStatuses WHERE name = 'No Request Done');

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

-- Count how many certificates have the extension and whether it is critical or not
SELECT 
    COALESCE(crl_distr_point_is_critical, 'No Extension') AS crl_distr_point_is_critical, 
    COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c
LEFT JOIN Extensions AS e ON c.certificate_id = e.certificate_id
INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY crl_distr_point_is_critical;







-- Count the certificates with a duplicate serial number
SELECT serial_number, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY serial_number
HAVING count > 1
ORDER BY count DESC;

-- Count the certificates with a negative serial number
SELECT serial_number, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY serial_number
ORDER BY serial_number;

-- Count the certificates with a positive serial number longer than 20 bytes
SELECT COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE serial_number >= 0 AND (LENGTH(printf('%X', serial_number)) / 2) > 20
GROUP BY serial_number
ORDER BY count DESC;

-- Count the distinct serial numbers
SELECT COUNT(DISTINCT(serial_number))
FROM Certificates;

-- Distribution of the number of intermediate certificates in the chain
SELECT certificates_up_to_root_count, COUNT(DISTINCT(subject_dn)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY certificates_up_to_root_count
ORDER BY count DESC;

-- Distribution of the signature algorithms among the certificates 
SELECT signature_algorithm, COUNT(DISTINCT(subject_dn)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY signature_algorithm;

-- Count the unique certificates for each policy identifier and validation level
SELECT policy_identifier, validation_level, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS cc INNER JOIN Subjects AS s ON cc.subject_id = s.subject_id
LEFT JOIN Extensions AS e ON cc.certificate_id = e.certificate_id 
LEFT JOIN CertificatePolicies AS c ON c.extension_id = e.extension_id
GROUP BY policy_identifier, validation_level
ORDER BY count DESC;

-- Count the certificates with at least one policy
SELECT COUNT(DISTINCT s.subject_key_id) AS certificates_with_policy
FROM Certificates AS cc INNER JOIN Subjects AS s ON cc.subject_id = s.subject_id
LEFT JOIN Extensions AS e ON cc.certificate_id = e.certificate_id
LEFT JOIN CertificatePolicies AS c ON c.extension_id = e.extension_id
WHERE c.policy_identifier IS NOT NULL;

-- Count the policy identifiers for each validation level, as required by the CA/B Forum
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
    
    -- Count the certificates with only the policy of their validation level (DV, OV, EV)
    COUNT(DISTINCT CASE 
        WHEN validation_level = 'DV' AND has_policy_2_23_140_1_2_1 = 1 AND has_other_policy_dv = 0 THEN subject_key_id 
        WHEN validation_level = 'OV' AND has_policy_2_23_140_1_2_2 = 1 AND has_other_policy_ov = 0 THEN subject_key_id 
        WHEN validation_level = 'EV' AND has_policy_2_23_140_1_1 = 1 AND has_other_policy_ev = 0 THEN subject_key_id 
        END) AS count_with_only_own_policy,
    
	-- Count the certificates with their own policy_identifier and other policy_identifiers
    COUNT(DISTINCT CASE  
		WHEN validation_level = 'DV' AND has_policy_2_23_140_1_2_1 = 1 THEN subject_key_id 
        WHEN validation_level = 'OV' AND has_policy_2_23_140_1_2_2 = 1 THEN subject_key_id 
        WHEN validation_level = 'EV' AND has_policy_2_23_140_1_1 = 1 THEN subject_key_id 
		END) AS count_with_other_policy,

    -- Count the certificates without their own policy_identifier but with other policies
    COUNT(DISTINCT CASE 
		WHEN validation_level = 'DV' AND has_policy_2_23_140_1_2_1 = 0 AND has_other_policy_dv = 1 THEN subject_key_id 
        WHEN validation_level = 'OV' AND has_policy_2_23_140_1_2_2 = 0 AND has_other_policy_ov = 1 THEN subject_key_id 
        WHEN validation_level = 'EV' AND has_policy_2_23_140_1_1 = 0 AND has_other_policy_ev = 1 THEN subject_key_id 
		END) AS count_without_own_policy,
    	
	-- Count the certificates without any policy
    COUNT(DISTINCT CASE 
        WHEN count_without_any_policy > 0 THEN subject_key_id 
        END) AS count_without_any_policy
FROM PolicyCounts
GROUP BY validation_level;

-- Count the issuers for each AKI length
SELECT LENGTH(DISTINCT authority_key_id) AS key_length, COUNT(DISTINCT issuer_key_id) AS key_count
FROM Issuers
GROUP BY key_length
ORDER BY key_length;

-- Count the subjects for each SKI length
SELECT LENGTH(DISTINCT subject_key_id) AS key_length, COUNT(DISTINCT subject_dn) AS key_count
FROM Subjects
GROUP BY key_length
ORDER BY key_length;

-- Contradiction between max_path_length equal to 0 and intermediate certificates issued by the certificate in the chain (TO CHECK, COULD BECOME A CHART).
SELECT c.certificate_id, e.max_path_length, c.certificates_emitted_up_to, c.has_root_certificate, e.basic_constraints
FROM Certificates AS c INNER JOIN Extensions AS e ON c.certificate_id = e.certificate_id
WHERE max_path_length = 0 AND c.certificates_emitted_up_to > 0;

-- Optional indexes, only for your own queries: the program needs none of them (it reads the tables in order or by
-- primary key). Views cannot have indexes, so they go on the base tables. Each index takes disk space (remove it with
-- DROP INDEX), and it can change the order of rows with equal values in a query whose ORDER BY does not decide it.

-- Occurrences (the per-occurrence columns of the Certificates view)
CREATE INDEX IF NOT EXISTS idx_occurrences_certificate_id ON Occurrences(certificate_id);
CREATE INDEX IF NOT EXISTS idx_occurrences_issuer_id ON Occurrences(issuer_id);
CREATE INDEX IF NOT EXISTS idx_occurrences_leaf_domain ON Occurrences(leaf_domain);
CREATE INDEX IF NOT EXISTS idx_occurrences_ocsp_check ON Occurrences(ocsp_check);
CREATE INDEX IF NOT EXISTS idx_occurrences_signature_valid ON Occurrences(signature_valid);  -- leaf and root only

-- CertificateData (the columns of each distinct certificate, with its subject and extensions)
CREATE INDEX IF NOT EXISTS idx_certificate_data_version ON CertificateData(version);
CREATE INDEX IF NOT EXISTS idx_certificate_data_validity_end ON CertificateData(validity_end);
CREATE INDEX IF NOT EXISTS idx_certificate_data_self_signed ON CertificateData(self_signed);
CREATE INDEX IF NOT EXISTS idx_certificate_data_subject_dn ON CertificateData(subject_dn);
CREATE INDEX IF NOT EXISTS idx_certificate_data_subject_common_name ON CertificateData(subject_common_name);
CREATE INDEX IF NOT EXISTS idx_certificate_data_key_usage ON CertificateData(key_usage);
CREATE INDEX IF NOT EXISTS idx_certificate_data_extended_key_usage ON CertificateData(extended_key_usage);

-- IssuerData (each distinct issuer)
CREATE INDEX IF NOT EXISTS idx_issuer_data_common_name ON IssuerData(common_name);
CREATE INDEX IF NOT EXISTS idx_issuer_data_organization ON IssuerData(organization);

-- SctData (the SCTs of each distinct certificate; its primary key already starts with certificate_id)
CREATE INDEX IF NOT EXISTS idx_sct_data_log_id ON SctData(log_id);

-- ErrorData (leaf database only)
CREATE INDEX IF NOT EXISTS idx_error_data_domain ON ErrorData(domain);
CREATE INDEX IF NOT EXISTS idx_error_data_status ON ErrorData(status);

-- Logs (Logs.log_id is UNIQUE, so it already has an index)
CREATE INDEX IF NOT EXISTS idx_logs_operator_id ON Logs(operator_id);







--------------

-- Check OCSP Status for certificates
SELECT c.certificate_id, c.authority_info_access, i.common_name, i.raw AS issuer_cert_raw, c.raw AS leaf_cert_raw
FROM certificates AS c 
INNER JOIN Issuers AS i ON c.issuer_id = i.issuer_id
WHERE c.ocsp_check = 'No Request Done'
LIMIT 1000;

--------------
-- Queries for the charts of the results

-- Count the certificates issued by each issuer
WITH IssuersCounts AS (
	SELECT Issuers.organization, COUNT(*) AS certificate_count
	FROM Certificates 
	INNER JOIN Issuers ON Certificates.issuer_id = Issuers.issuer_id 
	WHERE Issuers.organization IS NOT NULL AND TRIM(Issuers.organization) <> ''
	GROUP BY Issuers.organization
	ORDER BY certificate_count DESC, Issuers.organization
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

-- Rename DigiCert (the program does it before drawing the charts); each distinct issuer is stored once in IssuerData
UPDATE IssuerData
SET organization = 'DigiCert Inc'
WHERE organization = 'DigiCert, Inc.';

-- Number of certificates issued in each country
WITH IssuersCounts AS (
	SELECT Issuers.country, COUNT(*) AS country_count
	FROM Issuers
	WHERE TRIM(Issuers.country) <> '' AND TRIM(Issuers.country) <> '--'
	GROUP BY Issuers.country
	ORDER BY country_count DESC, Issuers.country
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

-- Distribution of the validity period in units of 365 days
SELECT validity_length/31536000, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE validity_length < 0
UNION ALL
SELECT validity_length/31536000, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE c.validity_length IS NOT NULL AND validity_length >= 0
GROUP BY validity_length/31536000
HAVING count >= 0;

-- Count the certificates with a validity period longer than 398 days issued after September 2, 2020
SELECT validity_length/34387200, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE c.validity_length IS NOT NULL AND validity_length >= 0 AND validity_start > '2020-09-01T00:00:00Z'
GROUP BY validity_length/34387200;

-- Count the certificates with a validity period longer than 39 months issued after April 1, 2015 and before September 2, 2020
SELECT validity_length/101088000, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE c.validity_length IS NOT NULL AND validity_length >= 0 AND validity_start >= '2015-04-01T00:00:00Z' AND validity_start <= '2020-09-01T00:00:00Z'
GROUP BY validity_length/101088000;

-- Certificate expiry trend
SELECT strftime('%Y-%m', validity_end) AS month, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE validity_end IS NOT NULL
GROUP BY month
HAVING count > 0
ORDER BY month ASC;

-- Signature algorithms used
SELECT signature_algorithm, COUNT(DISTINCT(subject_key_id)) AS sign_algorithm_count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
WHERE signature_algorithm IS NOT NULL
GROUP BY signature_algorithm
ORDER BY sign_algorithm_count DESC;

-- Distribution of the key algorithms and lengths
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
	
-- OCSP status of the certificates
SELECT ocsp_check, COUNT(*) AS count
FROM Certificates
GROUP BY ocsp_check;

-- Critical vs non-critical AIA extensions
SELECT authority_info_access_is_critical, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY authority_info_access_is_critical
ORDER BY count DESC;

-- Self-signed vs CA-signed certificates
SELECT 
	CASE 
        WHEN self_signed = 1 THEN 'True' 
        ELSE 'False' 
    END AS is_self_signed,
    COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY self_signed;

-- Validation levels of the certificates
SELECT validation_level, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY validation_level;

-- Distribution of the certificate versions
SELECT version, COUNT(*) AS count
FROM Certificates
GROUP BY version;

-- Validity of the certificate signatures
SELECT signature_valid AS is_valid_signature, COUNT(DISTINCT(subject_key_id)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY signature_valid
ORDER BY count DESC;

-- Certificate status analysis
SELECT 'success', COUNT(*) AS count
FROM Certificates
UNION ALL
SELECT status, COUNT(*) AS count
FROM Errors
GROUP BY status;

-- Key usage in the extensions, by key algorithm (leaf)
SELECT e.key_usage, c.key_algorithm, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Extensions AS e JOIN Certificates AS c ON e.certificate_id = c.certificate_id 
JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY e.key_usage, c.key_algorithm
ORDER BY count DESC;

-- Key usage in the extensions
SELECT e.key_usage, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Extensions AS e JOIN Certificates AS c ON e.certificate_id = c.certificate_id 
JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY e.key_usage
ORDER BY count DESC;

-- SELECT e.key_usage, COUNT(DISTINCT(s.subject_dn)) AS count
-- FROM Extensions AS e INNER JOIN Subjects AS s ON e.certificate_id = s.subject_id
-- GROUP BY e.key_usage
-- ORDER BY count DESC;

-- Critical vs non-critical key usage extensions
SELECT key_usage_is_critical, COUNT(DISTINCT(subject_key_id)) AS count
FROM Extensions AS e JOIN Certificates AS c ON e.certificate_id = c.certificate_id
JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY key_usage_is_critical
ORDER BY count DESC;

-- SELECT e.key_usage_is_critical, COUNT(DISTINCT(s.subject_dn)) AS count
-- FROM Extensions AS e INNER JOIN Subjects AS s ON e.certificate_id = s.subject_id
-- GROUP BY e.key_usage_is_critical
-- ORDER BY count DESC;

-- Extended key usage in the extensions
SELECT e.extended_key_usage, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS c INNER JOIN Subjects AS s ON c.subject_id = s.subject_id 
LEFT JOIN Extensions AS e ON e.certificate_id = c.certificate_id 
GROUP BY e.extended_key_usage
ORDER BY count DESC;

-- Number of records without an EKU
SELECT COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Certificates AS c 
INNER JOIN Subjects AS s ON c.subject_id = s.subject_id
LEFT JOIN Extensions AS e ON e.certificate_id = c.certificate_id
WHERE e.certificate_id IS NULL;

-- SELECT e.extended_key_usage, COUNT(DISTINCT(s.subject_dn)) AS count
-- FROM Extensions AS e JOIN Subjects AS s ON e.certificate_id = s.subject_id 
-- GROUP BY e.extended_key_usage
-- ORDER BY count DESC;

-- Critical vs non-critical extended key usage extensions
SELECT e.extended_key_usage_is_critical, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Extensions AS e JOIN Certificates AS c ON e.certificate_id = c.certificate_id 
JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY e.extended_key_usage_is_critical
ORDER BY count DESC;

-- SELECT e.extended_key_usage_is_critical, COUNT(DISTINCT(s.subject_dn)) AS count
-- FROM Extensions AS e JOIN Subjects AS s ON e.certificate_id = s.subject_id 
-- GROUP BY e.extended_key_usage_is_critical
-- ORDER BY count DESC;

-- Distribution of the basic constraints in the extensions
SELECT e.basic_constraints, COUNT(DISTINCT(s.subject_key_id)) AS count
FROM Extensions AS e JOIN Certificates AS c ON e.certificate_id = c.certificate_id
JOIN Subjects AS s ON c.subject_id = s.subject_id
GROUP BY e.basic_constraints
ORDER BY count DESC;

-- SELECT e.basic_constraints, COUNT(DISTINCT(s.subject_dn)) AS count
-- FROM Extensions AS e JOIN Subjects AS s ON e.certificate_id = s.subject_id
-- GROUP BY e.basic_constraints
-- ORDER BY count DESC;

-- Critical vs non-critical CRL distribution point extensions
SELECT crl_distr_point_is_critical, COUNT(*) AS count
FROM Extensions
GROUP BY crl_distr_point_is_critical
ORDER BY count DESC;

-- Signed Certificate Timestamps (SCT) trend by month and year
SELECT 
    strftime('%Y-%m', datetime(timestamp, 'unixepoch')) AS month_year, 
    COUNT(*) AS count
FROM SignedCertificateTimestamps
GROUP BY month_year
HAVING count > 10
ORDER BY month_year ASC;

-- Number of Signed Certificate Timestamps (SCT) per certificate
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

-- Critical vs non-critical Subject Alternative Name extensions in the Subjects
SELECT 
    subject_alt_name_is_critical,
    COUNT(DISTINCT CASE WHEN subject_dn IS NULL OR subject_dn = '' THEN subject_key_id END) AS count_null_empty,
    COUNT(DISTINCT CASE WHEN subject_dn IS NOT NULL AND subject_dn <> '' THEN subject_key_id END) AS count_non_empty
FROM Subjects
GROUP BY subject_alt_name_is_critical;

-- Critical vs non-critical Certificate Policies extensions
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
