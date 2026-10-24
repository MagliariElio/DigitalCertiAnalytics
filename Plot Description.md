# Charts and tables of the digital certificate analysis

This document describes the figures and tables generated with `--plot_all_results` (or `--plot_leaf_results`,
`--plot_intermediate_results`, `--plot_root_results`) in the `src/analysis/<type>/plots/` folder, the SQL query each
one comes from, the graphic style, and how the statistics are computed.

---

## Output files

For every chart with data, four files with the same base name are written:

| File | Content |
|------|---------|
| `<name>.png` | Raster figure at 300 dpi, 6.3 inches wide (16 cm, the text width of an A4 thesis). |
| `<name>.pdf` | The same figure in vector format, with embedded fonts, to include in LaTeX. |
| `<name>.csv` | The plotted data: columns `category`, `count` (in the unit of the chart: unique certificates, occurrences, SCTs or domains, as in the table heading), `share` (percentage of the chart total, decimal point). |
| `<name>.tex` | LaTeX table (`booktabs` + `siunitx`) with the same data, numbers with comma thousands separators and decimal point, a total row, a caption and the label `\label{tab:<type>-<name>}`. |

The folder also gets `captions.tex`, with a ready `figure` environment for every generated figure (`\includegraphics`
of the PDF, caption, label `\label{fig:<type>-<name>}`). The labels contain the certificate type (`leaf`,
`intermediate`, `root`) because the three analyses produce figures with the same names. For the same reason the figures
are referenced with the path of their folder, through one macro per type:
`\includegraphics{\plotsfolderleaf/issuer_certificates_count.pdf}`, with `\plotsfolderleaf` (and
`\plotsfolderintermediate`, `\plotsfolderroot`) defined by default as `leaf/plots`, the last two folders of the output
path. It is then enough to add the folder that contains them to `\graphicspath` (for example
`\graphicspath{{../src/analysis/}}`); to move the figures elsewhere, define the macro before `\input`, for example
`\newcommand{\plotsfolderleaf}{figures/leaf}`. With bare file names LaTeX would use the first figure found along
`\graphicspath`, even one of another certificate type.

The required packages are named at the top of the files: `graphicx` for the figures, `booktabs` and `siunitx` for the
tables (set up with `group-separator = {,}` and `output-decimal-marker = {.}`). The captions are computed from the data
(total N, thresholds, period, shares): they contain no hand-written values, and singular and plural follow the values
("at least 1 certificate", "1 certificate exceeds it", "of the only issuer", "N = 1 occurrence"). The table captions do
not describe the drawing: they mention no colours, columns of the UpSet diagram or curves. The signature algorithm
table has a "Status" column (`recommended` or `deprecated`) instead of the red colour, and in the UpSet table the least
frequent combinations are aggregated in the last row.

If a query returns no data, the chart is not generated and the log shows the warning
"No data available for chart ...". An error in one chart does not stop the generation of the others.

---

## Figure style ("classic academic")

- STIX serif font (shipped with matplotlib), 9.5 pt; no title inside the figure: the message goes in the LaTeX caption.
  The exceptions are the narrative figures, which have a title computed from the data (on two lines when it is wider
  than the figure).
- One accent colour, dark blue `#1d3f6e`, for the main categories (those that together reach half of the total); grey
  `#b8b8b8` for the others; light grey for the aggregated "Others" entry; dark red `#7a1f1f` for the negative
  categories: deprecated signature algorithms (SHA-1, MD5), OCSP status "Revoked", signature "Not Valid" or "Error",
  negative validity durations or durations beyond the limit.
- Axes without top and right spines. Horizontal bars sorted by value (ordinal categories, such as versions and
  durations, keep their order), each labelled "count (share)": `4,245,727 (45.0%)`, `< 0.01%` for the smallest shares.
- Automatic log scale when the values span more than three orders of magnitude, so the rare categories stay visible;
  axis in millions when the values exceed one million.
- No pie charts: shares are compared on bars.
- Line charts (expirations and SCTs) in the same style, with month labels (`Jan 2025`) or only the years for long
  periods. The queries return only the months above the threshold of the certificate type: the line is broken at the
  omitted months, instead of joining two distant months with a segment, and an isolated month is shown as a dot.
- Labels in English; technical names stay unchanged (RSA-SHA256, digitalSignature, ...).

---

## Figures for every certificate type (leaf, intermediate, root)

| File | Query (`StatisticsDAO`) | Figure |
|------|-------------------------|--------|
| `issuer_certificates_count` | `get_issuer_certificate_count` | Certificate occurrences per issuer organization: the first 20 issuers and the others aggregated in "Other issuers". |
| `issuer_concentration` | `get_issuer_distribution` | **Narrative.** Concentration curve: cumulative share of the occurrences of the first 20 issuers, with the Herfindahl-Hirschman index computed over all the issuers (low concentration below 1,000, moderate up to 1,800, high above). The title gives how many issuers cover half of the occurrences. |
| `certificate_version_distribution` | `get_certificate_version_distribution` | X.509 version (v1, v2, v3). |
| `count_critical_non_critical_extensions` | `get_count_critical_non_critical_extensions` | Criticality of the Authority Information Access extension (Critical, Not Critical, Not Found, Error). |
| `certificates_per_country` | `get_certificates_per_country` | Certificate occurrences per issuer country (ISO 3166 code): the first 5 countries (4 for intermediate certificates) and the others aggregated. |
| `certificate_expiration_trend` | `get_certificate_expiration_trend` | Certificates expiring per month (only the months above the threshold of the certificate type; the line is broken at the omitted months). |
| `validity_duration_distribution` | `get_validity_duration_distribution` | Validity duration in whole years; negative durations are grouped apart. |
| `validity_days_distribution` | `get_validity_days_distribution` | Validity duration in days, in classes aligned with the CA/Browser Forum limits: ≤ 90, 91–200, 201–398, 399–825, 826 days – 5 years, > 5 years, negative duration. |
| `signature_algorithm_distribution` | `get_signature_algorithm_distribution` | Signature algorithms; in red those with a deprecated hash (SHA-1, MD5, MD2), marked `deprecated` in the "Status" column of the table. |
| `signature_family_share` | `get_signature_algorithm_distribution` | **Narrative.** Signature algorithm families (RSA, ECDSA, EdDSA, DSA): the title gives the ECDSA share and the note below the figure the number of certificates still signed with SHA-1 or MD5. |
| `key_algorithm_length_distribution` | `get_key_algorithm_length_distribution` | Algorithm and length in bits of the public key (e.g. "RSA 2048", "ECDSA 256"). |
| `key_usage_distribution` | `get_key_usage_distribution` | **UpSet diagram** of the Key Usage combinations: the bars give the certificates of each combination, the dot matrix the flags it contains. The 10 most frequent combinations are shown; the others are aggregated in the last column. |
| `critical_vs_non_critical_key_usage` | `get_critical_vs_non_critical_key_usage` | Criticality of the Key Usage extension. |
| `extended_key_usage_distribution` | `get_extended_key_usage_distribution` | **UpSet diagram** of the Extended Key Usage combinations, as for Key Usage. |
| `critical_vs_non_critical_extended_key_usage` | `get_critical_vs_non_critical_extended_key_usage` | Criticality of the Extended Key Usage extension. |
| `critical_vs_non_critical_san_extensions` | `get_critical_vs_non_critical_san_extensions` | Criticality of the Subject Alternative Name extension. |
| `critical_vs_non_critical_cp_policies` | `get_critical_vs_non_critical_cp_policies` | Criticality of the Certificate Policies extension. |
| `validation_level_distribution` | `get_validation_level_distribution` | Validation level (DV, OV, EV). |
| `basic_constraints_distribution` | `get_basic_constraints_distribution` | Values of the Basic Constraints extension (e.g. "cA = TRUE, max_path_len = 0"). |
| `critical_vs_non_critical_crl_distribution` | `get_critical_vs_non_critical_crl_distribution` | Criticality of the CRL Distribution Points extension. |
| `ocsp_status_distribution` | `get_ocsp_status_distribution` | Outcome of the OCSP check of the certificate occurrences; "Revoked" in red. |

## Figures for leaf certificates only

| File | Query (`StatisticsDAO`) | Figure |
|------|-------------------------|--------|
| `validity_beyond_398_days` | `get_validity_days_distribution` | **Narrative.** Share of certificates per duration class, in red the classes beyond the 398-day limit of the CA/Browser Forum Baseline Requirements; the title gives the share that exceeds it; the note with the number of certificates is placed above the side with the lower bars and covers no bar or label. |
| `status_analysis` | `get_status_analysis` | Outcome of the TLS scan of the domains: successful handshakes and error types. |
| `self_signed_vs_ca_signed` | `get_self_signed_vs_ca_signed` | Self-signed and CA-signed certificates. |
| `top_sct_logs` | `get_top_sct_logs` | Certificate Transparency logs used by more than 12,000 certificates. |
| `top_sct_log_operators` | `get_top_sct_log_operators` | Signed Certificate Timestamps (SCTs) per log operator. |
| `sct_trend` | `get_signed_certificate_timestamp_trend` | SCTs per month (only the months with more than 20 SCTs; the line is broken at the omitted months). |
| `sct_count_per_certificate` | `get_sct_count_per_certificate` | Number of SCTs per certificate occurrence. |

## Figures for leaf and root certificates

| File | Query (`StatisticsDAO`) | Figure |
|------|-------------------------|--------|
| `signature_validity_distribution` | `get_signature_validity_distribution` | Signature validity; "Not Valid" and "Error" in red. |

---

## Counting the certificates

The figures count two different quantities, named in the captions:

- **Unique certificates**, in most figures: two rows with the same Subject Key Identifier count once; certificates
  without a Subject Key Identifier (e.g. v1) are told apart by the certificate itself.
- **Occurrences**: the database rows, that is every certificate counted once for every scanned domain that presented
  it. `issuer_certificates_count`, `issuer_concentration` (Herfindahl-Hirschman index included),
  `certificates_per_country`, `ocsp_status_distribution` and `sct_count_per_certificate` count these. For intermediate
  and root certificates, which repeat a few thousand certificates in millions of chains, the occurrences can be
  thousands of times more than the unique certificates: the captions call them "occurrences", not "certificates".

`status_analysis` (scanned domains), `top_sct_log_operators` and `sct_trend` (SCTs) count other quantities;
`top_sct_logs` counts the unique certificates of each log. The display thresholds (issuers and countries shown,
minimum months and durations) depend on the certificate type and are given in the captions.

---

## Execution

The plot stage of each certificate type has two steps:

1. **Correction** (`Database.prepare_for_plots`): issuers stored as `DigiCert, Inc.` become `DigiCert Inc`. Each
   distinct issuer is stored once (`IssuerData`, see `Database Description.md`), so only a few rows change and the
   rollback journal stays small. No index is built: the statistics need none, and the query of
   `get_issuer_certificate_count` orders the issuers with equal counts by name (`ORDER BY count DESC, label`).
2. **Statistics and charts.** The statistics of every chart are computed from one parallel read of each base table
   (`StatisticsDAO.materialize`, `src/dao/statistics_facts.py`):
   - the scans of `Occurrences` (integer keys and codes only), `CertificateData` (each distinct certificate, with its
     subject and extensions), `IssuerData`, `SctData` and `PolicySetMembers` are split into row ranges and run in the
     render processes (one per CPU), on read-only connections. The `Errors` count runs as one more task;
   - each row is reduced to integer codes of its values, computed in SQL with the same expressions as the queries; the
     values stored per certificate are evaluated once per distinct certificate, and the counts of rows of the views
     (OCSP statuses, issuer organizations and countries, SCT months and operators, SCTs per certificate) weigh every
     certificate by its number of occurrences;
   - the main process counts the unique certificates exactly, with numpy: the certificate identity (Subject Key
     Identifier, or the original raw certificate text when it has none) is compared through its SQLite type and a
     128-bit BLAKE2b digest (collision probability about 1e-25 for 6.5 million certificates);
   - the final grouping, filtering and ordering of each statistic run in SQLite, on small temporary tables, with the
     SQL of the per-query path: values, order and key types are identical to those of the queries.

   Without render processes the same statistics are computed in the main process. The charts are then drawn in the
   render processes from these data. The log reports "Computing the statistics (one read per table)...", "Statistics
   computed in ... s." and, for every figure, "Generating chart ..." and its outcome in the order of the tables above,
   whatever the order in which the drawings finish.

If the statistics cannot be computed this way, the stage falls back to the per-query path, with the same results: each
`get_*` query runs on the views (`Certificates`, `Subjects`, `Issuers`, ...) in a render process on its own read-only
connection (at most four queries at the same time), followed by its charts. This happens with in-memory databases and
connections with uncommitted changes (queried in the main process), or any error during the scans, for example a
render process that dies (warning "Statistics not materialized ..."). A statistic that a database cannot give (the
`signature_valid` column of intermediate databases, the `Errors` view missing in intermediate and root databases)
always runs its own query, which logs the same error as before.

The render processes are reused for leaf, intermediate and root and closed with `shutdown_render_pool()` after the plot
stage, so they do not stay alive during the following stages. If they are not available, or one of them ends
abnormally, the remaining charts are generated in sequence in the main process. With Ctrl+C the processes are stopped
at once, also during the scans (exit code 130, no message from their start-up); if the main process is killed (for
example with `kill -9`), the render processes exit on their own as soon as it is gone.

### Time and memory

Measured on a machine with 12 CPUs and an SSD (Python 3.12), on the databases made from the dataset of 1 million scan
lines (about 649,000 leaf certificate occurrences):

| Step | Time |
|---|---|
| leaf statistics, in the main process only | 3.1-3.8 s (4.4 s with schema version 1) |
| leaf statistics, scans in 12 render processes | 1.1 s |
| intermediate statistics, in the main process only | 0.28 s (2.9 s with schema version 1) |
| root statistics, in the main process only | 0.14 s (0.9 s with schema version 1) |
| the whole `--plot_all_results` stage | 17.7 s with an empty matplotlib font cache, 3.7 s afterwards (21.7 s with schema version 1) |

The main process used at most 285 MB of memory. On the per-query path the leaf queries took 44.7 s (43.0 s
with schema version 1): the views always join all their lookup tables, so this path is the slower one.

Memory:
- The main process holds the codes of every scanned row while it aggregates them, so it grows linearly with the
  distinct certificates and the occurrences, and does not depend on the number of render processes.
- Each render process uses 0.1-0.25 GiB (Python, matplotlib, the rows of the scan in progress). There is one per CPU,
  so the total grows with the CPU count.

On the per-query path the temporary tables of DISTINCT and GROUP BY are kept in memory only if the database file is at
most one eighth of the physical memory; above that they are written to temporary files and every process stays below
about 330 MiB, whatever the size of the database.

### Temporary disk space

- The statistics write no temporary files: the scans keep their rows in memory and the final temporary tables hold a
  few rows.
- The correction writes a rollback journal next to the database with the original content of the pages it changes:
  only the pages of the distinct issuers to correct, a few MB at most.
- Only on the per-query path, the temporary files of the queries need up to about 11% of the database file for each of
  the four queries in progress.
