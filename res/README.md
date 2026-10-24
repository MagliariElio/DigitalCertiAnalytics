# Instructions

The analysis reads one input file at a time, always named:

- **certs_polito.json**

or, compressed, **certs_polito.json.zst**, **certs_polito.json.gz**, **certs_polito.json.xz** or
**certs_polito.json.bz2** (the plain file is used first when several are there). `./dca --compress_input` (Windows:
`dca.bat --compress_input`) turns the file into **certs_polito.json.zst**, about a fifth of its size, which is read in
parallel just like the plain file.

To analyse one of the following scans, rename it to that name (keeping the compression suffix, if any):

1. **certs_polito_top10m_domcop.json**
2. **certs_european.json**

The files **top-10m-websites-dom-cop.txt** and **european_domains_google.txt** are the input files used for ZGrab2.
