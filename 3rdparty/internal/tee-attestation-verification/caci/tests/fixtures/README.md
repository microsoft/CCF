# CACI Fixture Provenance

These fixtures include one legacy UVM endorsement set and one transparent/SCITT
UVM endorsement set. They are intended for local regression tests.

The legacy files were captured from an earlier CACI container run.

The transparent/SCITT fixture capture flow was:

1. Start a CACI container.
2. Read the fixture material from `/security-context-XXXXXX/<fixture>` inside
   the container.
3. Request the SNP attestation report with `/tools/get-snp-report <report_data>`.
4. Query the AMD KDS for the certificate chain and VCEK certificates needed to
   verify the report.

The legacy files in this directory are:

- `host-amd-cert.base64`: AMD endorsement/certificate material from the CACI
  security context.
- `reference-info.base64`: Legacy UVM reference information from the CACI
  security context.
- `report.hex`: SNP attestation report captured with the legacy fixture set.

The transparent/SCITT files in this directory are:

- `host-amd-cert-scitt-cwt.base64`: AMD endorsement/certificate material from
  the CACI security context.
- `reference-info-scitt-cwt.base64`: Transparent/SCITT UVM reference
  information from the CACI security context.
- `report-scitt-cwt.hex`: SNP attestation report generated with
  `/tools/get-snp-report`.