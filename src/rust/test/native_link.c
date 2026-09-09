// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tav/snp.h"

#include <stdio.h>

int main(void)
{
  const uint8_t bytes[1184] = {0};
  TavSnpAttestationReport* report = NULL;
  TavError* error = tav_snp_attestation_report_from_unverified_bytes(
    bytes, sizeof(bytes), &report);
  if (error != NULL)
  {
    fprintf(stderr, "TAV parsing failed: %s\n", tav_error_message(error));
    tav_error_free(error);
    tav_snp_attestation_report_free(report);
    return 1;
  }
  if (report == NULL)
  {
    fputs("TAV parsing returned no report\n", stderr);
    return 1;
  }
  const uint32_t version = tav_snp_attestation_report_version(report);
  tav_snp_attestation_report_free(report);
  if (version != 0)
  {
    fputs("TAV parsing returned an unexpected report version\n", stderr);
    return 1;
  }
  return 0;
}
