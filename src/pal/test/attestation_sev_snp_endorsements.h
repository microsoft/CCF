// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/attestation_sev_snp_endorsements.h"

namespace ccf::pal::snp
{
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(
    EndorsementEndpointsConfiguration::EndpointInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    EndorsementEndpointsConfiguration::EndpointInfo, host, port, uri);
  DECLARE_JSON_OPTIONAL_FIELDS(
    EndorsementEndpointsConfiguration::EndpointInfo,
    params,
    response_is_der,
    response_is_thim_json,
    headers,
    tls,
    max_retries_count,
    max_client_response_size);

  DECLARE_JSON_TYPE(EndorsementEndpointsConfiguration);
  DECLARE_JSON_REQUIRED_FIELDS(EndorsementEndpointsConfiguration, servers);
}