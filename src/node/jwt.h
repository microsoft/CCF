// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json.h"
#include "entities.h"
#include "kv/map.h"

#include <msgpack/msgpack.hpp>
#include <optional>

namespace ccf
{
  struct JwtIssuerKeyPolicy
  {
    // OE claim name -> hex-encoded claim value
    // See openenclave/attestation/verifier.h
    std::optional<std::map<std::string, std::string>> sgx_claims;

    bool operator!=(const JwtIssuerKeyPolicy& rhs) const
    {
      return rhs.sgx_claims != sgx_claims;
    }

    MSGPACK_DEFINE(sgx_claims);
  };

  DECLARE_JSON_TYPE(JwtIssuerKeyPolicy);
  DECLARE_JSON_REQUIRED_FIELDS(JwtIssuerKeyPolicy, sgx_claims);

  enum class JwtIssuerKeyFilter
  {
    All,
    SGX
  };

  DECLARE_JSON_ENUM(
    JwtIssuerKeyFilter,
    {{JwtIssuerKeyFilter::All, "all"}, {JwtIssuerKeyFilter::SGX, "sgx"}});

  struct JwtIssuerMetadata
  {
    JwtIssuerKeyFilter key_filter;
    std::optional<JwtIssuerKeyPolicy> key_policy;
    std::optional<std::string> ca_cert_name;
    bool auto_refresh = false;

    MSGPACK_DEFINE(key_filter, key_policy, ca_cert_name, auto_refresh);
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JwtIssuerMetadata);
  DECLARE_JSON_REQUIRED_FIELDS(JwtIssuerMetadata, key_filter);
  DECLARE_JSON_OPTIONAL_FIELDS(
    JwtIssuerMetadata, key_policy, ca_cert_name, auto_refresh);

  using JwtIssuer = std::string;
  using JwtKeyId = std::string;

  using JwtIssuers = kv::Map<JwtIssuer, JwtIssuerMetadata>;
  using JwtPublicSigningKeys = kv::RawCopySerialisedMap<JwtKeyId, Cert>;
  using JwtPublicSigningKeyIssuer =
    kv::RawCopySerialisedMap<JwtKeyId, JwtIssuer>;
}

MSGPACK_ADD_ENUM(ccf::JwtIssuerKeyFilter);
