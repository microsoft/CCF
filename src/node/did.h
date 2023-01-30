// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/jwk.h"
#include "ccf/ds/json.h"

#include <string>
#include <vector>

namespace ccf::did
{
  // From https://www.w3.org/TR/did-core.
  // Note that the types defined in this file do not exhaustively cover
  // all fields and types from the spec.
  struct DIDDocumentVerificationMethod
  {
    std::string id;
    std::string type;
    std::string controller;
    std::optional<crypto::JsonWebKeyRSAPublic> public_key_jwk =
      std::nullopt; // Note: Only supports RSA for now

    bool operator==(const DIDDocumentVerificationMethod&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(DIDDocumentVerificationMethod);
  DECLARE_JSON_REQUIRED_FIELDS(
    DIDDocumentVerificationMethod, id, type, controller);
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
    DIDDocumentVerificationMethod, public_key_jwk, "publicKeyJwk");

  struct DIDDocument
  {
    std::string id;
    std::string context;
    std::string type;
    std::vector<DIDDocumentVerificationMethod> verification_method = {};
    nlohmann::json assertion_method = {};

    bool operator==(const DIDDocument&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(DIDDocument);
  DECLARE_JSON_REQUIRED_FIELDS(DIDDocument, id);
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
    DIDDocument,
    context,
    "@context",
    type,
    "type",
    verification_method,
    "verificationMethod",
    assertion_method,
    "assertionMethod");
}