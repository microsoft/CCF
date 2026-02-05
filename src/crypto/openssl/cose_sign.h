// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/cbor.h"
#include "crypto/openssl/ec_key_pair.h"

#include <openssl/ossl_typ.h>
#include <string>

namespace ccf::crypto
{
  struct COSESignError : public std::runtime_error
  {
    COSESignError(const std::string& msg) : std::runtime_error(msg) {}
  };

  /* Sign a cose_sign1 payload with custom protected headers as strings, where
       - key: integer label to be assigned in a COSE value
       - value: string behind the label.

    Labels have to be unique. For standardised labels list check
    https://www.iana.org/assignments/cose/cose.xhtml#header-parameters.
   */
  std::vector<uint8_t> cose_sign1(
    const ECKeyPair_OpenSSL& key,
    ccf::cbor::Value protected_headers,
    std::span<const uint8_t> payload,
    bool detached_payload = true);
}
