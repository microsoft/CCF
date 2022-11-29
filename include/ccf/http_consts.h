// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace http
{
  namespace headers
  {
    // All HTTP headers are expected to be lowercase
    static constexpr auto ACCEPT = "accept";
    static constexpr auto ALLOW = "allow";
    static constexpr auto AUTHORIZATION = "authorization";
    static constexpr auto CACHE_CONTROL = "cache-control";
    static constexpr auto CONTENT_LENGTH = "content-length";
    static constexpr auto CONTENT_TYPE = "content-type";
    static constexpr auto DATE = "date";
    static constexpr auto DIGEST = "digest";
    static constexpr auto HOST = "host";
    static constexpr auto LOCATION = "location";
    static constexpr auto RETRY_AFTER = "retry-after";
    static constexpr auto TRAILER = "trailer";
    static constexpr auto WWW_AUTHENTICATE = "www-authenticate";

    static constexpr auto CCF_TX_ID = "x-ms-ccf-transaction-id";
  }

  namespace headervalues
  {
    namespace contenttype
    {
      static constexpr auto JSON = "application/json";
      static constexpr auto MSGPACK = "application/msgpack";
      static constexpr auto TEXT = "text/plain";
      static constexpr auto OCTET_STREAM = "application/octet-stream";
      static constexpr auto GRPC = "application/grpc";
      static constexpr auto COSE = "application/cose";
    }
  }

  namespace auth
  {
    static constexpr auto DIGEST_SHA256 = "SHA-256";

    static constexpr auto SIGN_AUTH_SCHEME = "Signature";
    static constexpr auto SIGN_PARAMS_KEYID = "keyId";
    static constexpr auto SIGN_PARAMS_SIGNATURE = "signature";
    static constexpr auto SIGN_PARAMS_ALGORITHM = "algorithm";
    static constexpr auto SIGN_PARAMS_HEADERS = "headers";
    static constexpr auto SIGN_ALGORITHM_ECDSA_SHA256 = "ecdsa-sha256";
    static constexpr auto SIGN_ALGORITHM_HS_2019 = "hs2019";

    static constexpr auto SIGN_HEADER_REQUEST_TARGET = "(request-target)";

    static constexpr auto SIGN_PARAMS_DELIMITER = ",";
    static constexpr auto SIGN_PARAMS_HEADERS_DELIMITER = " ";

    static constexpr auto BEARER_AUTH_SCHEME = "Bearer";
  }

  static constexpr char const* required_signature_headers[] = {
    auth::SIGN_HEADER_REQUEST_TARGET, headers::DIGEST};
}

namespace http2
{
  namespace headers
  {
    static constexpr auto PATH = ":path";
    static constexpr auto STATUS = ":status";
    static constexpr auto METHOD = ":method";
  }
}