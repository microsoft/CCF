// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace http
{
  namespace headers
  {
    // All HTTP headers are expected to be lowercase
    static constexpr auto AUTHORIZATION = "authorization";
    static constexpr auto DIGEST = "digest";
    static constexpr auto CONTENT_TYPE = "content-type";
    static constexpr auto CONTENT_LENGTH = "content-length";
    static constexpr auto LOCATION = "location";
    static constexpr auto WWW_AUTHENTICATE = "www-authenticate";

    static constexpr auto CCF_COMMIT = "x-ccf-commit";
    static constexpr auto CCF_TERM = "x-ccf-term";
    static constexpr auto CCF_GLOBAL_COMMIT = "x-ccf-global-commit";
    static constexpr auto CCF_READ_ONLY = "x-ccf-read-only";
  }

  namespace headervalues
  {
    namespace contenttype
    {
      static constexpr auto JSON = "application/json";
      static constexpr auto MSGPACK = "application/msgpack";
      static constexpr auto TEXT = "text/plain";
    }
  }

  namespace auth
  {
    static constexpr auto DIGEST_SHA256 = "SHA-256";

    static constexpr auto AUTH_SCHEME = "Signature";
    static constexpr auto SIGN_PARAMS_KEYID = "keyId";
    static constexpr auto SIGN_PARAMS_SIGNATURE = "signature";
    static constexpr auto SIGN_PARAMS_ALGORITHM = "algorithm";
    static constexpr auto SIGN_PARAMS_HEADERS = "headers";
    static constexpr auto SIGN_ALGORITHM_SHA256 = "ecdsa-sha256";

    static constexpr auto SIGN_HEADER_REQUEST_TARGET = "(request-target)";

    static constexpr auto SIGN_PARAMS_DELIMITER = ",";
    static constexpr auto SIGN_PARAMS_HEADERS_DELIMITER = " ";
  }
}