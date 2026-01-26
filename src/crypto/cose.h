// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <cstdint>
#include <string>

namespace ccf
{
  namespace cose
  {
    namespace header
    {
      namespace iana // https://www.iana.org/assignments/cose/cose.xhtml
      {
        static constexpr int64_t ALG = 1;
        static constexpr int64_t CONTENT_TYPE = 3;
        static constexpr int64_t KID = 4;
        static constexpr int64_t CWT_CLAIMS = 15;
        static constexpr int64_t X5CHAIN = 33;
        static constexpr int64_t PREIMAGE_CONTENT_TYPE = 259;
        static constexpr int64_t VDS = 395;
        static constexpr int64_t VDP = 396;

        // https://www.ietf.org/archive/id/draft-ietf-cose-merkle-tree-proofs-18.html#name-cose-header-parameter
        static constexpr int64_t INCLUSION_PROOFS = -1;
      }
      namespace custom
      {
        static constexpr std::string_view CCF_V1 = "ccf.v1";
        static constexpr std::string_view TX_ID = "txid";
        static constexpr std::string_view TX_RANGE_BEGIN = "epoch.start.txid";
        static constexpr std::string_view TX_RANGE_END = "epoch.end.txid";
        static constexpr std::string_view EPOCH_LAST_MERKLE_ROOT =
          "epoch.end.merkle.root";
      }
    }
    namespace value
    {
      // https://www.ietf.org/archive/id/draft-birkholz-cose-receipts-ccf-profile-05.html#section-2
      static constexpr int64_t CCF_LEDGER_SHA256 = 2;

      static constexpr std::string_view CT_JSON = "application/json";
      static constexpr std::string_view CT_OCTET_STREAM =
        "application/octet-stream";
    }
  }
  namespace cwt
  {
    namespace header
    {
      namespace iana // https://www.iana.org/assignments/cwt/cwt.xhtml
      {
        static constexpr int64_t ISS = 1;
        static constexpr int64_t SUB = 2;

        /* Value is **PLAIN INTEGER**, as per
         * https://www.rfc-editor.org/rfc/rfc8392#section-2. Quote:
         *
         * The "NumericDate" term in this specification has the same meaning and
         * processing rules as the JWT "NumericDate" term defined in Section 2
         * of [RFC7519], except that it is represented as a CBOR numericdate
         * (from Section 2.4.1 of [RFC7049]) instead of a JSON number.  The
         * encoding is modified so that the leading tag 1 (epoch-based
         * date/time) MUST  be omitted.
         */
        static constexpr int64_t IAT = 6;
      }
      namespace custom
      {
        static constexpr std::string_view SVN = "svn";
      }
    }
  }
}
