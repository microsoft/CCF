// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <cstdint>
#include <string>

namespace ccf::cose
{
  namespace headers
  {
    // Standardised field: COSE tag.
    static constexpr int64_t COSE_TAG = 18;

    // https://www.iana.org/assignments/cose/cose.xhtml
    static constexpr int64_t COSE_KEY_ALG = 1;
    static constexpr int64_t COSE_KEY_CONTENT_TYPE = 3;
    static constexpr int64_t COSE_KEY_ID = 4;
    static constexpr int64_t COSE_KEY_CWT = 15;
    static constexpr int64_t COSE_KEY_X5CHAIN = 33;

    // https://www.ietf.org/archive/id/draft-ietf-cose-hash-envelope-10.html#section-4
    static constexpr int64_t COSE_KEY_CONTENT_TYPE_HASH_ENVELOPE = 259;

    // Standardised: verifiable data structure.
    // https://www.ietf.org/archive/id/draft-ietf-cose-merkle-tree-proofs-18.html#name-cose-header-parameter
    static constexpr int64_t COSE_KEY_VDS = 395;
    static constexpr int64_t COSE_KEY_VDP = 396;
    static constexpr int64_t COSE_KEY_INCL_PROOF = -1;

    // https://www.iana.org/assignments/cwt/cwt.xhtml
    static constexpr int64_t CWT_CLAIMS_KEY_ISS = 1;
    static constexpr int64_t CWT_CLAIMS_KEY_SUB = 2;

    // Standardised: issued at CWT claim. Value is **PLAIN INTEGER**, as per
    // https://www.rfc-editor.org/rfc/rfc8392#section-2. Quote:
    /* The "NumericDate" term in this specification has the same meaning and
     * processing rules as the JWT "NumericDate" term defined in Section 2 of
     * [RFC7519], except that it is represented as a CBOR numericdate (from
     * Section 2.4.1 of [RFC7049]) instead of a JSON number.  The  encoding is
     * modified so that the leading tag 1 (epoch-based date/time) MUST  be
     * omitted.
     */
    static constexpr int64_t CWT_CLAIMS_KEY_IAT = 6;

    // UVM endorsements: SVN string key.
    static const std::string CWT_CLAIMS_KEY_SVN = "svn";

    // CCF headers nested map key.
    static const std::string COSE_KEY_CCF = "ccf.v1";

    // CCF-specific: last signed TxID.
    static const std::string CCF_CLAIMS_KEY_TXID = "txid";

    // CCF-specific: first TX in the range.
    static const std::string CCF_CLAIMS_KEY_RANGE_BEGIN = "epoch.start.txid";

    // CCF-specific: last TX included in the range.
    static const std::string CCF_CLAIMS_KEY_RANGE_END = "epoch.end.txid";

    static constexpr int64_t COSE_KEY_VDS_CCF_LEDGER_SHA256 = 2;

    // CCF-specific: last signed Merkle root hash in the range.
    static const std::string CCF_CLAIMS_KEY_EPOCH_LAST_MERKLE_ROOT =
      "epoch.end.merkle.root";

    static constexpr auto COSE_VALUE_CONTENT_TYPE_JSON = "application/json";
    static constexpr auto COSE_VALUE_CONTENT_TYPE_OCTET_STREAM =
      "application/octet-stream";
  }
}