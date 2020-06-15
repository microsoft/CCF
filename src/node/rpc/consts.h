// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace ccf
{
  struct GeneralProcs
  {
    static constexpr auto MK_SIGN = "mkSign";

    static constexpr auto API_GET_SCHEMA = "api/schema";
    static constexpr auto API_LIST_METHODS = "api";
    static constexpr auto GET_COMMIT = "commit";
    static constexpr auto GET_METRICS = "metrics";
    static constexpr auto GET_NETWORK_INFO = "network_info";
    static constexpr auto GET_PRIMARY_INFO = "primary_info";
    static constexpr auto GET_RECEIPT = "receipt";
    static constexpr auto GET_TX_STATUS = "tx";
    static constexpr auto VERIFY_RECEIPT = "receipt/verify";
    static constexpr auto WHO = "who";
  };

  struct MemberProcs
  {
    static constexpr auto CREATE = "create";

    static constexpr auto READ = "read";
    static constexpr auto QUERY = "query";

    static constexpr auto COMPLETE = "complete";
    static constexpr auto VOTE = "vote";
    static constexpr auto PROPOSE = "propose";
    static constexpr auto WITHDRAW = "withdraw";

    static constexpr auto ACK = "ack";
    static constexpr auto UPDATE_ACK_STATE_DIGEST = "updateAckStateDigest";

    static constexpr auto GET_ENCRYPTED_RECOVERY_SHARE =
      "getEncryptedRecoveryShare";
    static constexpr auto SUBMIT_RECOVERY_SHARE = "submitRecoveryShare";
  };

  struct NodeProcs
  {
    static constexpr auto JOIN = "join";
    static constexpr auto GET_SIGNED_INDEX = "getSignedIndex";
    static constexpr auto GET_NODE_QUOTE = "getQuote";
    static constexpr auto GET_QUOTES = "getQuotes";
  };
}
