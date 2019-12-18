// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "../entities.h"
#include "jsonrpc.h"

namespace ccf
{
  static constexpr auto COMMIT = "commit";
  static constexpr auto GLOBAL_COMMIT = "global_commit";
  static constexpr auto TERM = "term";
  static constexpr auto CERT = "cert";
  static constexpr auto PUBK = "pubk";
  static constexpr auto TABLE = "table";
  static constexpr auto OBJECTS = "objects";

  struct GeneralProcs
  {
    static constexpr auto GET_COMMIT = "getCommit";
    static constexpr auto GET_METRICS = "getMetrics";
    static constexpr auto MK_SIGN = "mkSign";
    static constexpr auto GET_PRIMARY_INFO = "getPrimaryInfo";
    static constexpr auto GET_NETWORK_INFO = "getNetworkInfo";
    static constexpr auto WHO_AM_I = "whoAmI";
    static constexpr auto WHO_IS = "whoIs";
    static constexpr auto LIST_METHODS = "listMethods";
    static constexpr auto GET_SCHEMA = "getSchema";
    static constexpr auto GET_RECEIPT = "getReceipt";
    static constexpr auto VERIFY_RECEIPT = "verifyReceipt";
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
    static constexpr auto UPDATE_ACK_NONCE = "updateAckNonce";
  };

  struct NodeProcs
  {
    static constexpr auto JOIN = "join";
    static constexpr auto GET_SIGNED_INDEX = "getSignedIndex";
    static constexpr auto GET_QUOTES = "getQuotes";
  };
}
