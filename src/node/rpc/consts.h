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
    static constexpr auto GET_LEADER_INFO = "getLeaderInfo";
  };

  struct ManagementProcs
  {
    static constexpr auto START_NETWORK = "startNetwork";
    static constexpr auto JOIN_NETWORK = "joinNetwork";
    static constexpr auto GET_SIGNED_INDEX = "getSignedIndex";
    static constexpr auto SET_RECOVERY_NODES = "setRecoveryNodes";
    static constexpr auto GET_QUOTES = "getQuotes";
  };

  struct MemberProcs
  {
    static constexpr auto READ = "read";
    static constexpr auto QUERY = "query";

    static constexpr auto COMPLETE = "complete";
    static constexpr auto VOTE = "vote";
    static constexpr auto PROPOSE = "propose";
    static constexpr auto REMOVAL = "removal";

    static constexpr auto ACK = "ack";
    static constexpr auto UPDATE_ACK_NONCE = "updateAckNonce";
  };

  struct NodeProcs
  {
    static constexpr auto JOIN = "join";
  };
}
