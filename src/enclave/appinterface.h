// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/logger.h"
#include "ds/spinlock.h"
#include "kv/kv.h"
#include "kv/kvserialiser.h"
#include "node/networktables.h"
#include "node/rpc/nodeinterface.h"
#include "rpchandler.h"

namespace ccfapp
{
  using Store = kv::Store<kv::KvStoreSerialiser, kv::KvStoreDeserialiser>;

  // TODO(#api): This should return a ccf::UserRpcFrontend
  // SNIPPET_START: rpc_handler
  /** To be implemented by the CCF application
   *
   * @param network Access to the network's tables
   * @param notifier Access to host notification service
   *
   * @return Shared pointer to the application handler instance
   *
   * @see `ccf::RpcFrontend`
   */
  std::shared_ptr<enclave::RpcHandler> get_rpc_handler(
    ccf::NetworkTables& network, ccf::AbstractNotifier& notifier);
  // SNIPPET_END: rpc_handler
}
