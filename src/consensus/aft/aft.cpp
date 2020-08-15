// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "aft_network.h"
#include "aft_types.h"
#include "enclave/rpc_map.h"
#include "impl/global_commit_handler.h"
#include "impl/state_machine.h"
#include "kv/tx.h"

namespace aft
{
  std::unique_ptr<IStateMachine> create_state_machine(
    kv::NodeId my_node_id,
    const std::vector<uint8_t>& cert,
    IStore& store,
    std::shared_ptr<EnclaveNetwork> network,
    std::shared_ptr<enclave::RPCMap> rpc_map,
    pbft::RequestsMap& pbft_requests_map)
  {
    return std::make_unique<StateMachine>(
      my_node_id,
      cert,
      create_startup_state_machine(network, rpc_map, store, pbft_requests_map),
      create_global_commit_handler(store),
      network);
  }

  class StoreAdaptor : public IStore
  {
  public:
    StoreAdaptor(std::shared_ptr<kv::Store> x) : x(x) {}

    kv::DeserialiseSuccess deserialise_views(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      kv::Term* term = nullptr,
      kv::Tx* tx = nullptr) override
    {
      auto p = x.lock();
      if (p)
        return p->deserialise_views(data, public_only, term, tx);
      return kv::DeserialiseSuccess::FAILED;
    }

    void compact(kv::Version v) override
    {
      auto p = x.lock();
      if (p)
      {
        p->compact(v);
      }
    }

    kv::Version current_version() override
    {
      auto p = x.lock();
      if (p)
      {
        return p->current_version();
      }
      return kv::NoVersion;
    }

  private:
    std::weak_ptr<kv::Store> x;
  };

  std::unique_ptr<IStore> create_store_adaptor(std::shared_ptr<kv::Store> store)
  {
    return std::make_unique<StoreAdaptor>(store);
  }

}