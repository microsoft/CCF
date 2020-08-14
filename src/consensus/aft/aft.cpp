// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "aft_types.h"
#include "impl/state_machine.h"
#include "impl/global_commit_handler.h"
#include "aft_network.h"

namespace aft
{
  std::unique_ptr<IStateMachine> create_state_machine(
    kv::NodeId my_node_id,
    const std::vector<uint8_t>& cert,
    IStore& store,
    std::shared_ptr<EnclaveNetwork> network)
  {
    return std::make_unique<StateMachine>(
      my_node_id,
      cert,
      std::make_unique<StartupStateMachine>(),
      create_global_commit_handler(store),
      network);
  }

  class StoreAdaptor : public IStore
  {
  public:
    StoreAdaptor(std::shared_ptr<kv::Store> x) : x(x) {}

    void compact(kv::Version v)
    {
      auto p = x.lock();
      if (p)
      {
        p->compact(v);
      }
    }

    kv::Version current_version()
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