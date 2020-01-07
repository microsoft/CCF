// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/pbft/pbftpreprepares.h"
#include "ds/ringbuffer_types.h"
#include "kv/kvtypes.h"

namespace pbft
{
  using Index = int64_t;
  using Term = uint64_t;
  using NodeId = uint64_t;
  using Node2NodeMsg = uint64_t;
  using CallerId = uint64_t;

  enum PbftMsgType : Node2NodeMsg
  {
    pbft_message = 1000,
  };

#pragma pack(push, 1)
  struct PbftHeader
  {
    PbftMsgType msg;
    NodeId from_node;
  };
#pragma pack(pop)

  class Store
  {
  public:
    virtual ~Store() {}
    virtual void compact(Index v) = 0;
    virtual void rollback(Index v) = 0;
    virtual kv::Version current_version() = 0;
    virtual void commit_pre_prepare(
      const pbft::PrePrepare& pp,
      pbft::PrePreparesMap& pbft_pre_prepares_map) = 0;
  };

  template <typename T>
  class Adaptor : public pbft::Store
  {
  private:
    std::weak_ptr<T> x;

  public:
    Adaptor(std::shared_ptr<T> x) : x(x) {}

    void commit_pre_prepare(
      const pbft::PrePrepare& pp, pbft::PrePreparesMap& pbft_pre_prepares_map)
    {
      while (true)
      {
        auto p = x.lock();
        if (p)
        {
          auto version = p->next_version();
          LOG_TRACE_FMT("Storing pre prepare at seqno {}", pp.seqno);
          auto success = p->commit(
            version,
            [&]() {
              ccf::Store::Tx tx(version);
              auto pp_view = tx.get_view(pbft_pre_prepares_map);
              pp_view->put(0, pp);
              return tx.commit_reserved();
            },
            false);
          if (success == kv::CommitSuccess::OK)
          {
            break;
          }
        }
      }
    }

    void compact(Index v)
    {
      auto p = x.lock();
      if (p)
      {
        p->compact(v);
      }
    }

    void rollback(Index v)
    {
      auto p = x.lock();
      if (p)
      {
        p->rollback(v);
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
  };
}