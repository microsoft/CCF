// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/consensus_types.h"
#include "consensus/pbft/pbft_new_views.h"
#include "consensus/pbft/pbft_pre_prepares.h"
#include "ds/ring_buffer_types.h"
#include "kv/tx.h"
#include "node/signatures.h"

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
    encrypted_pbft_message,
    pbft_append_entries
  };

#pragma pack(push, 1)
  struct PbftHeader
  {
    PbftMsgType msg;
    NodeId from_node;
  };

  struct AppendEntries : consensus::ConsensusHeader<PbftMsgType>,
                         consensus::AppendEntriesIndex
  {};

#pragma pack(pop)

  template <typename S>
  class Store
  {
  public:
    virtual ~Store() {}
    virtual S deserialise_views(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      Term* term = nullptr,
      kv::Tx* tx = nullptr) = 0;
    virtual void compact(Index v) = 0;
    virtual void rollback(Index v) = 0;
    virtual kv::Version current_version() = 0;
    virtual kv::Version commit_pre_prepare(
      const pbft::PrePrepare& pp,
      pbft::PrePreparesMap& pbft_pre_prepares_map,
      CBuffer root,
      ccf::Signatures& signatures) = 0;
    virtual kv::Version commit_tx(
      kv::Tx& tx, CBuffer root, ccf::Signatures& signatures) = 0;
    virtual void commit_new_view(
      const pbft::NewView& new_view, pbft::NewViewsMap& pbft_new_views_map) = 0;
    virtual std::shared_ptr<kv::AbstractTxEncryptor> get_encryptor() = 0;
  };

  template <typename T, typename S>
  class Adaptor : public pbft::Store<S>
  {
  private:
    std::weak_ptr<T> x;

  public:
    Adaptor(std::shared_ptr<T> x) : x(x) {}

    S deserialise_views(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      Term* term = nullptr,
      kv::Tx* tx = nullptr)
    {
      auto p = x.lock();
      if (p)
        return p->deserialise_views(data, public_only, term, tx);

      return S::FAILED;
    }

    kv::Version commit_pre_prepare(
      const pbft::PrePrepare& pp,
      pbft::PrePreparesMap& pbft_pre_prepares_map,
      CBuffer root,
      ccf::Signatures& signatures)
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
              kv::Tx tx(version);
              auto pp_view = tx.get_view(pbft_pre_prepares_map);
              pp_view->put(0, pp);
              auto sig_view = tx.get_view(signatures);
              ccf::Signature sig_value(root);
              sig_view->put(0, sig_value);
              return tx.commit_reserved();
            },
            false);
          if (success == kv::CommitSuccess::OK)
          {
            return version;
          }
        }
      }
    }

    kv::Version commit_tx(kv::Tx& tx, CBuffer root, ccf::Signatures& signatures)
    {
      while (true)
      {
        auto p = x.lock();
        if (p)
        {
          auto sig_view = tx.get_view(signatures);
          ccf::Signature sig_value(root);
          sig_view->put(0, sig_value);
          auto success = tx.commit();
          if (success == kv::CommitSuccess::OK)
          {
            return tx.get_version();
          }
        }
      }
    }

    void commit_new_view(
      const pbft::NewView& new_view, pbft::NewViewsMap& pbft_new_views_map)
    {
      while (true)
      {
        auto p = x.lock();
        if (p)
        {
          auto version = p->next_version();
          LOG_TRACE_FMT(
            "Storing new view message at view {} for node {}",
            new_view.view,
            new_view.node_id);
          auto success = p->commit(
            version,
            [&]() {
              kv::Tx tx(version);
              auto vc_view = tx.get_view(pbft_new_views_map);
              vc_view->put(0, new_view);
              return tx.commit_reserved();
            },
            false);
          if (success == kv::CommitSuccess::OK)
          {
            return;
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
      while (true)
      {
        auto p = x.lock();
        if (p)
        {
          p->rollback(v);
          break;
        }
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

    std::shared_ptr<kv::AbstractTxEncryptor> get_encryptor()
    {
      while (true)
      {
        auto p = x.lock();
        if (p)
        {
          return p->get_encryptor();
        }
      }
    }
  };

  using PbftStore = pbft::Store<kv::DeserialiseSuccess>;
}