// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft.h"
#include "consensus/aft/raft_types.h"

#include <map>
#include <optional>
#include <vector>

namespace aft
{
  class LedgerStubProxy
  {
  protected:
    ccf::NodeId _id;

  public:
    std::vector<std::vector<uint8_t>> ledger;
    uint64_t skip_count = 0;

    LedgerStubProxy(const ccf::NodeId& id) : _id(id) {}

    virtual void put_entry(
      const std::vector<uint8_t>& data,
      bool globally_committable,
      bool force_chunk)
    {
      ledger.push_back(data);
    }

    void skip_entry(const uint8_t*& data, size_t& size)
    {
      skip_count++;
    }

    std::vector<uint8_t> get_entry(const uint8_t*& data, size_t& size)
    {
      const auto entry_size = serialized::read<size_t>(data, size);
      std::vector<uint8_t> entry(data, data + entry_size);
      serialized::skip(data, size, entry_size);
      return entry;
    }

    std::optional<std::vector<uint8_t>> get_entry_by_idx(size_t idx)
    {
      // Ledger indices are 1-based, hence the -1
      if (idx > 0 && idx <= ledger.size())
      {
        return ledger[idx - 1];
      }

      return std::nullopt;
    }

    virtual void truncate(Index idx)
    {
      ledger.resize(idx);
    }

    void reset_skip_count()
    {
      skip_count = 0;
    }

    void commit(Index idx) {}
  };

  class ChannelStubProxy : public ccf::NodeToNode
  {
  public:
    // Capture what is being sent out
    // Using a deque so we can both pop from the front and shuffle
    using MessageList =
      std::deque<std::pair<ccf::NodeId, std::vector<uint8_t>>>;
    MessageList messages;

    ChannelStubProxy() {}

    size_t count_messages_with_type(RaftMsgType type)
    {
      size_t count = 0;
      for (const auto& [nid, m] : messages)
      {
        const uint8_t* data = m.data();
        size_t size = m.size();

        if (serialized::peek<RaftMsgType>(data, size) == type)
        {
          ++count;
        }
      }

      return count;
    }

    std::optional<std::vector<uint8_t>> pop_first(
      RaftMsgType type, ccf::NodeId target)
    {
      for (auto it = messages.begin(); it != messages.end(); ++it)
      {
        const auto [nid, m] = *it;
        const uint8_t* data = m.data();
        size_t size = m.size();

        if (serialized::peek<RaftMsgType>(data, size) == type)
        {
          if (target == nid)
          {
            messages.erase(it);
            return m;
          }
        }
      }

      return std::nullopt;
    }

    void create_channel(
      const ccf::NodeId& peer_id,
      const std::string& peer_hostname,
      const std::string& peer_service,
      size_t message_limit = ccf::Channel::default_message_limit) override
    {}

    void destroy_channel(const ccf::NodeId& peer_id) override {}

    void destroy_all_channels() override {}

    void close_all_outgoing() override {}

    bool send_authenticated(
      const ccf::NodeId& to,
      ccf::NodeMsgType msg_type,
      const uint8_t* data,
      size_t size) override
    {
      std::vector<uint8_t> m(data, data + size);
      messages.emplace_back(to, std::move(m));
      return true;
    }

    bool recv_authenticated(
      const ccf::NodeId& from_node,
      CBuffer cb,
      const uint8_t*& data,
      size_t& size) override
    {
      return true;
    }

    void recv_message(
      const ccf::NodeId& from, const uint8_t* data, size_t size) override
    {}

    void initialize(
      const ccf::NodeId& self_id,
      const crypto::Pem& network_cert,
      crypto::KeyPairPtr node_kp,
      const crypto::Pem& node_cert) override
    {}

    bool send_encrypted(
      const ccf::NodeId& to,
      ccf::NodeMsgType msg_type,
      CBuffer cb,
      const std::vector<uint8_t>& data) override
    {
      return true;
    }

    std::vector<uint8_t> recv_encrypted(
      const ccf::NodeId& fromfpf32,
      CBuffer cb,
      const uint8_t* data,
      size_t size) override
    {
      return {};
    }

    bool recv_authenticated_with_load(
      const ccf::NodeId& from, const uint8_t*& data, size_t& size) override
    {
      return true;
    }
  };

  class LoggingStubStore
  {
  private:
    ccf::NodeId _id;

  public:
    LoggingStubStore(ccf::NodeId id) : _id(id) {}

    // TODO: Move these logging lines as well
    virtual void compact(Index i)
    {
#ifdef STUB_LOG
      std::cout << "  Node" << _id << "->>KV" << _id << ": compact i: " << i
                << std::endl;
#endif
    }

    virtual void rollback(const kv::TxID& tx_id, Term t)
    {
#ifdef STUB_LOG
      std::cout << "  Node" << _id << "->>KV" << _id
                << ": rollback i: " << tx_id.version << " term: " << t;
      std::cout << std::endl;
#endif
    }

    virtual void initialise_term(Term t)
    {
#ifdef STUB_LOG
      std::cout << "  Node" << _id << "->>KV" << _id
                << ": initialise_term t: " << t << std::endl;
#endif
    }

    kv::Version current_version()
    {
      return kv::NoVersion;
    }

    template <kv::ApplyResult AR>
    class ExecutionWrapper : public kv::AbstractExecutionWrapper
    {
    private:
      kv::ConsensusHookPtrs hooks;
      aft::Term term;
      kv::Version index;
      std::vector<uint8_t> entry;

    public:
      ExecutionWrapper(const std::vector<uint8_t>& data_)
      {
        const uint8_t* data = data_.data();
        auto size = data_.size();

        term = serialized::read<aft::Term>(data, size);
        index = serialized::read<kv::Version>(data, size);
        entry = serialized::read(data, size, size);
      }

      kv::ApplyResult apply() override
      {
        return AR;
      }

      kv::ConsensusHookPtrs& get_hooks() override
      {
        return hooks;
      }

      const std::vector<uint8_t>& get_entry() override
      {
        return entry;
      }

      Term get_term() override
      {
        return term;
      }

      kv::Version get_index() override
      {
        return index;
      }

      kv::Version get_max_conflict_version() override
      {
        return kv::NoVersion;
      }

      ccf::PrimarySignature& get_signature() override
      {
        throw std::logic_error("get_signature not implemented");
      }

      aft::Request& get_request() override
      {
        throw std::logic_error("get_request not implemented");
      }

      bool support_async_execution() override
      {
        return false;
      }

      bool is_public_only() override
      {
        return false;
      }

      bool should_rollback_to_last_committed() override
      {
        return false;
      }
    };

    virtual std::unique_ptr<kv::AbstractExecutionWrapper> deserialize(
      const std::vector<uint8_t>& data,
      ConsensusType consensus_type,
      bool public_only = false)
    {
      return std::make_unique<ExecutionWrapper<kv::ApplyResult::PASS>>(data);
    }

    std::shared_ptr<ccf::ProgressTracker> get_progress_tracker()
    {
      return nullptr;
    }
  };

  class LoggingStubStoreSig : public LoggingStubStore
  {
  public:
    LoggingStubStoreSig(ccf::NodeId id) : LoggingStubStore(id) {}

    std::unique_ptr<kv::AbstractExecutionWrapper> deserialize(
      const std::vector<uint8_t>& data,
      ConsensusType consensus_type,
      bool public_only = false) override
    {
      return std::make_unique<
        ExecutionWrapper<kv::ApplyResult::PASS_SIGNATURE>>(data);
    }
  };

  class StubSnapshotter
  {
  public:
    void update(Index, bool)
    {
      // For now, do not test snapshots in unit tests
      return;
    }

    bool record_committable(Index)
    {
      // For now, do not test snapshots in unit tests
      return false;
    }

    void commit(Index, bool)
    {
      // For now, do not test snapshots in unit tests
      return;
    }

    void rollback(Index)
    {
      // For now, do not test snapshots in unit tests
      return;
    }
  };
}