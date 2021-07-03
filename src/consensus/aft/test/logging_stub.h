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
  private:
    ccf::NodeId _id;

  public:
    std::vector<std::shared_ptr<std::vector<uint8_t>>> ledger;
    uint64_t skip_count = 0;

    LedgerStubProxy(const ccf::NodeId& id) : _id(id) {}

    void put_entry(
      const std::vector<uint8_t>& data,
      bool globally_committable,
      bool force_chunk)
    {
#ifdef STUB_LOG
      std::cout << "  Node" << _id << "->>Ledger" << _id
                << ": put s: " << data.size() << std::endl;
#endif

      auto size = data.size();
      auto buffer = std::make_shared<std::vector<uint8_t>>(size);
      auto ptr = buffer->data();

      serialized::write(ptr, size, data.data(), data.size());

      ledger.push_back(buffer);
    }

    void skip_entry(const uint8_t*& data, size_t& size)
    {
      skip_count++;
    }

    std::vector<uint8_t> get_entry(const uint8_t*& data, size_t& size)
    {
      return {data, data + size};
    }

    void truncate(Index idx)
    {
      ledger.resize(idx);
#ifdef STUB_LOG
      std::cout << "  KV" << _id << "->>Node" << _id << ": truncate i: " << idx
                << std::endl;
#endif
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
    std::list<std::pair<ccf::NodeId, RequestVote>> sent_request_vote;
    std::list<std::pair<ccf::NodeId, AppendEntries>> sent_append_entries;
    std::list<std::pair<ccf::NodeId, RequestVoteResponse>>
      sent_request_vote_response;
    std::list<std::pair<ccf::NodeId, AppendEntriesResponse>>
      sent_append_entries_response;

    ChannelStubProxy() {}

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
      switch (serialized::peek<RaftMsgType>(data, size))
      {
        case aft::RaftMsgType::raft_append_entries:
          sent_append_entries.push_back(
            std::make_pair(to, *(AppendEntries*)(data)));
          break;
        case aft::RaftMsgType::raft_request_vote:
          sent_request_vote.push_back(
            std::make_pair(to, *(RequestVote*)(data)));
          break;
        case aft::RaftMsgType::raft_request_vote_response:
          sent_request_vote_response.push_back(
            std::make_pair(to, *(RequestVoteResponse*)(data)));
          break;
        case aft::RaftMsgType::raft_append_entries_response:
          sent_append_entries_response.push_back(
            std::make_pair(to, *(AppendEntriesResponse*)(data)));
          break;
        default:
          throw std::logic_error("unexpected response type");
      }

      return true;
    }

    size_t sent_msg_count() const
    {
      return sent_request_vote.size() + sent_request_vote_response.size() +
        sent_append_entries.size() + sent_append_entries_response.size();
    }

    bool recv_authenticated(
      const ccf::NodeId& from_node,
      CBuffer cb,
      const uint8_t*& data,
      size_t& size) override
    {
      return true;
    }

    void recv_message(const ccf::NodeId& from, OArray&& oa) override {}

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

    virtual void compact(Index i)
    {
#ifdef STUB_LOG
      std::cout << "  Node" << _id << "->>KV" << _id << ": compact i: " << i
                << std::endl;
#endif
    }

    virtual void rollback(Index i, std::optional<Term> t = std::nullopt)
    {
#ifdef STUB_LOG
      std::cout << "  Node" << _id << "->>KV" << _id << ": rollback i: " << i;
      if (t.has_value())
        std::cout << " term: " << t.value();
      std::cout << std::endl;
#endif
    }

    virtual void set_term(Term t)
    {
#ifdef STUB_LOG
      std::cout << "  Node" << _id << "->>KV" << _id << ": set_term t: " << t
                << std::endl;
#endif
    }

    virtual kv::ApplyResult apply(
      const std::vector<uint8_t>& data,
      kv::ConsensusHookPtrs& hooks,
      bool public_only = false,
      Term* term = nullptr)
    {
      return kv::ApplyResult::PASS;
    }

    kv::Version current_version()
    {
      return kv::NoVersion;
    }

    virtual kv::ApplyResult deserialise_views(
      const std::vector<uint8_t>& data,
      kv::ConsensusHookPtrs& hooks,
      bool public_only = false,
      kv::Term* term = nullptr,
      kv::Version* index = nullptr,
      kv::Tx* tx = nullptr,
      ccf::PrimarySignature* sig = nullptr)
    {
      return kv::ApplyResult::PASS;
    }

    class ExecutionWrapper : public kv::AbstractExecutionWrapper
    {
    private:
      const std::vector<uint8_t>& data;
      kv::ConsensusHookPtrs hooks;

    public:
      ExecutionWrapper(const std::vector<uint8_t>& data_) : data(data_) {}

      kv::ApplyResult apply() override
      {
        return kv::ApplyResult::PASS;
      }

      kv::ConsensusHookPtrs& get_hooks() override
      {
        return hooks;
      }

      const std::vector<uint8_t>& get_entry() override
      {
        return data;
      }

      Term get_term() override
      {
        return 0;
      }

      kv::Version get_index() override
      {
        return 0;
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
      return std::make_unique<ExecutionWrapper>(data);
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

    kv::ApplyResult apply(
      const std::vector<uint8_t>& data,
      kv::ConsensusHookPtrs& hooks,
      bool public_only = false,
      Term* term = nullptr) override
    {
      return kv::ApplyResult::PASS_SIGNATURE;
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