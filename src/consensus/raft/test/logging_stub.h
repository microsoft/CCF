// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/raft/raft.h"
#include "consensus/raft/raft_types.h"

#include <map>
#include <vector>

namespace raft
{
  class LedgerStubProxy
  {
  private:
    NodeId _id;

  public:
    std::vector<std::shared_ptr<std::vector<uint8_t>>> ledger;
    uint64_t skip_count = 0;

    LedgerStubProxy(NodeId id) : _id(id) {}

    void put_entry(const std::vector<uint8_t>& data, bool globally_committable)
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

  class ChannelStubProxy
  {
  public:
    // Capture what is being sent out
    std::list<std::pair<NodeId, RequestVote>> sent_request_vote;
    std::list<std::pair<NodeId, AppendEntries>> sent_append_entries;
    std::list<std::pair<NodeId, RequestVoteResponse>>
      sent_request_vote_response;
    std::list<std::pair<NodeId, AppendEntriesResponse>>
      sent_append_entries_response;

    ChannelStubProxy() {}

    void create_channel(
      NodeId peer_id,
      const std::string& peer_hostname,
      const std::string& peer_service)
    {}

    void destroy_channel(NodeId peer_id) {}

    void close_all_outgoing() {}

    void send_authenticated(
      const ccf::NodeMsgType& msg_type, NodeId to, const RequestVote& data)
    {
      sent_request_vote.push_back(std::make_pair(to, data));
    }

    void send_authenticated(
      const ccf::NodeMsgType& msg_type, NodeId to, const AppendEntries& data)
    {
      sent_append_entries.push_back(std::make_pair(to, data));
    }

    void send_authenticated(
      const ccf::NodeMsgType& msg_type,
      NodeId to,
      const RequestVoteResponse& data)
    {
      sent_request_vote_response.push_back(std::make_pair(to, data));
    }

    void send_authenticated(
      const ccf::NodeMsgType& msg_type,
      NodeId to,
      const AppendEntriesResponse& data)
    {
      sent_append_entries_response.push_back(std::make_pair(to, data));
    }

    size_t sent_msg_count() const
    {
      return sent_request_vote.size() + sent_request_vote_response.size() +
        sent_append_entries.size() + sent_append_entries_response.size();
    }

    template <class T>
    const T& recv_authenticated(const uint8_t*& data, size_t& size)
    {
      return serialized::overlay<T>(data, size);
    }
  };

  class LoggingStubStore
  {
  private:
    raft::NodeId _id;

  public:
    LoggingStubStore(raft::NodeId id) : _id(id) {}

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

    virtual kv::DeserialiseSuccess deserialise(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      Term* term = nullptr)
    {
      return kv::DeserialiseSuccess::PASS;
    }
  };

  class LoggingStubStoreSig : public LoggingStubStore
  {
  public:
    LoggingStubStoreSig(raft::NodeId id) : LoggingStubStore(id) {}

    kv::DeserialiseSuccess deserialise(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      Term* term = nullptr) override
    {
      return kv::DeserialiseSuccess::PASS_SIGNATURE;
    }
  };
}