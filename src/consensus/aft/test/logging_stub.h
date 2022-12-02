// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
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

    std::mutex ledger_access;

  public:
    std::vector<std::vector<uint8_t>> ledger;
    uint64_t skip_count = 0;

    LedgerStubProxy(const ccf::NodeId& id) : _id(id) {}

    virtual void init(Index, Index) {}

    virtual void put_entry(
      const std::vector<uint8_t>& original,
      bool globally_committable,
      kv::Term term,
      kv::Version index)
    {
      std::lock_guard<std::mutex> lock(ledger_access);

      // The payload that we eventually deserialise must include the
      // ledger entry as well as the View and Index that identify it. In
      // the real entries, they are nested in the payload and the IV. For
      // test purposes, we just prefix them manually (to mirror the
      // deserialisation in LoggingStubStore::ExecutionWrapper). We also
      // size-prefix, so in a buffer of multiple of these messages we can
      // extract each with get_entry
      const size_t idx = ledger.size() + 1;
      assert(idx == index);
      auto additional_size = sizeof(size_t) + sizeof(term) + sizeof(index);
      std::vector<uint8_t> combined(additional_size);
      {
        uint8_t* data = combined.data();
        serialized::write(
          data,
          additional_size,
          (sizeof(term) + sizeof(index) + original.size()));
        serialized::write(data, additional_size, term);
        serialized::write(data, additional_size, index);
      }

      combined.insert(combined.end(), original.begin(), original.end());

      ledger.push_back(combined);
    }

    void skip_entry(const uint8_t*& data, size_t& size)
    {
      get_entry(data, size);
      ++skip_count;
    }

    static std::vector<uint8_t> get_entry(const uint8_t*& data, size_t& size)
    {
      const auto entry_size = serialized::read<size_t>(data, size);
      std::vector<uint8_t> entry(data, data + entry_size);
      serialized::skip(data, size, entry_size);
      return entry;
    }

    std::optional<std::vector<uint8_t>> get_entry_by_idx(size_t idx)
    {
      std::lock_guard<std::mutex> lock(ledger_access);

      // Ledger indices are 1-based, hence the -1
      if (idx > 0 && idx <= ledger.size())
      {
        return ledger[idx - 1];
      }

      return std::nullopt;
    }

    std::optional<std::vector<uint8_t>> get_raw_entry_by_idx(size_t idx)
    {
      auto data = get_entry_by_idx(idx);
      if (data.has_value())
      {
        // Remove the View and Index that were written during put_entry
        data->erase(
          data->begin(),
          data->begin() + sizeof(size_t) + sizeof(kv::Term) +
            sizeof(kv::Version));
      }

      return data;
    }

    std::optional<std::vector<uint8_t>> get_append_entries_payload(
      const aft::AppendEntries& ae)
    {
      std::vector<uint8_t> payload;

      for (auto idx = ae.prev_idx + 1; idx <= ae.idx; ++idx)
      {
        auto entry_opt = get_entry_by_idx(idx);
        if (!entry_opt.has_value())
        {
          return std::nullopt;
        }

        const auto& entry = *entry_opt;
        payload.insert(payload.end(), entry.begin(), entry.end());
      }

      return payload;
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

    void associate_node_address(
      const ccf::NodeId& peer_id,
      const std::string& peer_hostname,
      const std::string& peer_service) override
    {}

    void close_channel(const ccf::NodeId& peer_id) override {}

    void set_endorsed_node_cert(const crypto::Pem&) override {}

    bool have_channel(const ccf::NodeId& nid) const override
    {
      return true;
    }

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
      std::span<const uint8_t> cb,
      const uint8_t*& data,
      size_t& size) override
    {
      return true;
    }

    bool recv_channel_message(
      const ccf::NodeId& from, const uint8_t* data, size_t size) override
    {
      return true;
    }

    void initialize(
      const ccf::NodeId& self_id,
      const crypto::Pem& service_cert,
      crypto::KeyPairPtr node_kp,
      const std::optional<crypto::Pem>& node_cert = std::nullopt) override
    {}

    bool send_encrypted(
      const ccf::NodeId& to,
      ccf::NodeMsgType msg_type,
      std::span<const uint8_t> cb,
      const std::vector<uint8_t>& data) override
    {
      return true;
    }

    std::vector<uint8_t> recv_encrypted(
      const ccf::NodeId& fromfpf32,
      std::span<const uint8_t> cb,
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

  enum class ReplicatedDataType
  {
    raw = 0,
    reconfiguration = 1
  };
  DECLARE_JSON_ENUM(
    ReplicatedDataType,
    {{ReplicatedDataType::raw, "raw"},
     {ReplicatedDataType::reconfiguration, "reconfiguration"}});

  struct ReplicatedData
  {
    ReplicatedDataType type;
    std::vector<uint8_t> data;
  };
  DECLARE_JSON_TYPE(ReplicatedData);
  DECLARE_JSON_REQUIRED_FIELDS(ReplicatedData, type, data);

  class ConfigurationChangeHook : public kv::ConsensusHook
  {
    kv::Configuration::Nodes
      new_configuration; // Absence of node means that node has been retired
    kv::Version version;

  public:
    ConfigurationChangeHook(
      kv::Configuration::Nodes new_configuration_, kv::Version version_) :
      new_configuration(new_configuration_),
      version(version_)
    {}

    void call(kv::ConfigurableConsensus* consensus) override
    {
      auto configuration = consensus->get_latest_configuration_unsafe();
      std::unordered_set<ccf::NodeId> retired_nodes;
      std::list<Configuration::Nodes::const_iterator> itrs;

      // Remove and track retired nodes
      for (auto it = configuration.begin(); it != configuration.end(); ++it)
      {
        if (new_configuration.find(it->first) == new_configuration.end())
        {
          retired_nodes.emplace(it->first);
          itrs.push_back(it);
        }
      }
      for (auto it : itrs)
      {
        configuration.erase(it);
      }

      // Add new node to configuration
      for (const auto& [node_id, _] : new_configuration)
      {
        configuration[node_id] = {};
      }

      consensus->add_configuration(version, configuration, {}, retired_nodes);
    }
  };

  class LoggingStubStore
  {
  protected:
    ccf::NodeId _id;

  public:
    LoggingStubStore(ccf::NodeId id) : _id(id) {}

    virtual void compact(Index i) {}

    virtual void rollback(const kv::TxID& tx_id, Term t) {}

    virtual void initialise_term(Term t) {}

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
      ccf::ClaimsDigest claims_digest;
      std::optional<crypto::Sha256Hash> commit_evidence_digest = std::nullopt;
      kv::ApplyResult result;

    public:
      ExecutionWrapper(
        const std::vector<uint8_t>& data_,
        const std::optional<kv::TxID>& expected_txid,
        kv::ConsensusHookPtrs&& hooks_) :
        hooks(std::move(hooks_))
      {
        const uint8_t* data = data_.data();
        auto size = data_.size();

        term = serialized::read<aft::Term>(data, size);
        index = serialized::read<kv::Version>(data, size);
        entry = serialized::read(data, size, size);

        result = AR;

        if (expected_txid.has_value())
        {
          if (term != expected_txid->term || index != expected_txid->version)
          {
            result = kv::ApplyResult::FAIL;
          }
        }
      }

      ccf::ClaimsDigest&& consume_claims_digest() override
      {
        return std::move(claims_digest);
      }

      std::optional<crypto::Sha256Hash>&& consume_commit_evidence_digest()
        override
      {
        return std::move(commit_evidence_digest);
      }

      kv::ApplyResult apply(bool track_deletes_on_missing_keys) override
      {
        return result;
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
      bool public_only = false,
      const std::optional<kv::TxID>& expected_txid = std::nullopt)
    {
      kv::ConsensusHookPtrs hooks = {};
      return std::make_unique<ExecutionWrapper<kv::ApplyResult::PASS>>(
        data, expected_txid, std::move(hooks));
    }

    bool flag_enabled(kv::AbstractStore::Flag)
    {
      return false;
    }

    void unset_flag(kv::AbstractStore::Flag) {}
  };

  class LoggingStubStoreSig : public LoggingStubStore
  {
  public:
    LoggingStubStoreSig(ccf::NodeId id) : LoggingStubStore(id) {}

    virtual std::unique_ptr<kv::AbstractExecutionWrapper> deserialize(
      const std::vector<uint8_t>& data,
      ConsensusType consensus_type,
      bool public_only = false,
      const std::optional<kv::TxID>& expected_txid = std::nullopt) override
    {
      kv::ConsensusHookPtrs hooks = {};
      return std::make_unique<
        ExecutionWrapper<kv::ApplyResult::PASS_SIGNATURE>>(
        data, expected_txid, std::move(hooks));
    }
  };

  class LoggingStubStoreSigConfig : public LoggingStubStoreSig
  {
  public:
    LoggingStubStoreSigConfig(ccf::NodeId id) : LoggingStubStoreSig(id) {}

    virtual std::unique_ptr<kv::AbstractExecutionWrapper> deserialize(
      const std::vector<uint8_t>& data,
      ConsensusType consensus_type,
      bool public_only = false,
      const std::optional<kv::TxID>& expected_txid = std::nullopt) override
    {
      // Set reconfiguration hook if there are any new nodes
      // Read wrapping term and version
      auto data_ = data.data();
      auto size = data.size();
      serialized::read<aft::Term>(data_, size);
      auto version = serialized::read<kv::Version>(data_, size);
      ReplicatedData r = nlohmann::json::parse(std::span{data_, size});
      kv::ConsensusHookPtrs hooks = {};
      if (r.type == ReplicatedDataType::reconfiguration)
      {
        kv::Configuration::Nodes configuration = nlohmann::json::parse(r.data);
        auto hook = std::make_unique<aft::ConfigurationChangeHook>(
          configuration, version);
        hooks.push_back(std::move(hook));
      }

      return std::make_unique<
        ExecutionWrapper<kv::ApplyResult::PASS_SIGNATURE>>(
        data, expected_txid, std::move(hooks));
    }
  };

  class StubSnapshotter
  {
  public:
    void update(Index, bool) {}

    void set_last_snapshot_idx(Index idx) {}

    void commit(Index, bool) {}

    void rollback(Index) {}

    void record_serialised_tree(Index version, const std::vector<uint8_t>& tree)
    {}

    void record_signature(
      Index,
      const std::vector<uint8_t>&,
      const ccf::NodeId&,
      const crypto::Pem&)
    {}
  };
}