// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"

#include <array>
#include <chrono>
#include <functional>
#include <limits>
#include <memory>
#include <unordered_set>
#include <vector>

namespace kv
{
  // Version indexes modifications to the local kv store. Special value -1
  // indicates deletion
  using Version = int64_t;
  // Term describes an epoch of Versions. It is incremented when global kv's
  // writer(s) changes. Term and Version combined give a unique identifier for
  // all accepted kv modifications. Terms are handled by Raft via the
  // TermHistory
  using Term = uint64_t;
  using NodeId = uint64_t;
  static const Version NoVersion = std::numeric_limits<Version>::min();

  enum CommitSuccess
  {
    OK,
    CONFLICT,
    NO_REPLICATE
  };

  enum SecurityDomain
  {
    PUBLIC, // Public domains indicate the version and always appears, first
    PRIVATE,
    SECURITY_DOMAIN_MAX
  };

  // Note that failed = 0, and all other values are
  // variants of PASS, which allows DeserialiseSuccess
  // to be used as a boolean in code that does not need
  // any detail about what happened on success
  enum DeserialiseSuccess
  {
    FAILED = 0,
    PASS = 1,
    PASS_SIGNATURE = 2
  };

  class TxHistory
  {
  public:
    using RequestID = std::tuple<
      size_t /* Caller ID */,
      size_t /* Client Session ID */,
      size_t /* JSON-RPC sequence number */>;

    struct RequestCallbackArgs
    {
      RequestID rid;
      std::vector<uint8_t> request;
      uint64_t actor;
      uint64_t caller_id;
    };

    struct ResultCallbackArgs
    {
      RequestID rid;
      Version version;
      crypto::Sha256Hash merkle_root;
    };

    struct ResponseCallbackArgs
    {
      RequestID rid;
      std::vector<uint8_t> response;
    };

    using ResultCallbackHandler = std::function<bool(ResultCallbackArgs)>;
    using ResponseCallbackHandler = std::function<bool(ResponseCallbackArgs)>;

    virtual ~TxHistory() {}
    virtual void append(const std::vector<uint8_t>& data) = 0;
    virtual bool verify(Term* term = nullptr) = 0;
    virtual void rollback(Version v) = 0;
    virtual void compact(Version v) = 0;
    virtual void emit_signature() = 0;
    virtual bool add_request(
      kv::TxHistory::RequestID id,
      uint64_t actor,
      uint64_t caller_id,
      const std::vector<uint8_t>& request) = 0;
    virtual void add_result(
      RequestID id, kv::Version version, const std::vector<uint8_t>& data) = 0;
    virtual void add_result(RequestID id, kv::Version version) = 0;
    virtual void add_response(
      RequestID id, const std::vector<uint8_t>& response) = 0;
    virtual void register_on_result(ResultCallbackHandler func) = 0;
    virtual void register_on_response(ResponseCallbackHandler func) = 0;
    virtual void clear_on_result() = 0;
    virtual void clear_on_response() = 0;
    virtual crypto::Sha256Hash get_root() = 0;
  };

  class Consensus
  {
  protected:
    enum State
    {
      Primary,
      Backup,
      Candidate
    };

    State state;
    NodeId local_id;

  public:
    // SeqNo indexes transactions processed by the consensus protocol providing
    // ordering
    using SeqNo = int64_t;
    // View describes an epoch of SeqNos. View is incremented when Consensus's
    // primary changes
    using View = uint64_t;

    struct NodeConf
    {
      NodeId node_id;
      std::string host_name;
      std::string port;
    };

    Consensus(NodeId id) : local_id(id), state(Backup){};
    virtual ~Consensus() {}

    virtual NodeId id()
    {
      return local_id;
    }

    virtual bool is_primary()
    {
      return state == Primary;
    }

    virtual bool is_backup()
    {
      return state == Backup;
    }

    virtual void force_become_primary()
    {
      state = Primary;
    }

    virtual void force_become_primary(
      SeqNo seqno,
      View view,
      const std::vector<Version>& terms,
      SeqNo commit_seqno)
    {
      state = Primary;
    }

    virtual bool replicate(
      const std::vector<std::tuple<SeqNo, std::vector<uint8_t>, bool>>&
        entries) = 0;
    virtual View get_view() = 0;

    virtual View get_view(SeqNo seqno) = 0;
    virtual SeqNo get_commit_seqno() = 0;
    virtual NodeId primary() = 0;

    virtual void recv_message(const uint8_t* data, size_t size) = 0;
    virtual void add_configuration(
      SeqNo seqno,
      std::unordered_set<NodeId> conf,
      const NodeConf& node_conf = {}) = 0;

    virtual bool on_request(const kv::TxHistory::RequestCallbackArgs& args)
    {
      return true;
    }

    virtual void periodic(std::chrono::milliseconds elapsed) {}
    virtual void enable_all_domains() {}
    virtual void resume_replication() {}
    virtual void suspend_replication(kv::Version) {}
  };

  using PendingTx = std::function<
    std::tuple<CommitSuccess, TxHistory::RequestID, std::vector<uint8_t>>()>;

  class AbstractTxEncryptor
  {
  public:
    virtual ~AbstractTxEncryptor() {}
    virtual void encrypt(
      const std::vector<uint8_t>& plain,
      const std::vector<uint8_t>& additional_data,
      std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& cipher,
      kv::Version version) = 0;
    virtual bool decrypt(
      const std::vector<uint8_t>& cipher,
      const std::vector<uint8_t>& additional_data,
      const std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& plain,
      kv::Version version) = 0;
    virtual size_t get_header_length() = 0;
  };

  class AbstractStore
  {
  public:
    virtual ~AbstractStore() {}
    virtual Version next_version() = 0;
    virtual Version current_version() = 0;
    virtual Version commit_version() = 0;
    virtual std::shared_ptr<Consensus> get_consensus() = 0;
    virtual std::shared_ptr<TxHistory> get_history() = 0;
    virtual std::shared_ptr<AbstractTxEncryptor> get_encryptor() = 0;
    virtual DeserialiseSuccess deserialise(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      Term* term = nullptr) = 0;
    virtual void compact(Version v) = 0;
    virtual void rollback(Version v) = 0;
    // TODO (#api): split out?
    virtual CommitSuccess commit(
      Version v, PendingTx pt, bool globally_committable) = 0;
    virtual size_t commit_gap() = 0;
  };

  template <class S, class D>
  class AbstractTxView
  {
  public:
    virtual ~AbstractTxView() {}
    virtual bool has_writes() = 0;
    virtual bool has_changes() = 0;
    virtual bool prepare() = 0;
    virtual void commit(Version v) = 0;
    virtual void post_commit() = 0;
    virtual void serialise(S& s, bool include_reads) = 0;
    virtual bool deserialise(D& d, Version version) = 0;
    virtual Version start_order() = 0;
    virtual Version end_order() = 0;
  };

  template <class S, class D>
  class AbstractMap
  {
  public:
    virtual ~AbstractMap() {}
    virtual bool operator==(const AbstractMap<S, D>& that) const = 0;
    virtual bool operator!=(const AbstractMap<S, D>& that) const = 0;

    virtual AbstractStore* get_store() = 0;
    virtual AbstractTxView<S, D>* create_view(Version version) = 0;
    virtual void compact(Version v) = 0;
    virtual void post_compact() = 0;
    virtual void rollback(Version v) = 0;
    virtual void lock() = 0;
    virtual void unlock() = 0;
    virtual SecurityDomain get_security_domain() = 0;
    virtual void clear() = 0;

    virtual AbstractMap<S, D>* clone(AbstractStore* store) = 0;
    virtual void swap(AbstractMap<S, D>* map) = 0;
  };
}