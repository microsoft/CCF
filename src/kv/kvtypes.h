// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"

#include <array>
#include <functional>
#include <limits>
#include <memory>
#include <vector>

namespace kv
{
  using Version = int64_t;
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

  class Replicator
  {
  public:
    virtual ~Replicator() {}
    virtual bool replicate(
      const std::vector<std::tuple<Version, std::vector<uint8_t>, bool>>&
        entries) = 0;
    virtual Term get_term() = 0; // TODO(#api): this ought to have a more
                                 // abstract name than Term

    virtual Term get_term(Version version) = 0;
    virtual Version get_commit_idx() = 0;

    virtual NodeId leader() = 0;
    virtual NodeId id() = 0;
    virtual bool is_leader() = 0;
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

    using RequestCallbackHandler = std::function<bool(RequestCallbackArgs)>;
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
    virtual void add_response(
      RequestID id, const std::vector<uint8_t>& response) = 0;
    virtual void register_on_request(RequestCallbackHandler func) = 0;
    virtual void register_on_result(ResultCallbackHandler func) = 0;
    virtual void register_on_response(ResponseCallbackHandler func) = 0;
    virtual void clear_on_request() = 0;
    virtual void clear_on_result() = 0;
    virtual void clear_on_response() = 0;
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
    virtual std::shared_ptr<Replicator> get_replicator() = 0;
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