// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"
#include "kv_serialiser.h"

#include <array>
#include <chrono>
#include <functional>
#include <limits>
#include <memory>
#include <unordered_set>
#include <vector>

namespace kv
{
  struct PendingTxInfo
  {
    CommitSuccess success;
    TxHistory::RequestID reqid;
    std::vector<uint8_t> data;

    PendingTxInfo(
      CommitSuccess success_,
      TxHistory::RequestID reqid_,
      std::vector<uint8_t>&& data_) :
      success(success_),
      reqid(std::move(reqid_)),
      data(std::move(data_))
    {}
  };

  using PendingTx = std::function<PendingTxInfo()>;

  class MovePendingTx
  {
  private:
    std::vector<uint8_t> data;
    kv::TxHistory::RequestID req_id;

  public:
    MovePendingTx(
      std::vector<uint8_t>&& data_, kv::TxHistory::RequestID req_id_) :
      data(std::move(data_)),
      req_id(std::move(req_id_))
    {}

    MovePendingTx(MovePendingTx&& other) = default;
    MovePendingTx& operator=(MovePendingTx&& other) = default;

    MovePendingTx(const MovePendingTx& other)
    {
      throw std::logic_error(
        "Calling copy constructor of MovePendingTx is not permitted");
    }
    MovePendingTx& operator=(const MovePendingTx& other)
    {
      throw std::logic_error(
        "Calling copy asignment operator of MovePendingTx is not "
        "permitted");
    }

    PendingTxInfo operator()()
    {
      return PendingTxInfo(
        CommitSuccess::OK, std::move(req_id), std::move(data));
    }
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
    virtual CommitSuccess commit(
      Version v, PendingTx pt, bool globally_committable) = 0;
    virtual size_t commit_gap() = 0;
  };

  using S = KvStoreSerialiser;
  using D = KvStoreDeserialiser;

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
    virtual bool is_replicated() = 0;
  };

  class AbstractMap
  {
  public:
    virtual ~AbstractMap() {}
    virtual bool operator==(const AbstractMap& that) const = 0;
    virtual bool operator!=(const AbstractMap& that) const = 0;

    virtual AbstractStore* get_store() = 0;
    virtual AbstractTxView* create_view(Version version) = 0;
    virtual const std::string& get_name() const = 0;
    virtual void compact(Version v) = 0;
    virtual void post_compact() = 0;
    virtual void rollback(Version v) = 0;
    virtual void lock() = 0;
    virtual void unlock() = 0;
    virtual SecurityDomain get_security_domain() = 0;
    virtual bool is_replicated() = 0;
    virtual void clear() = 0;

    virtual AbstractMap* clone(AbstractStore* store) = 0;
    virtual void swap(AbstractMap* map) = 0;
  };
}