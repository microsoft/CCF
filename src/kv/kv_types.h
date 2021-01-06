// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"
#include "ds/nonstd.h"
#include "enclave/consensus_type.h"
#include "serialiser_declare.h"
#include "tls/pem.h"

#include <array>
#include <chrono>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace ccf
{
  struct PrimarySignature;
}

namespace kv
{
  // Version indexes modifications to the local kv store. Negative values
  // indicate deletion
  using Version = int64_t;
  static const Version NoVersion = std::numeric_limits<Version>::min();

  static bool is_deleted(Version version)
  {
    return version < 0;
  }

  // Term describes an epoch of Versions. It is incremented when global kv's
  // writer(s) changes. Term and Version combined give a unique identifier for
  // all accepted kv modifications. Terms are handled by Consensus via the
  // TermHistory
  using Term = int64_t;
  using NodeId = uint64_t;

  struct TxID
  {
    Term term = 0;
    Version version = 0;
    MSGPACK_DEFINE(term, version);
  };
  DECLARE_JSON_TYPE(TxID);
  DECLARE_JSON_REQUIRED_FIELDS(TxID, term, version)

  using BatchVector = std::vector<
    std::tuple<kv::Version, std::shared_ptr<std::vector<uint8_t>>, bool>>;

  enum CommitSuccess
  {
    OK,
    CONFLICT,
    NO_REPLICATE
  };

  enum SecurityDomain
  {
    PUBLIC, // Public domain indicates the version and always appears first
    PRIVATE,
    SECURITY_DOMAIN_MAX
  };

  enum AccessCategory
  {
    INTERNAL,
    GOVERNANCE,
    APPLICATION
  };

  constexpr auto public_domain_prefix = "public:";

  static inline SecurityDomain get_security_domain(const std::string& name)
  {
    if (nonstd::starts_with(name, public_domain_prefix))
    {
      return SecurityDomain::PUBLIC;
    }

    return SecurityDomain::PRIVATE;
  }

  static inline std::pair<SecurityDomain, AccessCategory> parse_map_name(
    const std::string& name)
  {
    constexpr auto internal_category_prefix = "ccf.internal.";
    constexpr auto governance_category_prefix = "ccf.gov.";
    constexpr auto reserved_category_prefix = "ccf.";

    auto security_domain = SecurityDomain::PRIVATE;
    const auto core_name = nonstd::remove_prefix(name, public_domain_prefix);
    if (core_name != name)
    {
      security_domain = SecurityDomain::PUBLIC;
    }

    auto access_category = AccessCategory::APPLICATION;
    if (nonstd::starts_with(core_name, internal_category_prefix))
    {
      access_category = AccessCategory::INTERNAL;
    }
    else if (nonstd::starts_with(core_name, governance_category_prefix))
    {
      access_category = AccessCategory::GOVERNANCE;
    }
    else if (nonstd::starts_with(core_name, reserved_category_prefix))
    {
      throw std::logic_error(fmt::format(
        "Map name '{}' includes disallowed reserved prefix '{}'",
        name,
        reserved_category_prefix));
    }

    return {security_domain, access_category};
  }

  // Note that failed = 0, and all other values are variants of PASS, which
  // allows DeserialiseSuccess to be used as a boolean in code that does not
  // need any detail about what happened on success
  enum DeserialiseSuccess
  {
    FAILED = 0,
    PASS = 1,
    PASS_SIGNATURE = 2,
    PASS_BACKUP_SIGNATURE = 3,
    PASS_BACKUP_SIGNATURE_SEND_ACK = 4,
    PASS_NONCES = 5,
    PASS_NEW_VIEW = 6,
    PASS_SNAPSHOT_EVIDENCE = 7
  };

  enum ReplicateType
  {
    ALL = 0,
    NONE,
    SOME
  };

  class KvSerialiserException : public std::exception
  {
  private:
    std::string msg;

  public:
    KvSerialiserException(const std::string& msg_) : msg(msg_) {}

    virtual const char* what() const throw()
    {
      return msg.c_str();
    }
  };

  class Syncable
  {
  public:
    virtual void rollback(Version v) = 0;
    virtual void compact(Version v) = 0;
  };

  class TxHistory : public Syncable
  {
  public:
    using RequestID = std::tuple<
      size_t /* Client Session ID */,
      size_t /* Request sequence number */>;

    struct RequestCallbackArgs
    {
      RequestID rid;
      std::vector<uint8_t> request;
      std::vector<uint8_t> caller_cert;
      uint8_t frame_format;
    };

    struct ResultCallbackArgs
    {
      RequestID rid;
      Version version;
      crypto::Sha256Hash replicated_state_merkle_root;
    };

    struct ResponseCallbackArgs
    {
      RequestID rid;
      std::vector<uint8_t> response;
    };

    enum class Result
    {
      FAIL = 0,
      OK,
      SEND_SIG_RECEIPT_ACK,
      SEND_REPLY_AND_NONCE
    };

    using ResultCallbackHandler = std::function<bool(ResultCallbackArgs)>;
    using ResponseCallbackHandler = std::function<bool(ResponseCallbackArgs)>;

    virtual ~TxHistory() {}
    virtual void append(const std::vector<uint8_t>& replicated) = 0;
    virtual void append(const uint8_t* replicated, size_t replicated_size) = 0;
    virtual Result verify_and_sign(
      ccf::PrimarySignature& signature, Term* term = nullptr) = 0;
    virtual bool verify(
      Term* term = nullptr, ccf::PrimarySignature* sig = nullptr) = 0;
    virtual void try_emit_signature() = 0;
    virtual void emit_signature() = 0;
    virtual crypto::Sha256Hash get_replicated_state_root() = 0;
    virtual std::vector<uint8_t> get_receipt(Version v) = 0;
    virtual bool verify_receipt(const std::vector<uint8_t>& receipt) = 0;
    virtual bool init_from_snapshot(
      const std::vector<uint8_t>& hash_at_snapshot) = 0;
    virtual std::vector<uint8_t> get_raw_leaf(uint64_t index) = 0;

    virtual bool add_request(
      kv::TxHistory::RequestID id,
      const std::vector<uint8_t>& caller_cert,
      const std::vector<uint8_t>& request,
      uint8_t frame_format) = 0;
    virtual void add_result(
      RequestID id,
      kv::Version version,
      const std::vector<uint8_t>& replicated) = 0;
    virtual void add_pending(
      RequestID id,
      kv::Version version,
      std::shared_ptr<std::vector<uint8_t>> replicated) = 0;
    virtual void flush_pending() = 0;
    virtual void add_result(
      RequestID id,
      kv::Version version,
      const uint8_t* replicated,
      size_t replicated_size) = 0;
    virtual void add_result(RequestID id, kv::Version version) = 0;
    virtual void add_response(
      RequestID id, const std::vector<uint8_t>& response) = 0;
    virtual void register_on_result(ResultCallbackHandler func) = 0;
    virtual void register_on_response(ResponseCallbackHandler func) = 0;
    virtual void clear_on_result() = 0;
    virtual void clear_on_response() = 0;
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
    using View = int64_t;

    struct Configuration
    {
      struct NodeInfo
      {
        std::string hostname;
        std::string port;
        tls::Pem cert = {};

        NodeInfo() = default;

        NodeInfo(
          const std::string& hostname_,
          const std::string& port_,
          const tls::Pem& cert_ = {}) :
          hostname(hostname_),
          port(port_),
          cert(cert_)
        {}
      };

      using Nodes = std::unordered_map<NodeId, NodeInfo>;

      SeqNo idx;
      Nodes nodes;
    };

    Consensus(NodeId id) : state(Backup), local_id(id) {}
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
      SeqNo, View, const std::vector<SeqNo>&, SeqNo)
    {
      state = Primary;
    }

    virtual void init_as_backup(SeqNo, View, const std::vector<SeqNo>&)
    {
      state = Backup;
    }

    virtual bool replicate(const BatchVector& entries, View view) = 0;
    virtual std::pair<View, SeqNo> get_committed_txid() = 0;
    virtual std::optional<std::pair<View, SeqNo>> get_signable_txid() = 0;

    virtual View get_view(SeqNo seqno) = 0;
    virtual View get_view() = 0;
    virtual std::vector<SeqNo> get_view_history(SeqNo) = 0;
    virtual void initialise_view_history(const std::vector<SeqNo>&) = 0;
    virtual SeqNo get_committed_seqno() = 0;
    virtual NodeId primary() = 0;
    virtual std::set<NodeId> active_nodes() = 0;

    virtual void recv_message(OArray&& oa) = 0;
    virtual void add_configuration(
      SeqNo seqno, const Configuration::Nodes& conf) = 0;
    virtual Configuration::Nodes get_latest_configuration() const = 0;

    virtual bool on_request(const kv::TxHistory::RequestCallbackArgs&)
    {
      return true;
    }

    virtual void periodic(std::chrono::milliseconds) {}
    virtual void periodic_end() {}

    struct Statistics
    {
      uint32_t time_spent = 0;
      uint32_t count_num_samples = 0;
      uint32_t tx_count = 0;
    };
    virtual Statistics get_statistics()
    {
      return Statistics();
    }
    virtual void enable_all_domains() {}

    virtual uint32_t node_count() = 0;
    virtual void emit_signature() = 0;
    virtual ConsensusType type() = 0;
  };

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
      std::vector<uint8_t>&& data_, kv::TxHistory::RequestID&& req_id_) :
      data(std::move(data_)),
      req_id(std::move(req_id_))
    {}

    PendingTxInfo operator()()
    {
      return PendingTxInfo(
        CommitSuccess::OK, std::move(req_id), std::move(data));
    }
  };

  class AbstractTxEncryptor : public Syncable
  {
  public:
    virtual ~AbstractTxEncryptor() {}
    virtual void encrypt(
      const std::vector<uint8_t>& plain,
      const std::vector<uint8_t>& additional_data,
      std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& cipher,
      kv::Version version,
      bool is_snapshot = false) = 0;
    virtual bool decrypt(
      const std::vector<uint8_t>& cipher,
      const std::vector<uint8_t>& additional_data,
      const std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& plain,
      kv::Version version) = 0;
    virtual void set_iv_id(size_t id) = 0;

    virtual void compact(kv::Version version) = 0;
    virtual void rollback(kv::Version version) = 0;

    virtual size_t get_header_length() = 0;
    virtual void update_encryption_key(
      Version version, const std::vector<uint8_t>& key) = 0;
  };

  using EncryptorPtr = std::shared_ptr<AbstractTxEncryptor>;

  class AbstractChangeSet
  {
  public:
    virtual ~AbstractChangeSet() = default;

    virtual bool has_writes() const = 0;
  };

  class AbstractCommitter
  {
  public:
    virtual ~AbstractCommitter() = default;

    virtual bool has_writes() = 0;
    virtual bool prepare() = 0;
    virtual void commit(Version v) = 0;
    virtual void post_commit() = 0;
  };

  class AbstractTxView
  {
  public:
    virtual ~AbstractTxView() = default;
  };

  struct NamedMap
  {
  protected:
    std::string name;

  public:
    NamedMap(const std::string& s) : name(s) {}
    virtual ~NamedMap() = default;

    const std::string& get_name() const
    {
      return name;
    }
  };

  class AbstractStore;
  class AbstractMap : public std::enable_shared_from_this<AbstractMap>,
                      public NamedMap
  {
  public:
    class Snapshot
    {
    public:
      virtual ~Snapshot() = default;
      virtual void serialise(KvStoreSerialiser& s) = 0;
      virtual SecurityDomain get_security_domain() = 0;
    };

    using NamedMap::NamedMap;
    virtual ~AbstractMap() {}
    virtual bool operator==(const AbstractMap& that) const = 0;
    virtual bool operator!=(const AbstractMap& that) const = 0;

    virtual std::unique_ptr<AbstractCommitter> create_committer(
      AbstractChangeSet* changes) = 0;

    virtual AbstractStore* get_store() = 0;
    virtual void serialise_changes(
      const AbstractChangeSet* changes,
      KvStoreSerialiser& s,
      bool include_reads) = 0;
    virtual void compact(Version v) = 0;
    virtual std::unique_ptr<Snapshot> snapshot(Version v) = 0;
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

  class AbstractStore
  {
  public:
    class AbstractSnapshot
    {
    public:
      virtual ~AbstractSnapshot() = default;
      virtual Version get_version() const = 0;
      virtual std::vector<uint8_t> serialise(
        std::shared_ptr<AbstractTxEncryptor> encryptor) = 0;
    };

    virtual ~AbstractStore() {}

    virtual void lock() = 0;
    virtual void unlock() = 0;

    virtual Version next_version() = 0;
    virtual TxID next_txid() = 0;

    virtual Version current_version() = 0;
    virtual TxID current_txid() = 0;

    virtual Version commit_version() = 0;

    virtual std::shared_ptr<AbstractMap> get_map(
      kv::Version v, const std::string& map_name) = 0;
    virtual void add_dynamic_map(
      kv::Version v, const std::shared_ptr<AbstractMap>& map) = 0;
    virtual bool is_map_replicated(const std::string& map_name) = 0;

    virtual std::shared_ptr<Consensus> get_consensus() = 0;
    virtual std::shared_ptr<TxHistory> get_history() = 0;
    virtual EncryptorPtr get_encryptor() = 0;
    virtual DeserialiseSuccess deserialise(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      kv::Term* term = nullptr) = 0;
    virtual void compact(Version v) = 0;
    virtual void rollback(Version v, std::optional<Term> t = std::nullopt) = 0;
    virtual void set_term(Term t) = 0;
    virtual CommitSuccess commit(
      const TxID& txid, PendingTx&& pending_tx, bool globally_committable) = 0;

    virtual std::unique_ptr<AbstractSnapshot> snapshot(Version v) = 0;
    virtual std::vector<uint8_t> serialise_snapshot(
      std::unique_ptr<AbstractSnapshot> snapshot) = 0;
    virtual DeserialiseSuccess deserialise_snapshot(
      const std::vector<uint8_t>& data,
      std::vector<Version>* view_history = nullptr,
      bool public_only = false) = 0;

    virtual size_t commit_gap() = 0;
  };
}