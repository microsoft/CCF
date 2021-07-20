// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "ccf/tx_id.h"
#include "crypto/hash.h"
#include "crypto/pem.h"
#include "ds/nonstd.h"
#include "enclave/consensus_type.h"
#include "serialiser_declare.h"

#include <array>
#include <chrono>
#include <functional>
#include <limits>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

namespace ccf
{
  struct PrimarySignature;
}

namespace aft
{
  struct Request;
}

namespace kv
{
  // Version indexes modifications to the local kv store.
  using Version = uint64_t;
  static constexpr Version NoVersion = 0u;

  // DeletableVersion describes the version of an individual key within each
  // table, which may be negative to indicate a deletion
  using DeletableVersion = int64_t;

  static bool is_deleted(DeletableVersion version)
  {
    return version < 0;
  }

  // Term describes an epoch of Versions. It is incremented when global kv's
  // writer(s) changes. Term and Version combined give a unique identifier for
  // all accepted kv modifications. Terms are handled by Consensus via the
  // TermHistory
  using Term = uint64_t;
  using NodeId = ccf::NodeId;

  struct TxID
  {
    Term term = 0;
    Version version = 0;

    TxID() = default;
    TxID(Term t, Version v) : term(t), version(v) {}

    // Would like to remove these duplicate types, but for now we just do free
    // conversion
    TxID(const ccf::TxID& other) : term(other.view), version(other.seqno) {}

    operator ccf::TxID() const
    {
      return {term, version};
    }

    bool operator==(const TxID& other)
    {
      return term == other.term && version == other.version;
    }
  };
  DECLARE_JSON_TYPE(TxID);
  DECLARE_JSON_REQUIRED_FIELDS(TxID, term, version)

  struct Configuration
  {
    struct NodeInfo
    {
      std::string hostname;
      std::string port;

      NodeInfo() = default;

      NodeInfo(const std::string& hostname_, const std::string& port_) :
        hostname(hostname_),
        port(port_)
      {}
    };

    using Nodes = std::map<NodeId, NodeInfo>;

    ccf::SeqNo idx;
    Nodes nodes;
    uint32_t bft_offset;
  };

  inline void to_json(nlohmann::json& j, const Configuration::NodeInfo& ni)
  {
    j["address"] = fmt::format("{}:{}", ni.hostname, ni.port);
  }

  inline void from_json(const nlohmann::json& j, Configuration::NodeInfo& ni)
  {
    const std::string addr(j["address"]);
    const auto& [h, p] = nonstd::split_1(addr, ":");
    ni.hostname = h;
    ni.port = p;
  }

  enum class ReplicaState
  {
    Leader,
    Follower,
    Candidate,
    Retired,
    Learner,
    Retiring
  };

  DECLARE_JSON_ENUM(
    ReplicaState,
    {{ReplicaState::Leader, "Leader"},
     {ReplicaState::Follower, "Follower"},
     {ReplicaState::Candidate, "Candidate"},
     {ReplicaState::Retired, "Retired"},
     {ReplicaState::Learner, "Learner"},
     {ReplicaState::Retiring, "Retiring"}});

  DECLARE_JSON_TYPE(Configuration);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration, idx, nodes);

  struct ConsensusDetails
  {
    std::vector<Configuration> configs = {};
    std::unordered_map<ccf::NodeId, ccf::SeqNo> acks = {};
    ReplicaState state;
    std::optional<std::unordered_map<ccf::NodeId, ccf::SeqNo>> learners;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ConsensusDetails);
  DECLARE_JSON_REQUIRED_FIELDS(ConsensusDetails, configs, acks, state);
  DECLARE_JSON_OPTIONAL_FIELDS(ConsensusDetails, learners);

  using ReconfigurationId = uint64_t;

  struct NetworkConfiguration
  {
    ReconfigurationId rid;
    std::unordered_set<NodeId> nodes;

    bool operator<(const NetworkConfiguration& other) const
    {
      return rid < other.rid;
    }
  };

  DECLARE_JSON_TYPE(kv::NetworkConfiguration);
  DECLARE_JSON_REQUIRED_FIELDS(kv::NetworkConfiguration, rid, nodes);

  class ConfigurableConsensus
  {
  public:
    virtual void add_configuration(
      ccf::SeqNo seqno,
      const Configuration::Nodes& conf,
      const std::unordered_set<NodeId>& learners = {}) = 0;
    virtual Configuration::Nodes get_latest_configuration() = 0;
    virtual Configuration::Nodes get_latest_configuration_unsafe() const = 0;
    virtual ConsensusDetails get_details() = 0;
    virtual void add_network_configuration(
      ccf::SeqNo seqno, const NetworkConfiguration& config) = 0;
  };

  class ConsensusHook
  {
  public:
    virtual void call(ConfigurableConsensus*) = 0;
    virtual ~ConsensusHook(){};
  };

  using ConsensusHookPtr = std::unique_ptr<ConsensusHook>;
  using ConsensusHookPtrs = std::vector<ConsensusHookPtr>;

  using BatchVector = std::vector<std::tuple<
    Version,
    std::shared_ptr<std::vector<uint8_t>>,
    bool,
    std::shared_ptr<ConsensusHookPtrs>>>;

  enum CommitResult
  {
    SUCCESS = 1,
    FAIL_CONFLICT = 2,
    FAIL_NO_REPLICATE = 3
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
    constexpr auto governance_category_prefix = "public:ccf.gov.";
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
    else if (nonstd::starts_with(name, governance_category_prefix))
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

  enum ApplyResult
  {
    PASS = 1,
    PASS_SIGNATURE = 2,
    PASS_BACKUP_SIGNATURE = 3,
    PASS_BACKUP_SIGNATURE_SEND_ACK = 4,
    PASS_NONCES = 5,
    PASS_NEW_VIEW = 6,
    PASS_SNAPSHOT_EVIDENCE = 7,
    PASS_ENCRYPTED_PAST_LEDGER_SECRET = 8,
    PASS_APPLY = 9,
    FAIL = 10
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

  class TxHistory
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

    virtual ~TxHistory() {}
    virtual Result verify_and_sign(
      ccf::PrimarySignature& signature,
      Term* term,
      kv::Configuration::Nodes& nodes) = 0;
    virtual bool verify(
      Term* term = nullptr, ccf::PrimarySignature* sig = nullptr) = 0;
    virtual void try_emit_signature() = 0;
    virtual void emit_signature() = 0;
    virtual crypto::Sha256Hash get_replicated_state_root() = 0;
    virtual std::tuple<
      kv::TxID /* TxID of last transaction seen by history */,
      crypto::Sha256Hash /* root as of TxID */,
      kv::Term /* term_of_next_version */>
    get_replicated_state_txid_and_root() = 0;
    virtual std::vector<uint8_t> get_proof(Version v) = 0;
    virtual bool verify_proof(const std::vector<uint8_t>& proof) = 0;
    virtual bool init_from_snapshot(
      const std::vector<uint8_t>& hash_at_snapshot) = 0;
    virtual std::vector<uint8_t> get_raw_leaf(uint64_t index) = 0;

    virtual bool add_request(
      TxHistory::RequestID id,
      const std::vector<uint8_t>& caller_cert,
      const std::vector<uint8_t>& request,
      uint8_t frame_format) = 0;
    virtual void append(const std::vector<uint8_t>& data) = 0;
    virtual void rollback(
      const kv::TxID& tx_id, kv::Term term_of_next_version_) = 0;
    virtual void compact(Version v) = 0;
    virtual void set_term(kv::Term) = 0;
    virtual std::vector<uint8_t> serialise_tree(size_t from, size_t to) = 0;
  };

  class Consensus : public ConfigurableConsensus
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
    Consensus(const NodeId& id) : state(Backup), local_id(id) {}
    virtual ~Consensus() {}

    virtual NodeId id()
    {
      return local_id;
    }

    virtual bool is_primary()
    {
      return state == Primary;
    }

    virtual bool can_replicate()
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
      ccf::SeqNo, ccf::View, const std::vector<ccf::SeqNo>&, ccf::SeqNo)
    {
      state = Primary;
    }

    virtual void init_as_backup(
      ccf::SeqNo, ccf::View, const std::vector<ccf::SeqNo>&)
    {
      state = Backup;
    }

    virtual bool replicate(const BatchVector& entries, ccf::View view) = 0;
    virtual std::pair<ccf::View, ccf::SeqNo> get_committed_txid() = 0;

    struct SignableTxIndices
    {
      Term term;
      ccf::SeqNo version, previous_version;
    };

    virtual std::optional<SignableTxIndices> get_signable_txid() = 0;

    virtual ccf::View get_view(ccf::SeqNo seqno) = 0;
    virtual ccf::View get_view() = 0;
    virtual std::vector<ccf::SeqNo> get_view_history(ccf::SeqNo) = 0;
    virtual void initialise_view_history(const std::vector<ccf::SeqNo>&) = 0;
    virtual ccf::SeqNo get_committed_seqno() = 0;
    virtual std::optional<NodeId> primary() = 0;
    virtual bool view_change_in_progress() = 0;
    virtual std::set<NodeId> active_nodes() = 0;

    virtual void recv_message(
      const NodeId& from, const uint8_t* data, size_t size) = 0;

    virtual bool on_request(const TxHistory::RequestCallbackArgs&)
    {
      return true;
    }

    virtual void periodic(std::chrono::milliseconds) {}
    virtual void periodic_end() {}

    virtual void enable_all_domains() {}

    virtual void emit_signature() = 0;
    virtual ConsensusType type() = 0;
  };

  struct PendingTxInfo
  {
    CommitResult success;
    std::vector<uint8_t> data;
    std::vector<ConsensusHookPtr> hooks;

    PendingTxInfo(
      CommitResult success_,
      std::vector<uint8_t>&& data_,
      std::vector<ConsensusHookPtr>&& hooks_) :
      success(success_),
      data(std::move(data_)),
      hooks(std::move(hooks_))
    {}
  };

  class PendingTx
  {
  public:
    virtual PendingTxInfo call() = 0;
    virtual ~PendingTx() = default;
  };

  class MovePendingTx : public PendingTx
  {
  private:
    std::vector<uint8_t> data;
    ConsensusHookPtrs hooks;

  public:
    MovePendingTx(std::vector<uint8_t>&& data_, ConsensusHookPtrs&& hooks_) :
      data(std::move(data_)),
      hooks(std::move(hooks_))
    {}

    PendingTxInfo call() override
    {
      return PendingTxInfo(
        CommitResult::SUCCESS, std::move(data), std::move(hooks));
    }
  };

  class AbstractTxEncryptor
  {
  public:
    virtual ~AbstractTxEncryptor() {}

    virtual bool encrypt(
      const std::vector<uint8_t>& plain,
      const std::vector<uint8_t>& additional_data,
      std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& cipher,
      const TxID& tx_id,
      bool is_snapshot = false) = 0;
    virtual bool decrypt(
      const std::vector<uint8_t>& cipher,
      const std::vector<uint8_t>& additional_data,
      const std::vector<uint8_t>& serialised_header,
      std::vector<uint8_t>& plain,
      Version version,
      Term& term,
      bool historical_hint = false) = 0;

    virtual void rollback(Version version) = 0;

    virtual size_t get_header_length() = 0;
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
    virtual bool prepare(bool track_commits, Version& max_conflict_version) = 0;
    virtual void commit(Version v, bool track_read_versions) = 0;
    virtual ConsensusHookPtr post_commit() = 0;
  };

  class AbstractHandle
  {
  public:
    virtual ~AbstractHandle() = default;
  };

  struct NamedHandleMixin
  {
  protected:
    std::string name;

  public:
    NamedHandleMixin(const std::string& s) : name(s) {}
    virtual ~NamedHandleMixin() = default;

    const std::string& get_name() const
    {
      return name;
    }
  };

  class AbstractStore;
  class AbstractMap : public std::enable_shared_from_this<AbstractMap>,
                      public NamedHandleMixin
  {
  public:
    class Snapshot
    {
    public:
      virtual ~Snapshot() = default;
      virtual void serialise(KvStoreSerialiser& s) = 0;
      virtual SecurityDomain get_security_domain() = 0;
    };

    using NamedHandleMixin::NamedHandleMixin;
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

  class Tx;

  class AbstractExecutionWrapper
  {
  public:
    virtual ~AbstractExecutionWrapper() = default;
    virtual kv::ApplyResult apply() = 0;
    virtual kv::ConsensusHookPtrs& get_hooks() = 0;
    virtual const std::vector<uint8_t>& get_entry() = 0;
    virtual kv::Term get_term() = 0;
    virtual kv::Version get_index() = 0;
    virtual ccf::PrimarySignature& get_signature() = 0;
    virtual aft::Request& get_request() = 0;
    virtual kv::Version get_max_conflict_version() = 0;
    virtual bool support_async_execution() = 0;
    virtual bool is_public_only() = 0;

    // Setting a short rollback is a work around that should be fixed
    // shortly. In BFT mode when we deserialize and realize we need to
    // create a new map we remember this. If we need to create the same
    // map multiple times (for tx in the same group of append entries) the
    // first create successes but the second fails because the map is
    // already there. This works around the problem by stopping just
    // before the 2nd create (which failed at this point) and when the
    // primary resends the append entries we will succeed as the map is
    // already there. This will only occur on BFT startup so not a perf
    // problem but still need to be resolved.
    //
    // Thus, a large rollback is one which did not result from the map creating
    // issue. https://github.com/microsoft/CCF/issues/2799
    virtual bool should_rollback_to_last_committed() = 0;
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
    virtual std::tuple<Version, Version> next_version(bool commit_new_map) = 0;
    virtual TxID next_txid() = 0;

    virtual Version current_version() = 0;
    virtual TxID current_txid() = 0;
    virtual std::pair<TxID, Term> current_txid_and_commit_term() = 0;

    virtual Version compacted_version() = 0;
    virtual Term commit_view() = 0;

    virtual std::shared_ptr<AbstractMap> get_map(
      Version v, const std::string& map_name) = 0;
    virtual void add_dynamic_map(
      Version v, const std::shared_ptr<AbstractMap>& map) = 0;
    virtual bool is_map_replicated(const std::string& map_name) = 0;
    virtual bool should_track_dependencies(const std::string& name) = 0;

    virtual std::shared_ptr<Consensus> get_consensus() = 0;
    virtual std::shared_ptr<TxHistory> get_history() = 0;
    virtual EncryptorPtr get_encryptor() = 0;
    virtual std::unique_ptr<AbstractExecutionWrapper> deserialize(
      const std::vector<uint8_t>& data,
      ConsensusType consensus_type,
      bool public_only = false) = 0;
    virtual void compact(Version v) = 0;
    virtual void rollback(const TxID& tx_id, Term write_term_) = 0;
    virtual void initialise_term(Term t) = 0;
    virtual CommitResult commit(
      const TxID& txid,
      std::unique_ptr<PendingTx> pending_tx,
      bool globally_committable) = 0;

    virtual std::unique_ptr<AbstractSnapshot> snapshot(Version v) = 0;
    virtual std::vector<uint8_t> serialise_snapshot(
      std::unique_ptr<AbstractSnapshot> snapshot) = 0;
    virtual ApplyResult deserialise_snapshot(
      const std::vector<uint8_t>& data,
      ConsensusHookPtrs& hooks,
      std::vector<Version>* view_history = nullptr,
      bool public_only = false) = 0;

    virtual size_t commit_gap() = 0;
  };
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<kv::NetworkConfiguration>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const kv::NetworkConfiguration& config, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    return format_to(
      ctx.out(), "{}:{{{}}}", config.rid, fmt::join(config.nodes, " "));
  }
};
FMT_END_NAMESPACE