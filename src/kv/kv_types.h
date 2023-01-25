// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/claims_digest.h"
#include "ccf/crypto/pem.h"
#include "ccf/ds/nonstd.h"
#include "ccf/entity_id.h"
#include "ccf/kv/get_name.h"
#include "ccf/kv/hooks.h"
#include "ccf/kv/version.h"
#include "ccf/tx_id.h"
#include "enclave/consensus_type.h"
#include "enclave/reconfiguration_type.h"
#include "node/identity.h"
#include "serialiser_declare.h"
#include "service/tables/resharing_types.h"

#include <array>
#include <chrono>
#include <functional>
#include <limits>
#include <list>
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

    bool operator==(const TxID& other) const
    {
      return term == other.term && version == other.version;
    }

    std::string str() const
    {
      return fmt::format("{}.{}", term, version);
    }
  };
  DECLARE_JSON_TYPE(TxID);
  DECLARE_JSON_REQUIRED_FIELDS(TxID, term, version)

  using ReconfigurationId = uint64_t;

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

      bool operator==(const NodeInfo& other) const
      {
        return hostname == other.hostname && port == other.port;
      }
    };

    using Nodes = std::map<NodeId, NodeInfo>;

    ccf::SeqNo idx;
    Nodes nodes;
    uint32_t bft_offset = 0;
    ReconfigurationId rid;
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

  inline std::string schema_name(const Configuration::NodeInfo*)
  {
    return "Configuration__NodeInfo";
  }

  inline void fill_json_schema(
    nlohmann::json& schema, const Configuration::NodeInfo*)
  {
    schema["type"] = "object";
    schema["required"] = nlohmann::json::array();
    schema["required"].push_back("address");
    schema["properties"] = nlohmann::json::object();
    schema["properties"]["address"] = nlohmann::json::object();
    schema["properties"]["address"]["$ref"] = "#/components/schemas/string";
  }

  enum class LeadershipState
  {
    Leader,
    Follower,
    Candidate,
  };

  DECLARE_JSON_ENUM(
    LeadershipState,
    {{LeadershipState::Leader, "Leader"},
     {LeadershipState::Follower, "Follower"},
     {LeadershipState::Candidate, "Candidate"}});

  enum class MembershipState
  {
    Learner,
    Active,
    RetirementInitiated,
    Retired
  };

  DECLARE_JSON_ENUM(
    MembershipState,
    {{MembershipState::Learner, "Learner"},
     {MembershipState::Active, "Active"},
     {MembershipState::RetirementInitiated, "RetirementInitiated"},
     {MembershipState::Retired, "Retired"}});

  enum class RetirementPhase
  {
    Committed = 0,
    Ordered = 1,
    Signed = 2,
    Completed = 3
  };

  DECLARE_JSON_ENUM(
    RetirementPhase,
    {{RetirementPhase::Committed, "Committed"},
     {RetirementPhase::Ordered, "Ordered"},
     {RetirementPhase::Signed, "Signed"},
     {RetirementPhase::Completed, "Completed"}});

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration, idx, nodes, rid);
  DECLARE_JSON_OPTIONAL_FIELDS(Configuration, bft_offset);

  struct ConsensusDetails
  {
    struct Ack
    {
      ccf::SeqNo seqno;
      size_t last_received_ms;
    };

    std::vector<Configuration> configs = {};
    std::unordered_map<ccf::NodeId, Ack> acks = {};
    MembershipState membership_state;
    std::optional<LeadershipState> leadership_state = std::nullopt;
    std::optional<RetirementPhase> retirement_phase = std::nullopt;
    std::optional<std::unordered_map<ccf::NodeId, ccf::SeqNo>> learners =
      std::nullopt;
    std::optional<ReconfigurationType> reconfiguration_type = std::nullopt;
    std::optional<ccf::NodeId> primary_id = std::nullopt;
    ccf::View current_view = 0;
    bool ticking = false;
  };

  DECLARE_JSON_TYPE(ConsensusDetails::Ack);
  DECLARE_JSON_REQUIRED_FIELDS(ConsensusDetails::Ack, seqno, last_received_ms);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ConsensusDetails);
  DECLARE_JSON_REQUIRED_FIELDS(
    ConsensusDetails,
    configs,
    acks,
    membership_state,
    primary_id,
    current_view,
    ticking);
  DECLARE_JSON_OPTIONAL_FIELDS(
    ConsensusDetails,
    reconfiguration_type,
    learners,
    leadership_state,
    retirement_phase);

  struct ConsensusParameters
  {
    ReconfigurationType reconfiguration_type;
  };

  class ConfigurableConsensus
  {
  public:
    virtual void add_configuration(
      ccf::SeqNo seqno,
      const Configuration::Nodes& conf,
      const std::unordered_set<NodeId>& learners = {},
      const std::unordered_set<NodeId>& retired_nodes = {}) = 0;
    virtual Configuration::Nodes get_latest_configuration() = 0;
    virtual Configuration::Nodes get_latest_configuration_unsafe() const = 0;
    virtual ConsensusDetails get_details() = 0;
    virtual void add_resharing_result(
      ccf::SeqNo seqno,
      ReconfigurationId rid,
      const ccf::ResharingResult& result) = 0;
    virtual std::optional<Configuration::Nodes> orc(
      kv::ReconfigurationId rid, const NodeId& node_id) = 0;
    virtual void update_parameters(ConsensusParameters& params) = 0;
  };

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

  enum class EntryType : uint8_t
  {
    WriteSet = 0,
    Snapshot = 1,
    WriteSetWithClaims = 2,
    WriteSetWithCommitEvidence = 3,
    WriteSetWithCommitEvidenceAndClaims = 4,
    MAX = WriteSetWithCommitEvidenceAndClaims
  };

  static bool has_claims(const EntryType& et)
  {
    return et == EntryType::WriteSetWithClaims ||
      et == EntryType::WriteSetWithCommitEvidenceAndClaims;
  }

  static bool has_commit_evidence(const EntryType& et)
  {
    return et == EntryType::WriteSetWithCommitEvidence ||
      et == EntryType::WriteSetWithCommitEvidenceAndClaims;
  }

  // EntryType must be backwards compatible with the older
  // bool is_snapshot field
  static_assert(sizeof(EntryType) == sizeof(bool));

  constexpr auto public_domain_prefix = "public:";

  static inline SecurityDomain get_security_domain(const std::string& name)
  {
    if (name.starts_with(public_domain_prefix))
    {
      return SecurityDomain::PUBLIC;
    }

    return SecurityDomain::PRIVATE;
  }

  static inline std::pair<SecurityDomain, AccessCategory> parse_map_name(
    std::string_view name)
  {
    constexpr auto internal_category_prefix = "ccf.internal.";
    constexpr auto governance_category_prefix = "ccf.gov.";
    constexpr auto reserved_category_prefix = "ccf.";

    auto security_domain = SecurityDomain::PRIVATE;
    if (name.starts_with(public_domain_prefix))
    {
      name.remove_prefix(strlen(public_domain_prefix));
      security_domain = SecurityDomain::PUBLIC;
    }

    auto access_category = AccessCategory::APPLICATION;
    if (name.starts_with(internal_category_prefix))
    {
      access_category = AccessCategory::INTERNAL;
    }
    else if (name.starts_with(governance_category_prefix))
    {
      access_category = AccessCategory::GOVERNANCE;
    }
    else if (name.starts_with(reserved_category_prefix))
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
    virtual void append(const std::vector<uint8_t>& data) = 0;
    virtual void append_entry(const crypto::Sha256Hash& digest) = 0;
    virtual void rollback(
      const kv::TxID& tx_id, kv::Term term_of_next_version_) = 0;
    virtual void compact(Version v) = 0;
    virtual void set_term(kv::Term) = 0;
    virtual std::vector<uint8_t> serialise_tree(size_t from, size_t to) = 0;
    virtual void set_endorsed_certificate(const crypto::Pem& cert) = 0;
    virtual void start_signature_emit_timer() = 0;
  };

  class Consensus : public ConfigurableConsensus
  {
  public:
    virtual ~Consensus() {}

    virtual NodeId id() = 0;
    virtual bool is_primary() = 0;
    virtual bool is_backup() = 0;
    virtual bool is_candidate() = 0;
    virtual bool can_replicate() = 0;

    enum class SignatureDisposition
    {
      CANT_REPLICATE,
      CAN_SIGN,
      SHOULD_SIGN,
    };
    virtual SignatureDisposition get_signature_disposition() = 0;

    virtual void force_become_primary() = 0;
    virtual void force_become_primary(
      ccf::SeqNo, ccf::View, const std::vector<ccf::SeqNo>&, ccf::SeqNo) = 0;
    virtual void init_as_backup(
      ccf::SeqNo, ccf::View, const std::vector<ccf::SeqNo>&, ccf::SeqNo) = 0;

    virtual bool replicate(const BatchVector& entries, ccf::View view) = 0;
    virtual std::pair<ccf::View, ccf::SeqNo> get_committed_txid() = 0;

    // TODO: Doesn't need to be a struct
    struct SignableTxIndices
    {
      ccf::SeqNo previous_version;
    };

    virtual SignableTxIndices get_signable_txid() = 0;

    virtual ccf::View get_view(ccf::SeqNo seqno) = 0;
    virtual ccf::View get_view() = 0;
    virtual std::vector<ccf::SeqNo> get_view_history(
      ccf::SeqNo seqno = std::numeric_limits<ccf::SeqNo>::max()) = 0;
    virtual std::vector<ccf::SeqNo> get_view_history_since(
      ccf::SeqNo seqno) = 0;
    virtual ccf::SeqNo get_committed_seqno() = 0;
    virtual std::optional<NodeId> primary() = 0;
    virtual bool view_change_in_progress() = 0;

    virtual void recv_message(
      const NodeId& from, const uint8_t* data, size_t size) = 0;

    virtual void periodic(std::chrono::milliseconds) {}
    virtual void periodic_end() {}

    virtual void enable_all_domains() {}

    virtual ConsensusType type() = 0;
  };

  struct PendingTxInfo
  {
    CommitResult success;
    std::vector<uint8_t> data;
    ccf::ClaimsDigest claims_digest;
    crypto::Sha256Hash commit_evidence_digest;
    std::vector<ConsensusHookPtr> hooks;

    PendingTxInfo(
      CommitResult success_,
      std::vector<uint8_t>&& data_,
      ccf::ClaimsDigest&& claims_digest_,
      crypto::Sha256Hash&& commit_evidence_digest_,
      std::vector<ConsensusHookPtr>&& hooks_) :
      success(success_),
      data(std::move(data_)),
      claims_digest(claims_digest_),
      commit_evidence_digest(commit_evidence_digest_),
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
    ccf::ClaimsDigest claims_digest;
    crypto::Sha256Hash commit_evidence_digest;
    ConsensusHookPtrs hooks;

  public:
    MovePendingTx(
      std::vector<uint8_t>&& data_,
      ccf::ClaimsDigest&& claims_digest_,
      crypto::Sha256Hash&& commit_evidence_digest_,
      ConsensusHookPtrs&& hooks_) :
      data(std::move(data_)),
      claims_digest(std::move(claims_digest_)),
      commit_evidence_digest(std::move(commit_evidence_digest_)),
      hooks(std::move(hooks_))
    {}

    PendingTxInfo call() override
    {
      return PendingTxInfo(
        CommitResult::SUCCESS,
        std::move(data),
        std::move(claims_digest),
        std::move(commit_evidence_digest),
        std::move(hooks));
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
      EntryType entry_type = EntryType::WriteSet,
      bool historical_hint = false) = 0;
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
    virtual uint64_t get_term(const uint8_t* data, size_t size) = 0;

    virtual crypto::HashBytes get_commit_nonce(
      const TxID& tx_id, bool historical_hint = false) = 0;
  };
  using EncryptorPtr = std::shared_ptr<AbstractTxEncryptor>;

  class AbstractSnapshotter
  {
  public:
    virtual ~AbstractSnapshotter(){};

    virtual bool record_committable(kv::Version v) = 0;
    virtual void commit(kv::Version v, bool generate_snapshot) = 0;
    virtual void rollback(kv::Version v) = 0;
  };
  using SnapshotterPtr = std::shared_ptr<AbstractSnapshotter>;

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
    virtual bool prepare(bool track_commits) = 0;
    virtual void commit(
      Version v,
      bool track_read_versions,
      bool track_deletes_on_missing_keys) = 0;
    virtual ConsensusHookPtr post_commit() = 0;
  };

  class AbstractStore;
  class AbstractMap : public std::enable_shared_from_this<AbstractMap>,
                      public GetName
  {
  public:
    class Snapshot
    {
    public:
      virtual ~Snapshot() = default;
      virtual void serialise(KvStoreSerialiser& s) = 0;
      virtual SecurityDomain get_security_domain() = 0;
    };

    using GetName::GetName;
    virtual ~AbstractMap() {}

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
    virtual kv::ApplyResult apply(
      bool track_deletes_on_missing_keys = false) = 0;
    virtual kv::ConsensusHookPtrs& get_hooks() = 0;
    virtual const std::vector<uint8_t>& get_entry() = 0;
    virtual kv::Term get_term() = 0;
    virtual kv::Version get_index() = 0;
    virtual bool support_async_execution() = 0;
    virtual bool is_public_only() = 0;
    virtual ccf::ClaimsDigest&& consume_claims_digest() = 0;
    virtual std::optional<crypto::Sha256Hash>&&
    consume_commit_evidence_digest() = 0;

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
      bool public_only = false,
      const std::optional<TxID>& expected_txid = std::nullopt) = 0;
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
      const uint8_t* data,
      size_t size,
      ConsensusHookPtrs& hooks,
      std::vector<Version>* view_history = nullptr,
      bool public_only = false) = 0;
    virtual bool must_force_ledger_chunk(Version version) = 0;
    virtual bool must_force_ledger_chunk_unsafe(Version version) = 0;

    virtual size_t committable_gap() = 0;

    enum class Flag : uint8_t
    {
      LEDGER_CHUNK_AT_NEXT_SIGNATURE = 0x01,
      SNAPSHOT_AT_NEXT_SIGNATURE = 0x02
    };

    virtual void set_flag(Flag f) = 0;
    virtual void unset_flag(Flag f) = 0;
    virtual bool flag_enabled(Flag f) = 0;
    virtual void set_flag_unsafe(Flag f) = 0;
    virtual void unset_flag_unsafe(Flag f) = 0;
    virtual bool flag_enabled_unsafe(Flag f) const = 0;
  };
}

FMT_BEGIN_NAMESPACE

template <>
struct formatter<kv::Configuration::Nodes>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const kv::Configuration::Nodes& nodes, FormatContext& ctx) const
    -> decltype(ctx.out())
  {
    std::set<ccf::NodeId> node_ids;
    for (auto& [nid, _] : nodes)
    {
      node_ids.insert(nid);
    }
    return format_to(ctx.out(), "{{{}}}", fmt::join(node_ids, " "));
  }
};

FMT_END_NAMESPACE