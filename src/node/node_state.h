// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "blit.h"
#include "consensus/aft/raft_consensus.h"
#include "consensus/ledger_enclave.h"
#include "crypto/entropy.h"
#include "crypto/pem.h"
#include "crypto/symmetric_key.h"
#include "crypto/verifier.h"
#include "ds/logger.h"
#include "enclave/rpc_sessions.h"
#include "encryptor.h"
#include "entities.h"
#include "genesis_gen.h"
#include "history.h"
#include "hooks.h"
#include "js/wrap.h"
#include "network_state.h"
#include "node/config_id.h"
#include "node/jwt_key_auto_refresh.h"
#include "node/progress_tracker.h"
#include "node/rpc/serdes.h"
#include "node_to_node.h"
#include "rpc/frontend.h"
#include "rpc/serialization.h"
#include "secret_broadcast.h"
#include "secret_share.h"
#include "share_manager.h"
#include "snapshotter.h"
#include "tls/client.h"

#ifdef USE_NULL_ENCRYPTOR
#  include "kv/test/null_encryptor.h"
#endif

#ifndef VIRTUAL_ENCLAVE
#  include "ccf_t.h"
#endif

#include <atomic>
#include <chrono>
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <unordered_set>
#include <vector>

// Used by fmtlib to render ccf::State
namespace std
{
  std::ostream& operator<<(std::ostream& os, ccf::State s)
  {
    nlohmann::json j;
    to_json(j, s);
    return os << j.dump();
  }
}

namespace ccf
{
  using RaftConsensusType =
    aft::Consensus<consensus::LedgerEnclave, NodeToNode, Snapshotter>;
  using RaftType = aft::Aft<consensus::LedgerEnclave, NodeToNode, Snapshotter>;

  struct NodeCreateInfo
  {
    crypto::Pem node_cert;
    crypto::Pem network_cert;
  };

  template <typename T>
  class StateMachine
  {
    std::atomic<T> s;

  public:
    StateMachine(T s) : s(s) {}
    void expect(T s) const
    {
      auto state = this->s.load();
      if (s != state)
      {
        throw std::logic_error(
          fmt::format("State is {}, but expected {}", state, s));
      }
    }

    bool check(T s) const
    {
      return s == this->s.load();
    }

    T value() const
    {
      return this->s.load();
    }

    void advance(T s)
    {
      LOG_DEBUG_FMT("Advancing to state {} (from {})", s, this->s.load());
      this->s.store(s);
    }
  };

  void reset_data(std::vector<uint8_t>& data)
  {
    data.clear();
    data.shrink_to_fit();
  }

  class NodeState : public ccf::AbstractNodeState
  {
  private:
    //
    // this node's core state
    //
    StateMachine<State> sm;
    std::mutex lock;

    CurveID curve_id;
    crypto::KeyPairPtr node_sign_kp;
    NodeId self;
    std::shared_ptr<crypto::RSAKeyPair> node_encrypt_kp;
    crypto::Pem node_cert;
    QuoteInfo quote_info;
    CodeDigest node_code_id;
    CCFConfig config;
#ifdef GET_QUOTE
    EnclaveAttestationProvider enclave_attestation_provider;
#endif

    //
    // kv store, replication, and I/O
    //
    ringbuffer::AbstractWriterFactory& writer_factory;
    ringbuffer::WriterPtr to_host;
    consensus::Configuration consensus_config;
    size_t sig_tx_interval;
    size_t sig_ms_interval;

    NetworkState& network;

    std::shared_ptr<kv::Consensus> consensus;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    std::shared_ptr<NodeToNode> n2n_channels;
    std::shared_ptr<Forwarder<NodeToNode>> cmd_forwarder;
    std::shared_ptr<enclave::RPCSessions> rpcsessions;

    std::shared_ptr<kv::TxHistory> history;
    std::shared_ptr<ccf::ProgressTracker> progress_tracker;
    std::shared_ptr<ccf::ProgressTrackerStoreAdapter> tracker_store;
    std::shared_ptr<kv::AbstractTxEncryptor> encryptor;

    ShareManager& share_manager;
    std::shared_ptr<Snapshotter> snapshotter;

    //
    // recovery
    //
    NodeInfoNetwork node_info_network;
    std::shared_ptr<kv::Store> recovery_store;

    kv::Version recovery_v;
    crypto::Sha256Hash recovery_root;
    std::vector<kv::Version> view_history;
    consensus::Index last_recovered_signed_idx = 1;
    RecoveredEncryptedLedgerSecrets recovery_ledger_secrets;
    consensus::Index ledger_idx = 0;

    //
    // JWT key auto-refresh
    //
    std::shared_ptr<JwtKeyAutoRefresh> jwt_key_auto_refresh;

    struct StartupSnapshotInfo
    {
      std::vector<uint8_t>& raw;
      consensus::Index seqno;
      consensus::Index evidence_seqno;

      // Store used to verify a snapshot (either created fresh when a node joins
      // from a snapshot or points to the main store when recovering from a
      // snapshot)
      std::shared_ptr<kv::Store> store = nullptr;

      // The snapshot to startup from (on join or recovery) is only valid once a
      // signature ledger entry confirms that the snapshot evidence was
      // committed
      bool has_evidence = false;
      bool is_evidence_committed = false;

      StartupSnapshotInfo(
        const std::shared_ptr<kv::Store>& store_,
        std::vector<uint8_t>& raw_,
        consensus::Index seqno_,
        consensus::Index evidence_seqno_) :
        raw(raw_),
        seqno(seqno_),
        evidence_seqno(evidence_seqno_),
        store(store_)
      {}

      bool is_snapshot_verified()
      {
        return has_evidence && is_evidence_committed;
      }

      ~StartupSnapshotInfo()
      {
        reset_data(raw);
      }
    };
    std::unique_ptr<StartupSnapshotInfo> startup_snapshot_info = nullptr;
    // Set to the snapshot seqno when a node starts from one and remembered for
    // the lifetime of the node
    std::optional<kv::Version> startup_seqno = std::nullopt;

    std::shared_ptr<kv::AbstractTxEncryptor> make_encryptor()
    {
#ifdef USE_NULL_ENCRYPTOR
      return std::make_shared<kv::NullTxEncryptor>();
#else
      return std::make_shared<NodeEncryptor>(network.ledger_secrets);
#endif
    }

    void initialise_startup_snapshot(bool recovery = false)
    {
      std::shared_ptr<kv::Store> snapshot_store;
      if (!recovery)
      {
        // Create a new store to verify the snapshot only
        snapshot_store = make_store(network.consensus_type);
        auto snapshot_history = std::make_shared<MerkleTxHistory>(
          *snapshot_store.get(),
          self,
          *node_sign_kp,
          sig_tx_interval,
          sig_ms_interval,
          false /* No signature timer on snapshot_history */);

        auto snapshot_encryptor = make_encryptor();

        snapshot_store->set_history(snapshot_history);
        snapshot_store->set_encryptor(snapshot_encryptor);
      }
      else
      {
        snapshot_store = network.tables;
      }

      LOG_INFO_FMT(
        "Deserialising public snapshot ({})", config.startup_snapshot.size());

      kv::ConsensusHookPtrs hooks;
      auto rc = snapshot_store->deserialise_snapshot(
        config.startup_snapshot, hooks, &view_history, true);
      if (rc != kv::ApplyResult::PASS)
      {
        throw std::logic_error(
          fmt::format("Failed to apply public snapshot: {}", rc));
      }

      LOG_INFO_FMT(
        "Public snapshot deserialised at seqno {}",
        snapshot_store->current_version());

      startup_seqno = snapshot_store->current_version();

      ledger_idx = snapshot_store->current_version();
      last_recovered_signed_idx = ledger_idx;

      startup_snapshot_info = std::make_unique<StartupSnapshotInfo>(
        snapshot_store,
        config.startup_snapshot,
        ledger_idx,
        config.startup_snapshot_evidence_seqno);
    }

  public:
    NodeState(
      ringbuffer::AbstractWriterFactory& writer_factory,
      NetworkState& network,
      std::shared_ptr<enclave::RPCSessions> rpcsessions,
      ShareManager& share_manager,
      CurveID curve_id_) :
      sm(State::uninitialized),
      curve_id(curve_id_),
      node_sign_kp(crypto::make_key_pair(curve_id_)),
      node_encrypt_kp(crypto::make_rsa_key_pair()),
      writer_factory(writer_factory),
      to_host(writer_factory.create_writer_to_outside()),
      network(network),
      rpcsessions(rpcsessions),
      share_manager(share_manager)
    {
      if (network.consensus_type == ConsensusType::CFT)
      {
        self = crypto::Sha256Hash(node_sign_kp->public_key_der()).hex_str();
      }
    }

    QuoteVerificationResult verify_quote(
      kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const std::vector<uint8_t>& expected_node_public_key_der) override
    {
#ifdef GET_QUOTE
      return enclave_attestation_provider.verify_quote_against_store(
        tx, quote_info, expected_node_public_key_der);
#else
      (void)tx;
      (void)quote_info;
      (void)expected_node_public_key_der;
      return QuoteVerificationResult::Verified;
#endif
    }

    //
    // funcs in state "uninitialized"
    //
    void initialize(
      const consensus::Configuration& consensus_config_,
      std::shared_ptr<NodeToNode> n2n_channels_,
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      std::shared_ptr<Forwarder<NodeToNode>> cmd_forwarder_,
      size_t sig_tx_interval_,
      size_t sig_ms_interval_)
    {
      std::lock_guard<std::mutex> guard(lock);
      sm.expect(State::uninitialized);

      consensus_config = consensus_config_;
      n2n_channels = n2n_channels_;
      rpc_map = rpc_map_;
      cmd_forwarder = cmd_forwarder_;
      sig_tx_interval = sig_tx_interval_;
      sig_ms_interval = sig_ms_interval_;
      sm.advance(State::initialized);
    }

    //
    // funcs in state "initialized"
    //
    NodeCreateInfo create(StartType start_type, CCFConfig&& config_)
    {
      std::lock_guard<std::mutex> guard(lock);
      sm.expect(State::initialized);

      config = std::move(config_);

      js::register_class_ids();
      open_frontend(ActorsType::nodes);

#ifdef GET_QUOTE
      quote_info = enclave_attestation_provider.generate_quote(
        node_sign_kp->public_key_der());
      node_code_id = enclave_attestation_provider.get_code_id(quote_info);
#endif

      switch (start_type)
      {
        case StartType::New:
        {
          network.identity =
            std::make_unique<NetworkIdentity>("CN=CCF Network", curve_id);

          node_cert = create_endorsed_node_cert();

          network.ledger_secrets->init();

          if (network.consensus_type == ConsensusType::BFT)
          {
            // BFT consensus requires a stable order of node IDs so that the
            // primary node in a given view can be computed deterministically by
            // all nodes in the network
            // See https://github.com/microsoft/CCF/issues/1852

            // Pad node id string to avoid memory alignment issues on
            // node-to-node messages
            self = NodeId(fmt::format("{:#064}", 0));
          }

          setup_snapshotter();
          setup_encryptor();
          setup_consensus();
          setup_progress_tracker();
          setup_history();

          // Become the primary and force replication
          consensus->force_become_primary();

          // Open member frontend for members to configure and open the
          // network
          open_frontend(ActorsType::members);

          if (!create_and_send_request())
          {
            throw std::runtime_error(
              "Genesis transaction could not be committed");
          }

          accept_network_tls_connections();
          auto_refresh_jwt_keys();

          reset_data(quote_info.quote);
          reset_data(quote_info.endorsements);
          sm.advance(State::partOfNetwork);

          LOG_INFO_FMT("Created new node {}", self);
          return {node_cert, network.identity->cert};
        }
        case StartType::Join:
        {
          node_cert = create_self_signed_node_cert();
          accept_node_tls_connections();

          if (!config.startup_snapshot.empty())
          {
            initialise_startup_snapshot();
            sm.advance(State::verifyingSnapshot);
          }
          else
          {
            sm.advance(State::pending);
          }

          LOG_INFO_FMT("Created join node {}", self);
          return {node_cert, {}};
        }
        case StartType::Recover:
        {
          node_info_network = config.node_info_network;

          network.identity =
            std::make_unique<NetworkIdentity>("CN=CCF Network", curve_id);
          node_cert = create_endorsed_node_cert();

          setup_history();

          // It is necessary to give an encryptor to the store for it to
          // deserialise the public domain when recovering the public ledger.
          // Once the public recovery is complete, the existing encryptor is
          // replaced with a new one initialised with the recovered ledger
          // secrets.
          setup_encryptor();

          setup_snapshotter();
          bool from_snapshot = !config.startup_snapshot.empty();
          setup_recovery_hook();

          if (from_snapshot)
          {
            initialise_startup_snapshot(true);
            snapshotter->set_last_snapshot_idx(ledger_idx);
          }

          accept_network_tls_connections();

          sm.advance(State::readingPublicLedger);

          LOG_INFO_FMT("Created recovery node {}", self);
          return {node_cert, network.identity->cert};
        }
        default:
        {
          throw std::logic_error(
            fmt::format("Node was started in unknown mode {}", start_type));
        }
      }
    }

    //
    // funcs in state "pending"
    //
    void initiate_join()
    {
      auto network_ca = std::make_shared<tls::CA>(config.joining.network_cert);
      auto join_client_cert = std::make_unique<tls::Cert>(
        network_ca, node_cert, node_sign_kp->private_key_pem());

      // Create RPC client and connect to remote node
      auto join_client =
        rpcsessions->create_client(std::move(join_client_cert));

      join_client->connect(
        config.joining.target_host,
        config.joining.target_port,
        [this](
          http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          std::lock_guard<std::mutex> guard(lock);
          if (!sm.check(State::pending))
          {
            return false;
          }

          if (status != HTTP_STATUS_OK)
          {
            const auto& location = headers.find(http::headers::LOCATION);
            if (
              status == HTTP_STATUS_PERMANENT_REDIRECT &&
              location != headers.end())
            {
              const auto& url = http::parse_url_full(location->second);
              config.joining.target_host = url.host;
              config.joining.target_port = url.port;
              LOG_INFO_FMT("Target node redirected to {}", location->second);
            }
            else
            {
              LOG_FAIL_FMT(
                "An error occurred while joining the network: {} {}{}",
                status,
                http_status_str(status),
                data.empty() ?
                  "" :
                  fmt::format("  '{}'", std::string(data.begin(), data.end())));
            }
            return false;
          }

          auto j = serdes::unpack(data, serdes::Pack::Text);

          JoinNetworkNodeToNode::Out resp;
          try
          {
            resp = j.get<JoinNetworkNodeToNode::Out>();
          }
          catch (const std::exception& e)
          {
            LOG_FAIL_FMT(
              "An error occurred while parsing the join network response");
            LOG_DEBUG_FMT(
              "An error occurred while parsing the join network response: {}",
              j.dump());
            return false;
          }

          // Set network secrets, node id and become part of network.
          if (
            resp.node_status == NodeStatus::TRUSTED ||
            resp.node_status == NodeStatus::LEARNER)
          {
            network.identity =
              std::make_unique<NetworkIdentity>(resp.network_info.identity);

            node_cert = create_endorsed_node_cert();

            network.ledger_secrets->init_from_map(
              std::move(resp.network_info.ledger_secrets));

            if (resp.network_info.consensus_type != network.consensus_type)
            {
              throw std::logic_error(fmt::format(
                "Enclave initiated with consensus type {} but target node "
                "responded with consensus {}",
                network.consensus_type,
                resp.network_info.consensus_type));
            }

            if (network.consensus_type == ConsensusType::BFT)
            {
              // In CFT, the node id is computed at startup, as the hash of the
              // node's public key
              self = resp.node_id;
            }

            setup_snapshotter();
            setup_encryptor();
            setup_consensus(resp.network_info.public_only);
            setup_progress_tracker();
            setup_history();
            auto_refresh_jwt_keys();

            if (resp.network_info.public_only)
            {
              last_recovered_signed_idx =
                resp.network_info.last_recovered_signed_idx;
              setup_recovery_hook();
              snapshotter->set_snapshot_generation(false);
            }

            if (startup_snapshot_info)
            {
              // It is only possible to deserialise the entire snapshot then,
              // once the ledger secrets have been passed in by the network
              LOG_DEBUG_FMT(
                "Deserialising snapshot ({})",
                startup_snapshot_info->raw.size());
              std::vector<kv::Version> view_history;
              kv::ConsensusHookPtrs hooks;
              auto rc = network.tables->deserialise_snapshot(
                startup_snapshot_info->raw,
                hooks,
                &view_history,
                resp.network_info.public_only);
              if (rc != kv::ApplyResult::PASS)
              {
                throw std::logic_error(
                  fmt::format("Failed to apply snapshot on join: {}", rc));
              }

              for (auto& hook : hooks)
              {
                hook->call(consensus.get());
              }

              auto tx = network.tables->create_read_only_tx();
              auto signatures = tx.ro(network.signatures);
              auto sig = signatures->get();
              if (!sig.has_value())
              {
                throw std::logic_error(
                  fmt::format("No signatures found after applying snapshot"));
              }

              auto seqno = network.tables->current_version();
              consensus->init_as_backup(seqno, sig->view, view_history);

              if (!resp.network_info.public_only)
              {
                // Only clear snapshot if not recovering. When joining the
                // public network the snapshot is used later to initialise the
                // recovery store
                startup_snapshot_info.reset();
              }

              LOG_INFO_FMT(
                "Joiner successfully resumed from snapshot at seqno {} and "
                "view {}",
                seqno,
                sig->view);
            }

            open_frontend(ActorsType::members);

            accept_network_tls_connections();

            if (resp.network_info.public_only)
            {
              sm.advance(State::partOfPublicNetwork);
            }
            else
            {
              reset_data(quote_info.quote);
              reset_data(quote_info.endorsements);
              sm.advance(State::partOfNetwork);
            }

            LOG_INFO_FMT(
              "Node has now joined the network as node {}: {}",
              self,
              (resp.network_info.public_only ? "public only" : "all domains"));

            // The network identity is now known, the user frontend can be
            // opened once the KV state catches up
            open_user_frontend();
          }
          else if (resp.node_status == NodeStatus::PENDING)
          {
            LOG_INFO_FMT(
              "Node {} is waiting for votes of members to be trusted",
              resp.node_id);
          }

          return true;
        });

      // Send RPC request to remote node to join the network.
      JoinNetworkNodeToNode::In join_params;

      join_params.node_info_network = config.node_info_network;
      join_params.public_encryption_key =
        node_encrypt_kp->public_key_pem().raw();
      join_params.quote_info = quote_info;
      join_params.consensus_type = network.consensus_type;
      join_params.startup_seqno = startup_seqno;

      LOG_DEBUG_FMT(
        "Sending join request to {}:{}",
        config.joining.target_host,
        config.joining.target_port);

      const auto body = serdes::pack(join_params, serdes::Pack::Text);

      http::Request r(fmt::format(
        "/{}/{}", ccf::get_actor_prefix(ccf::ActorsType::nodes), "join"));
      r.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
      r.set_body(&body);

      join_client->send_request(r.build_request());
    }

    void start_join_timer()
    {
      initiate_join();

      struct JoinTimeMsg
      {
        JoinTimeMsg(NodeState& self_) : self(self_) {}
        NodeState& self;
      };

      auto join_timer_msg = std::make_unique<threading::Tmsg<JoinTimeMsg>>(
        [](std::unique_ptr<threading::Tmsg<JoinTimeMsg>> msg) {
          if (msg->data.self.sm.check(State::pending))
          {
            msg->data.self.initiate_join();
            auto delay = std::chrono::milliseconds(
              msg->data.self.config.joining.join_timer);

            threading::ThreadMessaging::thread_messaging.add_task_after(
              std::move(msg), delay);
          }
        },
        *this);

      threading::ThreadMessaging::thread_messaging.add_task_after(
        std::move(join_timer_msg),
        std::chrono::milliseconds(config.joining.join_timer));
    }

    void join()
    {
      std::lock_guard<std::mutex> guard(lock);
      sm.expect(State::pending);
      start_join_timer();
    }

    void auto_refresh_jwt_keys()
    {
      if (!consensus)
      {
        LOG_INFO_FMT(
          "JWT key auto-refresh: consensus not initialized, not starting "
          "auto-refresh");
        return;
      }
      jwt_key_auto_refresh = std::make_shared<JwtKeyAutoRefresh>(
        config.jwt_key_refresh_interval_s,
        network,
        consensus,
        rpcsessions,
        rpc_map,
        node_sign_kp,
        node_cert);
      jwt_key_auto_refresh->start();

      network.tables->set_map_hook(
        network.jwt_issuers.get_name(),
        [this](kv::Version, const kv::untyped::Write&) -> kv::ConsensusHookPtr {
          jwt_key_auto_refresh->schedule_once();
          return kv::ConsensusHookPtr(nullptr);
        });
    }

    //
    // funcs in state "readingPublicLedger" or "verifyingSnapshot"
    //
    void start_ledger_recovery()
    {
      std::lock_guard<std::mutex> guard(lock);
      if (
        !sm.check(State::readingPublicLedger) &&
        !sm.check(State::verifyingSnapshot))
      {
        throw std::logic_error(fmt::format(
          "Node should be in state {} or {} to start reading ledger",
          State::readingPublicLedger,
          State::verifyingSnapshot));
      }

      LOG_INFO_FMT("Starting to read public ledger");
      read_ledger_idx(++ledger_idx);
    }

    void recover_public_ledger_entry(const std::vector<uint8_t>& ledger_entry)
    {
      std::lock_guard<std::mutex> guard(lock);

      std::shared_ptr<kv::Store> store;
      if (sm.check(State::readingPublicLedger))
      {
        // In recovery, use the main store to deserialise public entries
        store = network.tables;
      }
      else if (sm.check(State::verifyingSnapshot))
      {
        store = startup_snapshot_info->store;
      }
      else
      {
        LOG_FAIL_FMT(
          "Node should be in state {} or {} to recover public ledger entry",
          State::readingPublicLedger,
          State::verifyingSnapshot);
        return;
      }

      LOG_INFO_FMT(
        "Deserialising public ledger entry ({})", ledger_entry.size());

      auto r = store->deserialize(ledger_entry, ConsensusType::CFT, true);
      auto result = r->apply();
      if (result == kv::ApplyResult::FAIL)
      {
        LOG_FAIL_FMT("Failed to deserialise entry in public ledger");
        store->rollback(ledger_idx - 1);
        recover_public_ledger_end_unsafe();
        return;
      }

      // Not synchronised because consensus isn't effectively running then
      for (auto& hook : r->get_hooks())
      {
        hook->call(consensus.get());
      }

      // If the ledger entry is a signature, it is safe to compact the store
      if (result == kv::ApplyResult::PASS_SIGNATURE)
      {
        // If the ledger entry is a signature, it is safe to compact the store
        store->compact(ledger_idx);
        auto tx = store->create_tx();
        GenesisGenerator g(network, tx);
        auto last_sig = g.get_last_signature();

        if (!last_sig.has_value())
        {
          throw std::logic_error("Signature missing");
        }

        LOG_DEBUG_FMT(
          "Read signature at {} for view {}", ledger_idx, last_sig->view);
        // Initial transactions, before the first signature, must have
        // happened in the first signature's view (eg - if the first
        // signature is at seqno 20 in view 4, then transactions 1->19 must
        // also have been in view 4). The brief justification is that while
        // the first node may start in an arbitrarily high view (it does not
        // necessarily start in view 1), it cannot _change_ view before a
        // valid signature.
        const auto view_start_idx =
          view_history.empty() ? 1 : last_recovered_signed_idx + 1;
        CCF_ASSERT_FMT(
          last_sig->view >= 0, "last_sig->view is invalid, {}", last_sig->view);
        for (auto i = view_history.size();
             i < static_cast<size_t>(last_sig->view);
             ++i)
        {
          view_history.push_back(view_start_idx);
        }
        last_recovered_signed_idx = ledger_idx;

        if (
          startup_snapshot_info && startup_snapshot_info->has_evidence &&
          static_cast<consensus::Index>(last_sig->commit_seqno) >=
            startup_snapshot_info->evidence_seqno)
        {
          startup_snapshot_info->is_evidence_committed = true;
        }

        if (sm.check(State::readingPublicLedger))
        {
          // Inform snapshotter of all signature entries so that this node can
          // continue generating snapshots at the correct interval once the
          // recovery is complete
          snapshotter->record_committable(ledger_idx);
          snapshotter->commit(ledger_idx, false);
        }
      }
      else if (
        result == kv::ApplyResult::PASS_SNAPSHOT_EVIDENCE &&
        startup_snapshot_info)
      {
        auto tx = store->create_read_only_tx();
        auto snapshot_evidence = tx.ro(network.snapshot_evidence);

        if (ledger_idx == startup_snapshot_info->evidence_seqno)
        {
          auto evidence = snapshot_evidence->get(0);
          if (!evidence.has_value())
          {
            throw std::logic_error("Invalid snapshot evidence");
          }

          if (evidence->hash == crypto::Sha256Hash(startup_snapshot_info->raw))
          {
            LOG_DEBUG_FMT(
              "Snapshot evidence for snapshot found at {}",
              startup_snapshot_info->evidence_seqno);
            startup_snapshot_info->has_evidence = true;
          }
        }
      }

      read_ledger_idx(++ledger_idx);
    }

    void verify_snapshot_end()
    {
      std::lock_guard<std::mutex> guard(lock);
      if (!sm.check(State::verifyingSnapshot))
      {
        LOG_FAIL_FMT(
          "Node in state {} cannot finalise snapshot verification", sm.value());
        return;
      }

      if (startup_snapshot_info == nullptr)
      {
        // Node should shutdown if the startup snapshot cannot be verified
        throw std::logic_error(
          "No known startup snapshot to finalise snapshot verification");
      }

      if (!startup_snapshot_info->is_snapshot_verified())
      {
        // Node should shutdown if the startup snapshot cannot be verified
        LOG_FAIL_FMT(
          "Snapshot evidence at {} was not committed in ledger ending at {}. "
          "Node should be shutdown by operator.",
          startup_snapshot_info->evidence_seqno,
          ledger_idx);
        return;
      }

      ledger_truncate(startup_snapshot_info->seqno);

      sm.advance(State::pending);
      start_join_timer();
    }

    void recover_public_ledger_end_unsafe()
    {
      sm.expect(State::readingPublicLedger);

      if (startup_snapshot_info)
      {
        if (!startup_snapshot_info->is_snapshot_verified())
        {
          throw std::logic_error(
            "Snapshot evidence was not committed in ledger");
        }

        if (last_recovered_signed_idx < startup_snapshot_info->evidence_seqno)
        {
          throw std::logic_error("Snapshot evidence would be rolled back");
        }
      }

      // When reaching the end of the public ledger, truncate to last signed
      // index and promote network secrets to this index
      network.tables->rollback(last_recovered_signed_idx);
      ledger_truncate(last_recovered_signed_idx);
      snapshotter->rollback(last_recovered_signed_idx);

      LOG_INFO_FMT(
        "End of public ledger recovery - Truncating ledger to last signed "
        "seqno: {}",
        last_recovered_signed_idx);

      // KV term must be set before the first Tx is committed
      auto new_term = view_history.size() + 2;
      LOG_INFO_FMT("Setting term on public recovery store to {}", new_term);
      network.tables->set_term(new_term);

      auto tx = network.tables->create_tx();
      GenesisGenerator g(network, tx);
      g.create_service(network.identity->cert);
      g.retire_active_nodes();

      if (network.consensus_type == ConsensusType::BFT)
      {
        // BFT consensus requires a stable order of node IDs so that the
        // primary node in a given view can be computed deterministically by
        // all nodes in the network
        // See https://github.com/microsoft/CCF/issues/1852

        // Pad node id string to avoid memory alignment issues on
        // node-to-node messages
        auto values = tx.ro(network.values);
        auto id = values->get(0);
        self = NodeId(fmt::format("{:#064}", id.value()));
      }

      g.add_node(
        self,
        {node_info_network,
         node_cert,
         quote_info,
         node_encrypt_kp->public_key_pem().raw(),
         NodeStatus::PENDING,
         get_fresh_config_id(network, tx)});

      LOG_INFO_FMT("Deleted previous nodes and added self as {}", self);

      network.ledger_secrets->init(last_recovered_signed_idx + 1);
      setup_encryptor();

      // Initialise snapshotter after public recovery
      snapshotter->init_after_public_recovery();
      snapshotter->set_snapshot_generation(false);

      kv::Version index = 0;
      kv::Term view = 0;
      kv::Version global_commit = 0;

      auto ls = g.get_last_signature();
      if (ls.has_value())
      {
        auto s = ls.value();
        index = s.seqno;
        view = s.view;
        global_commit = s.commit_seqno;
      }

      auto h = dynamic_cast<MerkleTxHistory*>(history.get());
      if (h)
      {
        h->set_node_id(self);
      }

      if (progress_tracker != nullptr)
      {
        progress_tracker->set_node_id(self);
      }

      setup_consensus(true);
      setup_progress_tracker();
      auto_refresh_jwt_keys();

      LOG_DEBUG_FMT(
        "Restarting consensus at view: {} seqno: {} commit_seqno {}",
        view,
        index,
        global_commit);

      consensus->force_become_primary(index, view, view_history, index);

      // Sets itself as trusted
      g.trust_node(self, network.ledger_secrets->get_latest(tx).first);

#ifdef GET_QUOTE
      g.trust_node_code_id(node_code_id);
#endif

      if (tx.commit() != kv::CommitResult::SUCCESS)
      {
        throw std::logic_error(
          "Could not commit transaction when starting recovered public "
          "network");
      }

      open_frontend(ActorsType::members);

      sm.advance(State::partOfPublicNetwork);
    }

    //
    // funcs in state "readingPrivateLedger"
    //
    void recover_private_ledger_entry(const std::vector<uint8_t>& ledger_entry)
    {
      std::lock_guard<std::mutex> guard(lock);
      if (!sm.check(State::readingPrivateLedger))
      {
        LOG_FAIL_FMT(
          "Node is state {} cannot recover private ledger entry", sm.value());
        return;
      }

      LOG_INFO_FMT(
        "Deserialising private ledger entry ({})", ledger_entry.size());

      // When reading the private ledger, deserialise in the recovery store
      auto result =
        recovery_store->deserialize(ledger_entry, ConsensusType::CFT)->apply();
      if (result == kv::ApplyResult::FAIL)
      {
        LOG_FAIL_FMT("Failed to deserialise entry in private ledger");
        recovery_store->rollback(ledger_idx - 1);
        recover_private_ledger_end_unsafe();
        return;
      }

      if (result == kv::ApplyResult::PASS_SIGNATURE)
      {
        recovery_store->compact(ledger_idx);
      }

      if (recovery_store->current_version() == recovery_v)
      {
        LOG_INFO_FMT("Reached recovery final version at {}", recovery_v);
        recover_private_ledger_end_unsafe();
      }
      else
      {
        read_ledger_idx(++ledger_idx);
      }
    }

    void recover_private_ledger_end_unsafe()
    {
      // When reaching the end of the private ledger, make sure the same
      // ledger has been read and swap in private state

      sm.expect(State::readingPrivateLedger);

      if (recovery_v != recovery_store->current_version())
      {
        throw std::logic_error(fmt::format(
          "Private recovery did not reach public ledger seqno: {}/{}",
          recovery_store->current_version(),
          recovery_v));
      }

      auto h =
        dynamic_cast<MerkleTxHistory*>(recovery_store->get_history().get());
      if (h->get_replicated_state_root() != recovery_root)
      {
        throw std::logic_error(fmt::format(
          "Root of public store does not match root of private store at {}",
          recovery_v));
      }

      network.tables->swap_private_maps(*recovery_store.get());
      recovery_store.reset();

      // Raft should deserialise all security domains when network is opened
      consensus->enable_all_domains();

      // Snapshots are only generated after recovery is complete
      snapshotter->set_snapshot_generation(true);

      // Open the service
      if (consensus->can_replicate())
      {
        setup_one_off_secret_hook();
        auto tx = network.tables->create_tx();

        // Shares for the new ledger secret can only be issued now, once the
        // previous ledger secrets have been recovered
        share_manager.issue_recovery_shares(tx);
        GenesisGenerator g(network, tx);
        if (!g.open_service())
        {
          throw std::logic_error("Service could not be opened");
        }

        if (tx.commit() != kv::CommitResult::SUCCESS)
        {
          throw std::logic_error(
            "Could not commit transaction when finishing network recovery");
        }
      }
      open_user_frontend();
      reset_data(quote_info.quote);
      reset_data(quote_info.endorsements);
      sm.advance(State::partOfNetwork);
    }

    void setup_one_off_secret_hook()
    {
      // This hook is necessary to adjust the version at which the last ledger
      // secret before recovery is recorded in the store. This can only be fired
      // once, after the recovery shares for the post-recovery ledger secret are
      // issued.
      network.tables->set_map_hook(
        network.encrypted_ledger_secrets.get_name(),
        network.encrypted_ledger_secrets.wrap_map_hook(
          [this](
            kv::Version version, const EncryptedLedgerSecretsInfo::Write& w)
            -> kv::ConsensusHookPtr {
            if (w.size() > 1)
            {
              throw std::logic_error(fmt::format(
                "Transaction contains {} writes to map {}, expected one",
                w.size(),
                network.encrypted_ledger_secrets.get_name()));
            }

            auto encrypted_ledger_secret_info = w.at(0);
            if (!encrypted_ledger_secret_info.has_value())
            {
              throw std::logic_error(fmt::format(
                "Removal from {} table",
                network.encrypted_ledger_secrets.get_name()));
            }

            network.ledger_secrets->adjust_previous_secret_stored_version(
              version);

            network.tables->unset_map_hook(
              network.encrypted_ledger_secrets.get_name());

            return kv::ConsensusHookPtr(nullptr);
          }));
    }

    //
    // funcs in state "readingPublicLedger" or "readingPrivateLedger"
    //
    void recover_ledger_end()
    {
      std::lock_guard<std::mutex> guard(lock);

      if (is_reading_public_ledger())
      {
        recover_public_ledger_end_unsafe();
      }
      else if (is_reading_private_ledger())
      {
        recover_private_ledger_end_unsafe();
      }
      else
      {
        LOG_FAIL_FMT(
          "Node in state {} cannot finalise ledger recovery", sm.value());
        return;
      }
    }

    //
    // funcs in state "partOfPublicNetwork"
    //
    void setup_private_recovery_store()
    {
      recovery_store = std::make_shared<kv::Store>(
        true /* Check transactions in order */,
        true /* Make use of historical secrets */);
      auto recovery_history = std::make_shared<MerkleTxHistory>(
        *recovery_store.get(),
        self,
        *node_sign_kp,
        sig_tx_interval,
        sig_ms_interval,
        false /* No signature timer on recovery_history */);

      auto recovery_encryptor = make_encryptor();

      recovery_store->set_history(recovery_history);
      recovery_store->set_encryptor(recovery_encryptor);

      // Record real store version and root
      recovery_v = network.tables->current_version();
      auto h = dynamic_cast<MerkleTxHistory*>(history.get());
      recovery_root = h->get_replicated_state_root();

      if (startup_snapshot_info)
      {
        LOG_INFO_FMT(
          "Deserialising private snapshot for recovery ({})",
          startup_snapshot_info->raw.size());
        std::vector<kv::Version> view_history;
        kv::ConsensusHookPtrs hooks;
        auto rc = recovery_store->deserialise_snapshot(
          startup_snapshot_info->raw, hooks, &view_history);
        if (rc != kv::ApplyResult::PASS)
        {
          throw std::logic_error(fmt::format(
            "Could not deserialise snapshot in recovery store: {}", rc));
        }

        startup_snapshot_info.reset();
      }

      LOG_DEBUG_FMT(
        "Recovery store successfully setup at {}. Target recovery seqno: {}",
        recovery_store->current_version(),
        recovery_v);
    }

    void trigger_recovery_shares_refresh(kv::Tx& tx) override
    {
      share_manager.shuffle_recovery_shares(tx);
    }

    void trigger_host_process_launch(
      const std::vector<std::string>& args) override
    {
      LaunchHostProcessMessage msg{args};
      nlohmann::json j = msg;
      auto json = j.dump();
      LOG_DEBUG_FMT("Triggering host process launch: {}", json);
      RINGBUFFER_WRITE_MESSAGE(AppMessage::launch_host_process, to_host, json);
    }

    void transition_service_to_open(kv::Tx& tx) override
    {
      std::lock_guard<std::mutex> guard(lock);

      auto service = tx.rw<Service>(Tables::SERVICE);
      auto service_info = service->get();
      if (!service_info.has_value())
      {
        throw std::logic_error(
          "Service information cannot be found to transition service to open");
      }

      // Idempotence: if the service is already open or waiting for recovery
      // shares, this function should succeed with no effect
      if (
        service_info->status == ServiceStatus::WAITING_FOR_RECOVERY_SHARES ||
        service_info->status == ServiceStatus::OPEN)
      {
        LOG_DEBUG_FMT(
          "Service in state {} is already open", service_info->status);
        return;
      }

      if (is_part_of_public_network())
      {
        // If the node is in public mode, start accepting member recovery
        // shares
        share_manager.clear_submitted_recovery_shares(tx);
        service_info->status = ServiceStatus::WAITING_FOR_RECOVERY_SHARES;
        service->put(service_info.value());
        return;
      }
      else if (is_part_of_network())
      {
        // Otherwise, if the node is part of the network. Open the network
        // straight away. Recovery shares are allocated to each recovery member.
        try
        {
          share_manager.issue_recovery_shares(tx);
        }
        catch (const std::logic_error& e)
        {
          throw std::logic_error(
            fmt::format("Failed to issue recovery shares: {}", e.what()));
        }

        GenesisGenerator g(network, tx);
        if (g.open_service())
        {
          open_user_frontend();
        }
        return;
      }
      else
      {
        throw std::logic_error(
          fmt::format("Node in state {} cannot open service", sm.value()));
      }
    }

    void initiate_private_recovery(kv::Tx& tx) override
    {
      std::lock_guard<std::mutex> guard(lock);
      sm.expect(State::partOfPublicNetwork);

      auto restored_ledger_secrets = share_manager.restore_recovery_shares_info(
        tx, std::move(recovery_ledger_secrets));

      // Broadcast decrypted ledger secrets to other nodes for them to initiate
      // private recovery too
      LedgerSecretsBroadcast::broadcast_some(
        network, self, tx, restored_ledger_secrets);

      network.ledger_secrets->restore_historical(
        std::move(restored_ledger_secrets));

      LOG_INFO_FMT("Initiating end of recovery (primary)");

      // Emit signature to certify transactions that happened on public
      // network
      history->emit_signature();

      setup_private_recovery_store();
      reset_recovery_hook();

      // Start reading private security domain of ledger
      ledger_idx = recovery_store->current_version();
      read_ledger_idx(++ledger_idx);

      sm.advance(State::readingPrivateLedger);
    }

    //
    // funcs in state "partOfNetwork" or "partOfPublicNetwork"
    //
    void tick(std::chrono::milliseconds elapsed)
    {
      if (
        !sm.check(State::partOfNetwork) &&
        !sm.check(State::partOfPublicNetwork) &&
        !sm.check(State::readingPrivateLedger))
      {
        return;
      }

      consensus->periodic(elapsed);
    }

    void tick_end()
    {
      if (
        !sm.check(State::partOfNetwork) &&
        !sm.check(State::partOfPublicNetwork) &&
        !sm.check(State::readingPrivateLedger))
      {
        return;
      }

      consensus->periodic_end();
    }

    void node_msg(const std::vector<uint8_t>& data)
    {
      // Only process messages once part of network
      if (
        !sm.check(State::partOfNetwork) &&
        !sm.check(State::partOfPublicNetwork) &&
        !sm.check(State::readingPrivateLedger))
      {
        return;
      }

      OArray oa(std::move(data));
      NodeMsgType msg_type =
        serialized::overlay<NodeMsgType>(oa.data(), oa.size());
      NodeId from = serialized::read<NodeId::Value>(oa.data(), oa.size());

      switch (msg_type)
      {
        case channel_msg:
        {
          n2n_channels->recv_message(from, std::move(oa));
          break;
        }
        case consensus_msg:
        {
          consensus->recv_message(from, std::move(oa));
          break;
        }

        default:
        {
          LOG_FAIL_FMT("Unknown node message type: {}", msg_type);
          return;
        }
      }
    }

    //
    // always available
    //
    bool is_primary() const override
    {
      return (
        (sm.check(State::partOfNetwork) ||
         sm.check(State::partOfPublicNetwork) ||
         sm.check(State::readingPrivateLedger)) &&
        consensus->is_primary());
    }

    bool can_replicate() override
    {
      return (
        (sm.check(State::partOfNetwork) ||
         sm.check(State::partOfPublicNetwork) ||
         sm.check(State::readingPrivateLedger)) &&
        consensus->can_replicate());
    }

    bool is_part_of_network() const override
    {
      return sm.check(State::partOfNetwork);
    }

    bool is_reading_public_ledger() const override
    {
      return sm.check(State::readingPublicLedger);
    }

    bool is_reading_private_ledger() const override
    {
      return sm.check(State::readingPrivateLedger);
    }

    bool is_verifying_snapshot() const override
    {
      return sm.check(State::verifyingSnapshot);
    }

    bool is_part_of_public_network() const override
    {
      return sm.check(State::partOfPublicNetwork);
    }

    ExtendedState state() override
    {
      std::lock_guard<std::mutex> guard(lock);
      State s = sm.value();
      if (s == State::readingPrivateLedger)
      {
        return {s, recovery_v, recovery_store->current_version()};
      }
      else
      {
        return {s, std::nullopt, std::nullopt};
      }
    }

    bool rekey_ledger(kv::Tx& tx) override
    {
      std::lock_guard<std::mutex> guard(lock);
      sm.expect(State::partOfNetwork);

      // The ledger should not be re-keyed when the service is not open because:
      // - While waiting for recovery shares, the submitted shares are stored
      // in a public table, encrypted with the ledger secret generated at
      // startup of the first recovery node
      // - On recovery, historical ledger secrets can only be looked up in the
      // ledger once all ledger secrets have been restored
      GenesisGenerator g(network, tx);
      if (g.get_service_status().value() != ServiceStatus::OPEN)
      {
        LOG_FAIL_FMT("Cannot rekey ledger while the service is not open");
        return false;
      }

      // Effects of ledger rekey are only observed from the next transaction,
      // once the local hook on the secrets table has been triggered.

      auto new_ledger_secret = make_ledger_secret();
      share_manager.issue_recovery_shares(tx, new_ledger_secret);
      LedgerSecretsBroadcast::broadcast_new(
        network, tx, std::move(new_ledger_secret));

      return true;
    }

    NodeId get_node_id() const override
    {
      return self;
    }

    std::optional<kv::Version> get_startup_snapshot_seqno() override
    {
      std::lock_guard<std::mutex> guard(lock);
      return startup_seqno;
    }

    SessionMetrics get_session_metrics() override
    {
      SessionMetrics sm;
      rpcsessions->get_stats(sm.active, sm.peak, sm.soft_cap, sm.hard_cap);
      return sm;
    }

  private:
    crypto::SubjectAltName get_subject_alt_name()
    {
      // If a domain is passed at node creation, record domain in SAN for node
      // hostname authentication over TLS. Otherwise, record IP in SAN.
      bool san_is_ip = config.domain.empty();
      return {san_is_ip ? config.node_info_network.rpchost : config.domain,
              san_is_ip};
    }

    std::vector<crypto::SubjectAltName> get_subject_alternative_names()
    {
      std::vector<crypto::SubjectAltName> sans =
        config.subject_alternative_names;
      sans.push_back(get_subject_alt_name());
      return sans;
    }

    Pem create_self_signed_node_cert()
    {
      auto sans = get_subject_alternative_names();
      return node_sign_kp->self_sign(config.subject_name, sans);
    }

    Pem create_endorsed_node_cert()
    {
      auto nw = crypto::make_key_pair(network.identity->priv_key);
      auto csr = node_sign_kp->create_csr(config.subject_name);
      auto sans = get_subject_alternative_names();
      return nw->sign_csr(network.identity->cert, csr, sans);
    }

    void accept_node_tls_connections()
    {
      // Accept TLS connections, presenting self-signed (i.e. non-endorsed)
      // node certificate. Once the node is part of the network, this
      // certificate should be replaced with network-endorsed counterpart

      assert(!node_cert.empty());
      rpcsessions->set_cert(node_cert, node_sign_kp->private_key_pem());
      LOG_INFO_FMT("Node TLS connections now accepted");
    }

    void accept_network_tls_connections()
    {
      // Accept TLS connections, presenting node certificate signed by network
      // certificate

      assert(!node_cert.empty() && !make_verifier(node_cert)->is_self_signed());
      rpcsessions->set_cert(node_cert, node_sign_kp->private_key_pem());
      LOG_INFO_FMT("Network TLS connections now accepted");
    }

    void open_frontend(
      ccf::ActorsType actor,
      std::optional<crypto::Pem*> identity = std::nullopt)
    {
      auto fe = rpc_map->find(actor);
      if (!fe.has_value())
      {
        throw std::logic_error(
          fmt::format("Cannot open {} frontend", (int)actor));
      }
      fe.value()->open(identity);
    }

    void open_user_frontend() override
    {
      open_frontend(ccf::ActorsType::users, &network.identity->cert);
    }

    std::vector<uint8_t> serialize_create_request(const QuoteInfo& quote_info)
    {
      CreateNetworkNodeToNode::In create_params;

      for (const auto& m_info : config.genesis.members_info)
      {
        create_params.members_info.push_back(m_info);
      }

      create_params.constitution = config.genesis.constitution;
      create_params.node_id = self;
      create_params.node_cert = node_cert;
      create_params.network_cert = network.identity->cert;
      create_params.quote_info = quote_info;
      create_params.public_encryption_key = node_encrypt_kp->public_key_pem();
      create_params.code_digest = node_code_id;
      create_params.node_info_network = config.node_info_network;
      create_params.configuration = {config.genesis.recovery_threshold,
                                     network.consensus_type};

      const auto body = serdes::pack(create_params, serdes::Pack::Text);

      http::Request request(fmt::format(
        "/{}/{}", ccf::get_actor_prefix(ccf::ActorsType::members), "create"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      request.set_body(&body);

      auto node_cert_der = crypto::cert_pem_to_der(node_cert);
      const auto key_id = crypto::Sha256Hash(node_cert_der).hex_str();

      http::sign_request(request, node_sign_kp, key_id);

      return request.build_request();
    }

    bool parse_create_response(const std::vector<uint8_t>& response)
    {
      http::SimpleResponseProcessor processor;
      http::ResponseParser parser(processor);

      parser.execute(response.data(), response.size());

      if (processor.received.size() != 1)
      {
        LOG_FAIL_FMT(
          "Expected single message, found {}", processor.received.size());
        return false;
      }

      const auto& r = processor.received.front();

      if (r.status != HTTP_STATUS_OK)
      {
        LOG_FAIL_FMT(
          "Create response is error: {} {}",
          r.status,
          http_status_str(r.status));
        return false;
      }

      const auto body = serdes::unpack(r.body, serdes::Pack::Text);
      if (!body.is_boolean())
      {
        LOG_FAIL_FMT("Expected boolean body in create response");
        LOG_DEBUG_FMT(
          "Expected boolean body in create response: {}", body.dump());
        return false;
      }

      return body;
    }

    bool send_create_request(const std::vector<uint8_t>& packed)
    {
      auto node_session = std::make_shared<enclave::SessionContext>(
        enclave::InvalidSessionId, node_cert.raw());
      auto ctx = enclave::make_rpc_context(node_session, packed);

      ctx->is_create_request = true;

      const auto actor_opt = http::extract_actor(*ctx);
      if (!actor_opt.has_value())
      {
        throw std::logic_error("Unable to get actor for create request");
      }

      const auto actor = rpc_map->resolve(actor_opt.value());
      auto frontend_opt = this->rpc_map->find(actor);
      if (!frontend_opt.has_value())
      {
        throw std::logic_error(
          "RpcMap::find returned invalid (empty) frontend");
      }
      auto frontend = frontend_opt.value();

      const auto response = frontend->process(ctx);
      if (!response.has_value())
      {
        return false;
      }

      return parse_create_response(response.value());
    }

    bool create_and_send_request()
    {
      const auto create_success =
        send_create_request(serialize_create_request(quote_info));
      if (network.consensus_type == ConsensusType::BFT)
      {
        return true;
      }
      else
      {
        return create_success;
      }
    }

    void backup_initiate_private_recovery()
    {
      if (!consensus->is_backup())
        return;

      sm.expect(State::partOfPublicNetwork);

      LOG_INFO_FMT("Initiating end of recovery (backup)");

      setup_private_recovery_store();

      reset_recovery_hook();
      setup_one_off_secret_hook();

      // Start reading private security domain of ledger
      ledger_idx = recovery_store->current_version();
      read_ledger_idx(++ledger_idx);

      sm.advance(State::readingPrivateLedger);
    }

    void setup_basic_hooks()
    {
      network.tables->set_map_hook(
        network.secrets.get_name(),
        network.secrets.wrap_map_hook(
          [this](kv::Version hook_version, const Secrets::Write& w)
            -> kv::ConsensusHookPtr {
            LedgerSecretsMap restored_ledger_secrets;

            if (w.size() > 1)
            {
              throw std::logic_error(fmt::format(
                "Transaction contains {} writes to map {}, expected one",
                w.size(),
                network.secrets.get_name()));
            }

            auto ledger_secrets_for_nodes = w.at(0);
            if (!ledger_secrets_for_nodes.has_value())
            {
              throw std::logic_error(fmt::format(
                "Removal from {} table", network.secrets.get_name()));
            }

            for (const auto& [node_id, encrypted_ledger_secrets] :
                 ledger_secrets_for_nodes.value())
            {
              if (node_id != self)
              {
                // Only consider ledger secrets for this node
                continue;
              }

              for (const auto& encrypted_ledger_secret :
                   encrypted_ledger_secrets)
              {
                auto plain_ledger_secret = LedgerSecretsBroadcast::decrypt(
                  node_encrypt_kp, encrypted_ledger_secret.encrypted_secret);

                // On rekey, the version is inferred from the version at which
                // the hook is executed. Otherwise, on recovery, use the version
                // read from the write set.
                kv::Version ledger_secret_version =
                  encrypted_ledger_secret.version.value_or(hook_version);

                if (is_part_of_public_network())
                {
                  // On recovery, accumulate restored ledger secrets
                  restored_ledger_secrets.emplace(
                    ledger_secret_version,
                    std::make_shared<LedgerSecret>(
                      std::move(plain_ledger_secret),
                      encrypted_ledger_secret.previous_secret_stored_version));
                }
                else
                {
                  // When rekeying, set the encryption key for the next version
                  // onward (backups deserialise this transaction with the
                  // previous ledger secret)
                  network.ledger_secrets->set_secret(
                    ledger_secret_version + 1,
                    std::make_shared<LedgerSecret>(
                      std::move(plain_ledger_secret), hook_version));
                }
              }
            }

            if (!restored_ledger_secrets.empty() && is_part_of_public_network())
            {
              // When recovering, restore ledger secrets and trigger end of
              // recovery protocol (backup only)
              network.ledger_secrets->restore_historical(
                std::move(restored_ledger_secrets));
              backup_initiate_private_recovery();
            }

            return kv::ConsensusHookPtr(nullptr);
          }));
    }

    kv::Version get_last_recovered_signed_idx() override
    {
      // On recovery, only one node recovers the public ledger and is thus
      // aware of the version at which the new ledger secret is applicable
      // from. If the primary changes while the network is public-only, the
      // new primary should also know at which version the new ledger secret
      // is applicable from.
      std::lock_guard<std::mutex> guard(lock);
      return last_recovered_signed_idx;
    }

    void setup_recovery_hook()
    {
      network.tables->set_map_hook(
        network.encrypted_ledger_secrets.get_name(),
        network.encrypted_ledger_secrets.wrap_map_hook(
          [this](
            kv::Version version, const EncryptedLedgerSecretsInfo::Write& w)
            -> kv::ConsensusHookPtr {
            if (w.size() > 1)
            {
              throw std::logic_error(fmt::format(
                "Transaction contains {} writes to map {}, expected one",
                w.size(),
                network.encrypted_ledger_secrets.get_name()));
            }

            auto encrypted_ledger_secret_info = w.at(0);
            if (!encrypted_ledger_secret_info.has_value())
            {
              throw std::logic_error(fmt::format(
                "Removal from {} table",
                network.encrypted_ledger_secrets.get_name()));
            }

            // If the version of the next ledger secret is not set, deduce it
            // from the hook version (i.e. ledger rekey)
            if (!encrypted_ledger_secret_info->next_version.has_value())
            {
              encrypted_ledger_secret_info->next_version = version + 1;
            }

            if (encrypted_ledger_secret_info->previous_ledger_secret
                  .has_value())
            {
              LOG_DEBUG_FMT(
                "Recovery encrypted ledger secret valid at seqno {}",
                encrypted_ledger_secret_info->previous_ledger_secret->version);
            }

            recovery_ledger_secrets.emplace_back(
              std::move(encrypted_ledger_secret_info.value()));

            return kv::ConsensusHookPtr(nullptr);
          }));
    }

    void reset_recovery_hook()
    {
      network.tables->unset_map_hook(
        network.encrypted_ledger_secrets.get_name());
    }

    void setup_n2n_channels()
    {
      n2n_channels->initialize(
        self, network.identity->cert, node_sign_kp, node_cert);
    }

    void setup_cmd_forwarder()
    {
      cmd_forwarder->initialize(self);
    }

    void setup_raft(bool public_only = false)
    {
      setup_n2n_channels();
      setup_cmd_forwarder();
      setup_tracker_store();

      auto request_tracker = std::make_shared<aft::RequestTracker>();
      auto view_change_tracker = std::make_unique<aft::ViewChangeTracker>(
        tracker_store,
        std::chrono::milliseconds(consensus_config.raft_election_timeout));
      auto shared_state = std::make_shared<aft::State>(self);
      auto raft = std::make_unique<RaftType>(
        network.consensus_type,
        std::make_unique<aft::Adaptor<kv::Store>>(network.tables),
        std::make_unique<consensus::LedgerEnclave>(writer_factory),
        n2n_channels,
        snapshotter,
        rpcsessions,
        rpc_map,
        node_cert.raw(),
        shared_state,
        std::make_shared<aft::ExecutorImpl>(shared_state, rpc_map, rpcsessions),
        request_tracker,
        std::move(view_change_tracker),
        std::chrono::milliseconds(consensus_config.raft_request_timeout),
        std::chrono::milliseconds(consensus_config.raft_election_timeout),
        std::chrono::milliseconds(consensus_config.bft_view_change_timeout),
        sig_tx_interval,
        public_only);

      consensus = std::make_shared<RaftConsensusType>(
        std::move(raft), network.consensus_type);

      network.tables->set_consensus(consensus);
      cmd_forwarder->set_request_tracker(request_tracker);

      // When a node is added, even locally, inform consensus so that it
      // can add a new active configuration.
      network.tables->set_map_hook(
        network.nodes.get_name(),
        network.nodes.wrap_map_hook(
          [](kv::Version version, const Nodes::Write& w)
            -> kv::ConsensusHookPtr {
            return std::make_unique<ConfigurationChangeHook>(version, w);
          }));

      setup_basic_hooks();
    }

    void setup_history()
    {
      history = std::make_shared<MerkleTxHistory>(
        *network.tables.get(),
        self,
        *node_sign_kp,
        sig_tx_interval,
        sig_ms_interval,
        true);

      network.tables->set_history(history);
    }

    void setup_encryptor()
    {
      // This function makes use of ledger secrets and should be called once
      // the node has joined the service
      encryptor = make_encryptor();
      network.tables->set_encryptor(encryptor);
    }

    void setup_consensus(bool public_only = false)
    {
      setup_raft(public_only);
    }

    void setup_progress_tracker()
    {
      if (network.consensus_type == ConsensusType::BFT)
      {
        setup_tracker_store();
        progress_tracker =
          std::make_shared<ccf::ProgressTracker>(tracker_store, self);
        network.tables->set_progress_tracker(progress_tracker);
      }
    }

    void setup_snapshotter()
    {
      snapshotter = std::make_shared<Snapshotter>(
        writer_factory, network.tables, config.snapshot_tx_interval);
    }

    void setup_tracker_store()
    {
      if (tracker_store == nullptr)
      {
        tracker_store = std::make_shared<ccf::ProgressTrackerStoreAdapter>(
          *network.tables.get(), *node_sign_kp);
      }
    }

    void read_ledger_idx(consensus::Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(
        consensus::ledger_get,
        to_host,
        idx,
        consensus::LedgerRequestPurpose::Recovery);
    }

    void ledger_truncate(consensus::Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(consensus::ledger_truncate, to_host, idx);
    }
  };
}
