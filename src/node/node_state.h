// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft_consensus.h"
#include "consensus/ledger_enclave.h"
#include "crypto/symmetric_key.h"
#include "ds/logger.h"
#include "enclave/rpc_sessions.h"
#include "encryptor.h"
#include "entities.h"
#include "genesis_gen.h"
#include "history.h"
#include "hooks.h"
#include "network_state.h"
#include "node/jwt_key_auto_refresh.h"
#include "node/progress_tracker.h"
#include "node/rpc/serdes.h"
#include "node_to_node.h"
#include "rpc/frontend.h"
#include "rpc/member_frontend.h"
#include "rpc/serialization.h"
#include "secret_broadcast.h"
#include "secret_share.h"
#include "share_manager.h"
#include "snapshotter.h"
#include "tls/client.h"
#include "tls/entropy.h"

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
    tls::Pem node_cert;
    tls::Pem network_cert;
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
    SpinLock lock;

    static constexpr NodeId invalid_node_id = -1;
    NodeId self = invalid_node_id;
    tls::KeyPairPtr node_sign_kp;
    tls::KeyPairPtr node_encrypt_kp;
    tls::Pem node_cert;
    tls::CurveID curve_id;
    QuoteInfo quote_info;
    CodeDigest node_code_id;
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
    std::shared_ptr<kv::TxHistory> recovery_history;
    std::shared_ptr<kv::AbstractTxEncryptor> recovery_encryptor;

    kv::Version recovery_v;
    crypto::Sha256Hash recovery_root;
    std::vector<kv::Version> view_history;
    consensus::Index last_recovered_signed_idx = 1;
    RecoveredEncryptedLedgerSecrets recovery_ledger_secrets;
    consensus::Index ledger_idx = 0;

    struct StartupSnapshotInfo
    {
      std::vector<uint8_t>& raw;
      consensus::Index seqno;
      consensus::Index evidence_seqno;

      bool has_evidence = false;
      // The snapshot to startup from (on join or recovery) is only valid once a
      // signature ledger entry confirms that the snapshot evidence was
      // committed
      bool is_evidence_committed = false;

      StartupSnapshotInfo(
        std::vector<uint8_t>& raw_,
        consensus::Index seqno_,
        consensus::Index evidence_seqno_) :
        raw(raw_),
        seqno(seqno_),
        evidence_seqno(evidence_seqno_)
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

    void initialise_startup_snapshot(CCFConfig& config)
    {
      LOG_INFO_FMT(
        "Deserialising public snapshot ({})", config.startup_snapshot.size());
      kv::ConsensusHookPtrs hooks;
      auto rc = network.tables->deserialise_snapshot(
        config.startup_snapshot, hooks, &view_history, true);
      if (rc != kv::ApplyResult::PASS)
      {
        throw std::logic_error(
          fmt::format("Failed to apply public snapshot: {}", rc));
      }

      LOG_INFO_FMT(
        "Public snapshot deserialised at seqno {}",
        network.tables->current_version());

      ledger_idx = network.tables->current_version();
      last_recovered_signed_idx = ledger_idx;

      startup_snapshot_info = std::make_unique<StartupSnapshotInfo>(
        config.startup_snapshot,
        ledger_idx,
        config.startup_snapshot_evidence_seqno);
    }

    //
    // JWT key auto-refresh
    //
    std::shared_ptr<JwtKeyAutoRefresh> jwt_key_auto_refresh;

  public:
    NodeState(
      ringbuffer::AbstractWriterFactory& writer_factory,
      NetworkState& network,
      std::shared_ptr<enclave::RPCSessions> rpcsessions,
      ShareManager& share_manager,
      const CurveID& curve_id) :
      sm(State::uninitialized),
      self(INVALID_ID),
      node_sign_kp(tls::make_key_pair(curve_id)),
      node_encrypt_kp(tls::make_key_pair(curve_id)),
      writer_factory(writer_factory),
      to_host(writer_factory.create_writer_to_outside()),
      network(network),
      rpcsessions(rpcsessions),
      share_manager(share_manager)
    {}

    QuoteVerificationResult verify_quote(
      kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const tls::Pem& expected_node_public_key) override
    {
#ifdef GET_QUOTE
      return enclave_attestation_provider.verify_quote_against_store(
        tx, quote_info, expected_node_public_key);
#else
      (void)tx;
      (void)quote_info;
      (void)expected_node_public_key;
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
      std::lock_guard<SpinLock> guard(lock);
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
    NodeCreateInfo create(StartType start_type, CCFConfig& config)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::initialized);

      create_node_cert(config);
      open_frontend(ActorsType::nodes);

      curve_id = config.curve_id;

#ifdef GET_QUOTE
      quote_info = enclave_attestation_provider.generate_quote(
        node_sign_kp->public_key_pem());
      node_code_id = enclave_attestation_provider.get_code_id(quote_info);
#endif

      switch (start_type)
      {
        case StartType::New:
        {
          set_node_id(0); // The first node id is always 0
          network.identity =
            std::make_unique<NetworkIdentity>("CN=CCF Network");

          network.ledger_secrets = std::make_shared<LedgerSecrets>(self);
          network.ledger_secrets->init();

          setup_snapshotter(config.snapshot_tx_interval);
          setup_encryptor();
          setup_consensus();
          setup_progress_tracker();
          setup_history();

          // Become the primary and force replication
          consensus->force_become_primary();

          // Open member frontend for members to configure and open the
          // network
          open_frontend(ActorsType::members);

          if (!create_and_send_request(config))
          {
            throw std::runtime_error(
              "Genesis transaction could not be committed");
          }

          accept_network_tls_connections(config);
          auto_refresh_jwt_keys(config);

          reset_data(quote_info.quote);
          reset_data(quote_info.endorsements);
          sm.advance(State::partOfNetwork);

          return {node_cert, network.identity->cert};
        }
        case StartType::Join:
        {
          // TLS connections are not endorsed by the network until the node
          // has joined
          accept_node_tls_connections();
          auto_refresh_jwt_keys(config);

          if (!config.startup_snapshot.empty())
          {
            setup_history();

            // It is necessary to give an encryptor to the store for it to
            // deserialise the public domain when recovering the public ledger
            network.ledger_secrets = std::make_shared<LedgerSecrets>();
            setup_encryptor();
            setup_snapshotter(config.snapshot_tx_interval);

            initialise_startup_snapshot(config);

            sm.advance(State::verifyingSnapshot);
          }
          else
          {
            sm.advance(State::pending);
          }

          return {node_cert, {}};
        }
        case StartType::Recover:
        {
          node_info_network = config.node_info_network;

          network.identity =
            std::make_unique<NetworkIdentity>("CN=CCF Network");
          network.ledger_secrets = std::make_shared<LedgerSecrets>();

          setup_history();

          // It is necessary to give an encryptor to the store for it to
          // deserialise the public domain when recovering the public ledger.
          // Once the public recovery is complete, the existing encryptor is
          // replaced with a new one initialised with the recovered ledger
          // secrets.
          setup_encryptor();

          setup_snapshotter(config.snapshot_tx_interval);
          bool from_snapshot = !config.startup_snapshot.empty();
          setup_recovery_hook();

          if (from_snapshot)
          {
            initialise_startup_snapshot(config);
            snapshotter->set_last_snapshot_idx(ledger_idx);
          }

          accept_network_tls_connections(config);
          auto_refresh_jwt_keys(config);

          sm.advance(State::readingPublicLedger);
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
    void initiate_join(CCFConfig& config)
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
        [this, &config](
          http_status status, http::HeaderMap&&, std::vector<uint8_t>&& data) {
          std::lock_guard<SpinLock> guard(lock);
          if (!sm.check(State::pending))
          {
            return false;
          }

          if (status != HTTP_STATUS_OK)
          {
            LOG_FAIL_FMT(
              "An error occurred while joining the network: {} {}{}",
              status,
              http_status_str(status),
              data.empty() ?
                "" :
                fmt::format("  '{}'", std::string(data.begin(), data.end())));
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
          if (resp.node_status == NodeStatus::TRUSTED)
          {
            set_node_id(resp.node_id);
            network.identity =
              std::make_unique<NetworkIdentity>(resp.network_info.identity);

            network.ledger_secrets = std::make_shared<LedgerSecrets>(
              self, std::move(resp.network_info.ledger_secrets));

            if (resp.network_info.consensus_type != network.consensus_type)
            {
              throw std::logic_error(fmt::format(
                "Enclave initiated with consensus type {} but target node "
                "responded with consensus {}",
                network.consensus_type,
                resp.network_info.consensus_type));
            }

            setup_snapshotter(config.snapshot_tx_interval);
            setup_encryptor();
            setup_consensus(resp.network_info.public_only);
            setup_progress_tracker();
            setup_history();

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
              auto sig = signatures->get(0);
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

            accept_network_tls_connections(config);

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

    void start_join_timer(CCFConfig& config)
    {
      initiate_join(config);

      struct JoinTimeMsg
      {
        JoinTimeMsg(NodeState& self_, CCFConfig& config_) :
          self(self_),
          config(config_)
        {}

        NodeState& self;
        CCFConfig& config;
      };

      auto join_timer_msg = std::make_unique<threading::Tmsg<JoinTimeMsg>>(
        [](std::unique_ptr<threading::Tmsg<JoinTimeMsg>> msg) {
          if (msg->data.self.sm.check(State::pending))
          {
            msg->data.self.initiate_join(msg->data.config);
            auto delay =
              std::chrono::milliseconds(msg->data.config.joining.join_timer);

            threading::ThreadMessaging::thread_messaging.add_task_after(
              std::move(msg), delay);
          }
        },
        *this,
        config);

      threading::ThreadMessaging::thread_messaging.add_task_after(
        std::move(join_timer_msg),
        std::chrono::milliseconds(config.joining.join_timer));
    }

    void join(CCFConfig& config)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::pending);
      start_join_timer(config);
    }

    void auto_refresh_jwt_keys(const CCFConfig& config)
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
      std::lock_guard<SpinLock> guard(lock);
      if (
        !sm.check(State::readingPublicLedger) &&
        !sm.check(State::verifyingSnapshot))
      {
        throw std::logic_error(fmt::format(
          "Node should be in state {} or {} to recover public ledger entry",
          State::readingPublicLedger,
          State::verifyingSnapshot));
      }

      LOG_INFO_FMT("Starting public recovery");
      read_ledger_idx(++ledger_idx);
    }

    void recover_public_ledger_entry(const std::vector<uint8_t>& ledger_entry)
    {
      std::lock_guard<SpinLock> guard(lock);
      if (
        !sm.check(State::readingPublicLedger) &&
        !sm.check(State::verifyingSnapshot))
      {
        throw std::logic_error(fmt::format(
          "Node should be in state {} or {} to recover public ledger entry",
          State::readingPublicLedger,
          State::verifyingSnapshot));
      }

      LOG_INFO_FMT(
        "Deserialising public ledger entry ({})", ledger_entry.size());

      // When reading the public ledger, deserialise in the real store
      auto r = network.tables->apply(ledger_entry, ConsensusType::CFT, true);
      auto result = r->execute();
      if (result == kv::ApplyResult::FAIL)
      {
        LOG_FAIL_FMT("Failed to deserialise entry in public ledger");
        network.tables->rollback(ledger_idx - 1);
        if (sm.check(State::verifyingSnapshot))
        {
          throw std::logic_error(
            "Error deserialising public ledger entry when verifying snapshot");
        }
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
        network.tables->compact(ledger_idx);
        auto tx = network.tables->create_tx();
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
          last_sig->commit_seqno >= startup_snapshot_info->evidence_seqno)
        {
          startup_snapshot_info->is_evidence_committed = true;
        }

        // Inform snapshotter of all signature entries so that this node can
        // continue generating snapshots at the correct interval once the
        // recovery is complete
        snapshotter->record_committable(ledger_idx);
        snapshotter->commit(ledger_idx);
      }
      else if (
        result == kv::ApplyResult::PASS_SNAPSHOT_EVIDENCE &&
        startup_snapshot_info)
      {
        auto tx = network.tables->create_read_only_tx();
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

    void verify_snapshot_end(CCFConfig& config)
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::verifyingSnapshot);

      if (
        !startup_snapshot_info ||
        !startup_snapshot_info->is_snapshot_verified())
      {
        throw std::logic_error("Snapshot evidence was not committed in ledger");
      }

      network.tables->clear();
      ledger_truncate(startup_snapshot_info->seqno);

      sm.advance(State::pending);
      start_join_timer(config);
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

      set_node_id(g.add_node({node_info_network,
                              node_cert,
                              quote_info,
                              node_encrypt_kp->public_key_pem().raw(),
                              NodeStatus::PENDING}));

      LOG_INFO_FMT("Deleted previous nodes and added self as {}", self);

      network.ledger_secrets->init(last_recovered_signed_idx + 1);
      network.ledger_secrets->set_node_id(self);
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

      setup_raft(true);

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

      if (g.finalize() != kv::CommitResult::SUCCESS)
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
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::readingPrivateLedger);

      LOG_INFO_FMT(
        "Deserialising private ledger entry ({})", ledger_entry.size());

      // When reading the private ledger, deserialise in the recovery store
      auto result =
        recovery_store->apply(ledger_entry, ConsensusType::CFT)->execute();
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

      auto h = dynamic_cast<MerkleTxHistory*>(recovery_history.get());
      if (h->get_replicated_state_root() != recovery_root)
      {
        throw std::logic_error(fmt::format(
          "Root of public store does not match root of private store at {}",
          recovery_v));
      }

      network.tables->swap_private_maps(*recovery_store.get());
      recovery_history.reset();
      recovery_store.reset();
      reset_recovery_hook();

      // Raft should deserialise all security domains when network is opened
      consensus->enable_all_domains();

      // Snapshots are only generated after recovery is complete
      snapshotter->set_snapshot_generation(true);

      // Open the service
      if (consensus->is_primary())
      {
        auto tx = network.tables->create_tx();

        // Shares for the new ledger secret can only be issued now, once the
        // previous ledger secrets have been recovered
        share_manager.issue_recovery_shares(tx);
        GenesisGenerator g(network, tx);
        if (!g.open_service())
        {
          throw std::logic_error("Service could not be opened");
        }

        if (g.finalize() != kv::CommitResult::SUCCESS)
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

    //
    // funcs in state "readingPublicLedger" or "readingPrivateLedger"
    //
    void recover_ledger_end()
    {
      std::lock_guard<SpinLock> guard(lock);

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
        throw std::logic_error(
          "Cannot end ledger recovery if not reading public or private "
          "ledger");
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
      recovery_history = std::make_shared<MerkleTxHistory>(
        *recovery_store.get(),
        self,
        *node_sign_kp,
        sig_tx_interval,
        sig_ms_interval,
        false /* No signature timer on recovery_history */);

#ifdef USE_NULL_ENCRYPTOR
      recovery_encryptor = std::make_shared<kv::NullTxEncryptor>();
#else
      recovery_encryptor =
        std::make_shared<NodeEncryptor>(network.ledger_secrets);
#endif

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

    bool accept_recovery(kv::Tx& tx) override
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::partOfPublicNetwork);

      GenesisGenerator g(network, tx);
      share_manager.clear_submitted_recovery_shares(tx);
      return g.service_wait_for_shares();
    }

    void initiate_private_recovery(kv::Tx& tx) override
    {
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::partOfPublicNetwork);

      auto restored_ledger_secrets = share_manager.restore_recovery_shares_info(
        tx, std::move(recovery_ledger_secrets));

      // Broadcast decrypted ledger secrets to other nodes for them to initiate
      // private recovery too
      LedgerSecretsBroadcast::broadcast_some(
        network, node_encrypt_kp, self, tx, restored_ledger_secrets);

      network.ledger_secrets->restore_historical(
        std::move(restored_ledger_secrets));

      LOG_INFO_FMT("Initiating end of recovery (primary)");

      // Emit signature to certify transactions that happened on public
      // network
      history->emit_signature();

      setup_private_recovery_store();

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

      switch (msg_type)
      {
        case channel_msg:
        {
          n2n_channels->recv_message(std::move(oa));
          break;
        }
        case consensus_msg:
        {
          consensus->recv_message(std::move(oa));
          break;
        }

        default:
        {
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
      std::lock_guard<SpinLock> guard(lock);
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
      std::lock_guard<SpinLock> guard(lock);
      sm.expect(State::partOfNetwork);

      // Because submitted recovery shares are encrypted with the latest
      // ledger secret, it is not possible to rekey the ledger if the service
      // is in that state.
      GenesisGenerator g(network, tx);
      if (
        g.get_service_status().value() ==
        ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
      {
        LOG_FAIL_FMT(
          "Cannot rekey ledger while the service is waiting for recovery "
          "shares");
        return false;
      }

      // Effects of ledger rekey are only observed from the next transaction,
      // once the local hook on the secrets table has been triggered.

      auto new_ledger_secret = make_ledger_secret();
      share_manager.issue_recovery_shares(tx, new_ledger_secret);
      LedgerSecretsBroadcast::broadcast_new(
        network, node_encrypt_kp, tx, std::move(new_ledger_secret));

      return true;
    }

    NodeId get_node_id() const override
    {
      return self;
    }

  private:
    void set_node_id(NodeId n)
    {
      LOG_INFO_FMT("Setting self node ID: {}", n);
      if (self != invalid_node_id)
      {
        throw std::logic_error(fmt::format(
          "Trying to reset node ID. Was previously {}, proposed {}", self, n));
      }

      self = n;
    }

    tls::SubjectAltName get_subject_alt_name(const CCFConfig& config)
    {
      // If a domain is passed at node creation, record domain in SAN for node
      // hostname authentication over TLS. Otherwise, record IP in SAN.
      bool san_is_ip = config.domain.empty();
      return {san_is_ip ? config.node_info_network.rpchost : config.domain,
              san_is_ip};
    }

    std::vector<tls::SubjectAltName> get_subject_alternative_names(
      const CCFConfig& config)
    {
      std::vector<tls::SubjectAltName> sans = config.subject_alternative_names;
      sans.push_back(get_subject_alt_name(config));
      return sans;
    }

    void create_node_cert(const CCFConfig& config)
    {
      auto sans = get_subject_alternative_names(config);
      node_cert = node_sign_kp->self_sign(config.subject_name, sans);
    }

    void accept_node_tls_connections()
    {
      // Accept TLS connections, presenting self-signed (i.e. non-endorsed)
      // node certificate. Once the node is part of the network, this
      // certificate should be replaced with network-endorsed counterpart
      rpcsessions->set_cert(node_cert, node_sign_kp->private_key_pem());
      LOG_INFO_FMT("Node TLS connections now accepted");
    }

    void accept_network_tls_connections(const CCFConfig& config)
    {
      // Accept TLS connections, presenting node certificate signed by network
      // certificate
      auto nw = tls::make_key_pair({network.identity->priv_key});

      auto sans = get_subject_alternative_names(config);
      auto endorsed_node_cert = nw->sign_csr(
        node_sign_kp->create_csr(config.subject_name),
        fmt::format("CN={}", "CCF Network"),
        sans);

      rpcsessions->set_cert(
        endorsed_node_cert, node_sign_kp->private_key_pem());
      LOG_INFO_FMT("Network TLS connections now accepted");
    }

    void open_frontend(
      ccf::ActorsType actor, std::optional<tls::Pem*> identity = std::nullopt)
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

    std::vector<uint8_t> serialize_create_request(
      const CCFConfig& config, const QuoteInfo& quote_info)
    {
      CreateNetworkNodeToNode::In create_params;

      for (const auto& m_info : config.genesis.members_info)
      {
        create_params.members_info.push_back(m_info);
      }

      create_params.gov_script = config.genesis.gov_script;
      create_params.node_cert = node_cert;
      create_params.network_cert = network.identity->cert;
      create_params.quote_info = quote_info;
      create_params.public_encryption_key = node_encrypt_kp->public_key_pem();
      create_params.code_digest =
        std::vector<uint8_t>(std::begin(node_code_id), std::end(node_code_id));
      create_params.node_info_network = config.node_info_network;
      create_params.configuration = {config.genesis.recovery_threshold,
                                     network.consensus_type};

      const auto body = serdes::pack(create_params, serdes::Pack::Text);

      http::Request request(fmt::format(
        "/{}/{}", ccf::get_actor_prefix(ccf::ActorsType::members), "create"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      request.set_body(&body);

      const auto contents = node_cert.contents();
      crypto::Sha256Hash hash({contents.data(), contents.size()});
      const std::string key_id = fmt::format("{:02x}", fmt::join(hash.h, ""));

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

    bool create_and_send_request(const CCFConfig& config)
    {
      const auto create_success =
        send_create_request(serialize_create_request(config, quote_info));
      if (network.consensus_type == ConsensusType::BFT)
      {
        return true;
      }
      else
      {
        return create_success;
      }
    }

    void backup_finish_recovery()
    {
      if (!consensus->is_backup())
        return;

      sm.expect(State::partOfPublicNetwork);

      LOG_INFO_FMT("Initiating end of recovery (backup)");

      setup_private_recovery_store();

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

            for (const auto& [node_id, opt_ledger_secret_set] : w)
            {
              if (!opt_ledger_secret_set.has_value())
              {
                throw std::logic_error(fmt::format(
                  "Unexpected: removal from secrets table for node ({})",
                  node_id));
              }

              if (node_id != self)
              {
                // Only consider ledger secrets for this node
                continue;
              }

              const auto& ledger_secret_set = opt_ledger_secret_set.value();

              for (const auto& encrypted_ledger_secret :
                   ledger_secret_set.encrypted_secrets)
              {
                auto plain_ledger_secret = LedgerSecretsBroadcast::decrypt(
                  node_encrypt_kp,
                  tls::make_public_key(
                    ledger_secret_set.primary_public_encryption_key),
                  encrypted_ledger_secret.encrypted_secret);

                // On rekey, the version is inferred from the version at which
                // the hook is executed. Otherwise, on recovery, use the version
                // read from the write set.
                kv::Version ledger_secret_version =
                  encrypted_ledger_secret.version.value_or(hook_version);

                if (is_part_of_public_network())
                {
                  // On recovery, accumulate restored ledger secrets
                  restored_ledger_secrets.emplace(
                    ledger_secret_version, std::move(plain_ledger_secret));
                }
                else
                {
                  // When rekeying, set the encryption key for the next version
                  // onward (backups deserialise this transaction with the
                  // previous ledger secret)
                  network.ledger_secrets->set_secret(
                    ledger_secret_version + 1, std::move(plain_ledger_secret));
                }
              }
            }

            if (!restored_ledger_secrets.empty() && is_part_of_public_network())
            {
              // When recovering, restore ledger secrets and trigger end of
              // recovery protocol (backup only)
              network.ledger_secrets->restore_historical(
                std::move(restored_ledger_secrets));
              backup_finish_recovery();
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
      std::lock_guard<SpinLock> guard(lock);
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
      n2n_channels->initialize(self, {network.identity->priv_key});
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
      // This function can be called once the node has started up and before
      // it has joined the service.
      history = std::make_shared<MerkleTxHistory>(
        *network.tables.get(),
        self,
        *node_sign_kp,
        sig_tx_interval,
        sig_ms_interval);

      network.tables->set_history(history);
    }

    void setup_encryptor()
    {
      // This function makes use of ledger secrets and should be called once
      // the node has joined the service (either via start_network() or
      // join_network())
#ifdef USE_NULL_ENCRYPTOR
      encryptor = std::make_shared<kv::NullTxEncryptor>();
#else
      encryptor = std::make_shared<NodeEncryptor>(network.ledger_secrets);
#endif

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

    void setup_snapshotter(size_t snapshot_tx_interval)
    {
      snapshotter = std::make_shared<Snapshotter>(
        writer_factory, network, snapshot_tx_interval);
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
