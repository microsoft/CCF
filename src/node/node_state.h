// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/entropy.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/ds/logger.h"
#include "ccf/serdes.h"
#include "ccf/service/tables/service.h"
#include "consensus/aft/raft.h"
#include "consensus/ledger_enclave.h"
#include "crypto/certs.h"
#include "ds/state_machine.h"
#include "enclave/reconfiguration_type.h"
#include "enclave/rpc_sessions.h"
#include "encryptor.h"
#include "history.h"
#include "indexing/indexer.h"
#include "js/wrap.h"
#include "network_state.h"
#include "node/attestation_types.h"
#include "node/hooks.h"
#include "node/http_node_client.h"
#include "node/jwt_key_auto_refresh.h"
#include "node/node_to_node_channel_manager.h"
#include "node_to_node.h"
#include "resharing.h"
#include "rpc/frontend.h"
#include "rpc/serialization.h"
#include "secret_broadcast.h"
#include "service/genesis_gen.h"
#include "share_manager.h"
#include "snapshotter.h"
#include "tls/client.h"

#ifdef USE_NULL_ENCRYPTOR
#  include "kv/test/null_encryptor.h"
#endif

#include <atomic>
#include <chrono>
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <unordered_set>
#include <vector>

namespace ccf
{
  using RaftType = aft::Aft<consensus::LedgerEnclave, Snapshotter>;

  struct NodeCreateInfo
  {
    crypto::Pem self_signed_node_cert;
    crypto::Pem service_cert;
  };

  void reset_data(std::vector<uint8_t>& data)
  {
    data.clear();
    data.shrink_to_fit();
  }

#ifdef GET_QUOTE
  static QuoteInfo generate_quote(
    const std::vector<uint8_t>& node_public_key_der)
  {
    QuoteInfo node_quote_info;
    node_quote_info.format = QuoteFormat::oe_sgx_v1;

    crypto::Sha256Hash h{node_public_key_der};

    Evidence evidence;
    Endorsements endorsements;
    SerialisedClaims serialised_custom_claims;

    // Serialise hash of node's public key as a custom claim
    const size_t custom_claim_length = 1;
    oe_claim_t custom_claim;
    custom_claim.name = const_cast<char*>(sgx_report_data_claim_name);
    custom_claim.value = h.h.data();
    custom_claim.value_size = h.SIZE;

    auto rc = oe_serialize_custom_claims(
      &custom_claim,
      custom_claim_length,
      &serialised_custom_claims.buffer,
      &serialised_custom_claims.size);
    if (rc != OE_OK)
    {
      throw std::logic_error(fmt::format(
        "Could not serialise node's public key as quote custom claim: {}",
        oe_result_str(rc)));
    }

    rc = oe_get_evidence(
      &oe_quote_format,
      0,
      serialised_custom_claims.buffer,
      serialised_custom_claims.size,
      nullptr,
      0,
      &evidence.buffer,
      &evidence.size,
      &endorsements.buffer,
      &endorsements.size);
    if (rc != OE_OK)
    {
      throw std::logic_error(
        fmt::format("Failed to get evidence: {}", oe_result_str(rc)));
    }

    node_quote_info.quote.assign(
      evidence.buffer, evidence.buffer + evidence.size);
    node_quote_info.endorsements.assign(
      endorsements.buffer, endorsements.buffer + endorsements.size);

    return node_quote_info;
  }
#endif

  class NodeState : public ccf::AbstractNodeState
  {
  private:
    //
    // this node's core state
    //
    ds::StateMachine<NodeStartupState> sm;
    std::mutex lock;

    crypto::CurveID curve_id;
    std::vector<crypto::SubjectAltName> subject_alt_names = {};

    std::shared_ptr<crypto::KeyPair_OpenSSL> node_sign_kp;
    NodeId self;
    std::shared_ptr<crypto::RSAKeyPair> node_encrypt_kp;
    crypto::Pem self_signed_node_cert;
    std::optional<crypto::Pem> endorsed_node_cert = std::nullopt;
    QuoteInfo quote_info;
    CodeDigest node_code_id;
    StartupConfig config;

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
    std::shared_ptr<ccf::RPCMap> rpc_map;
    std::shared_ptr<ccf::indexing::Indexer> indexer;
    std::shared_ptr<NodeToNode> n2n_channels;
    std::shared_ptr<Forwarder<NodeToNode>> cmd_forwarder;
    std::shared_ptr<ccf::RPCSessions> rpcsessions;

    std::shared_ptr<kv::TxHistory> history;
    std::shared_ptr<kv::AbstractTxEncryptor> encryptor;

    ShareManager& share_manager;
    std::shared_ptr<Snapshotter> snapshotter;

    //
    // recovery
    //
    std::shared_ptr<kv::Store> recovery_store;

    kv::Version recovery_v;
    crypto::Sha256Hash recovery_root;
    std::vector<kv::Version> view_history;
    consensus::Index last_recovered_signed_idx = 0;
    RecoveredEncryptedLedgerSecrets recovered_encrypted_ledger_secrets = {};
    LedgerSecretsMap recovered_ledger_secrets = {};
    consensus::Index ledger_idx = 0;

    //
    // JWT key auto-refresh
    //
    std::shared_ptr<JwtKeyAutoRefresh> jwt_key_auto_refresh;

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

    // Returns true if the snapshot is already verified (via embedded receipt)
    bool initialise_startup_snapshot(bool recovery = false)
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

      kv::ConsensusHookPtrs hooks;
      startup_snapshot_info = initialise_from_snapshot(
        snapshot_store,
        std::move(config.startup_snapshot),
        hooks,
        &view_history,
        true,
        config.startup_snapshot_evidence_seqno_for_1_x,
        config.recover.previous_service_identity);

      startup_seqno = startup_snapshot_info->seqno;
      ledger_idx = startup_seqno.value();
      last_recovered_signed_idx = ledger_idx;

      return !startup_snapshot_info->requires_ledger_verification();
    }

  public:
    NodeState(
      ringbuffer::AbstractWriterFactory& writer_factory,
      NetworkState& network,
      std::shared_ptr<ccf::RPCSessions> rpcsessions,
      ShareManager& share_manager,
      crypto::CurveID curve_id_) :
      sm("NodeState", NodeStartupState::uninitialized),
      curve_id(curve_id_),
      node_sign_kp(std::make_shared<crypto::KeyPair_OpenSSL>(curve_id_)),
      self(compute_node_id_from_kp(node_sign_kp)),
      node_encrypt_kp(crypto::make_rsa_key_pair()),
      writer_factory(writer_factory),
      to_host(writer_factory.create_writer_to_outside()),
      network(network),
      rpcsessions(rpcsessions),
      share_manager(share_manager)
    {}

    QuoteVerificationResult verify_quote(
      kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info,
      const std::vector<uint8_t>& expected_node_public_key_der,
      CodeDigest& code_digest) override
    {
#ifdef GET_QUOTE
      return EnclaveAttestationProvider::verify_quote_against_store(
        tx, quote_info, expected_node_public_key_der, code_digest);
#else
      (void)tx;
      (void)quote_info;
      (void)expected_node_public_key_der;
      (void)code_digest;
      return QuoteVerificationResult::Verified;
#endif
    }

    //
    // funcs in state "uninitialized"
    //
    void initialize(
      const consensus::Configuration& consensus_config_,
      std::shared_ptr<ccf::RPCMap> rpc_map_,
      std::shared_ptr<ccf::AbstractRPCResponder> rpc_sessions_,
      std::shared_ptr<ccf::indexing::Indexer> indexer_,
      size_t sig_tx_interval_,
      size_t sig_ms_interval_)
    {
      std::lock_guard<std::mutex> guard(lock);
      sm.expect(NodeStartupState::uninitialized);

      consensus_config = consensus_config_;
      rpc_map = rpc_map_;
      indexer = indexer_;
      sig_tx_interval = sig_tx_interval_;
      sig_ms_interval = sig_ms_interval_;

      n2n_channels =
        std::make_shared<ccf::NodeToNodeChannelManager>(writer_factory);

      cmd_forwarder = std::make_shared<ccf::Forwarder<ccf::NodeToNode>>(
        rpc_sessions_, n2n_channels, rpc_map, consensus_config.type);

      sm.advance(NodeStartupState::initialized);

      for (auto& [actor, fe] : rpc_map->frontends())
      {
        fe->set_sig_intervals(sig_tx_interval, sig_ms_interval);
        fe->set_cmd_forwarder(cmd_forwarder);
      }
    }

    //
    // funcs in state "initialized"
    //
    NodeCreateInfo create(StartType start_type, StartupConfig&& config_)
    {
      std::lock_guard<std::mutex> guard(lock);
      sm.expect(NodeStartupState::initialized);

      config = std::move(config_);
      subject_alt_names = get_subject_alternative_names();

      js::register_class_ids();
      self_signed_node_cert = create_self_signed_cert(
        node_sign_kp,
        config.node_certificate.subject_name,
        subject_alt_names,
        config.startup_host_time,
        config.node_certificate.initial_validity_days);

      accept_node_tls_connections();
      open_frontend(ActorsType::nodes);

#ifdef GET_QUOTE
      quote_info = generate_quote(node_sign_kp->public_key_der());
      auto code_id = EnclaveAttestationProvider::get_code_id(quote_info);
      if (code_id.has_value())
      {
        node_code_id = code_id.value();
      }
      else
      {
        throw std::logic_error("Failed to extract code id from quote");
      }
#endif

      setup_history();
      setup_snapshotter();
      setup_encryptor();

      switch (start_type)
      {
        case StartType::Start:
        {
          network.identity = std::make_unique<ReplicatedNetworkIdentity>(
            curve_id,
            config.startup_host_time,
            config.initial_service_certificate_validity_days);

          network.ledger_secrets->init();

          if (network.consensus_type == ConsensusType::BFT)
          {
            endorsed_node_cert = create_endorsed_node_cert(
              config.node_certificate.initial_validity_days);
            history->set_endorsed_certificate(endorsed_node_cert.value());
            accept_network_tls_connections();
            open_frontend(ActorsType::members);
          }

          setup_consensus(
            ServiceStatus::OPENING,
            config.start.service_configuration.reconfiguration_type.value_or(
              ReconfigurationType::ONE_TRANSACTION),
            false,
            endorsed_node_cert);

          // Become the primary and force replication
          consensus->force_become_primary();

          if (!create_and_send_boot_request(true /* Create new consortium */))
          {
            throw std::runtime_error(
              "Genesis transaction could not be committed");
          }

          auto_refresh_jwt_keys();

          reset_data(quote_info.quote);
          reset_data(quote_info.endorsements);
          sm.advance(NodeStartupState::partOfNetwork);

          LOG_INFO_FMT("Created new node {}", self);

          return {self_signed_node_cert, network.identity->cert};
        }
        case StartType::Join:
        {
          if (config.startup_snapshot.empty() || initialise_startup_snapshot())
          {
            // Note: 2.x snapshots are self-verified so the ledger verification
            // of its evidence can be skipped entirely
            sm.advance(NodeStartupState::pending);
          }
          else
          {
            // Node joins from a 1.x snapshot
            sm.advance(NodeStartupState::verifyingSnapshot);
          }

          LOG_INFO_FMT("Created join node {}", self);
          return {self_signed_node_cert, {}};
        }
        case StartType::Recover:
        {
          if (!config.recover.previous_service_identity)
          {
            throw std::logic_error(
              "Recovery requires the certificate of the previous service "
              "identity");
          }

          network.identity = std::make_unique<ReplicatedNetworkIdentity>(
            curve_id,
            config.startup_host_time,
            config.initial_service_certificate_validity_days);

          bool from_snapshot = !config.startup_snapshot.empty();
          setup_recovery_hook();

          if (from_snapshot)
          {
            initialise_startup_snapshot(true);
            snapshotter->set_last_snapshot_idx(ledger_idx);
          }

          sm.advance(NodeStartupState::readingPublicLedger);

          LOG_INFO_FMT("Created recovery node {}", self);
          return {self_signed_node_cert, network.identity->cert};
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
      auto network_ca = std::make_shared<tls::CA>(std::string(
        config.join.service_cert.begin(), config.join.service_cert.end()));
      auto join_client_cert = std::make_unique<tls::Cert>(
        network_ca,
        self_signed_node_cert,
        node_sign_kp->private_key_pem(),
        config.join.target_rpc_address);

      // Create RPC client and connect to remote node
      auto join_client =
        rpcsessions->create_client(std::move(join_client_cert));

      auto [target_host, target_port] =
        split_net_address(config.join.target_rpc_address);

      join_client->connect(
        target_host,
        target_port,
        [this](
          http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          std::lock_guard<std::mutex> guard(lock);
          if (!sm.check(NodeStartupState::pending))
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
              config.join.target_rpc_address =
                make_net_address(url.host, url.port);
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
            if (resp.network_info->consensus_type != network.consensus_type)
            {
              throw std::logic_error(fmt::format(
                "Enclave initiated with consensus type {} but target node "
                "responded with consensus {}",
                network.consensus_type,
                resp.network_info->consensus_type));
            }

            network.identity = std::make_unique<ReplicatedNetworkIdentity>(
              resp.network_info->identity);
            network.ledger_secrets->init_from_map(
              std::move(resp.network_info->ledger_secrets));

            crypto::Pem n2n_channels_cert;
            if (!resp.network_info->endorsed_certificate.has_value())
            {
              // Endorsed node certificate is included in join response
              // from 2.x (CFT only). When joining an existing 1.x service,
              // self-sign own certificate and use it to endorse TLS
              // connections.
              endorsed_node_cert = create_endorsed_node_cert(
                default_node_cert_validity_period_days);
              history->set_endorsed_certificate(endorsed_node_cert.value());
              n2n_channels_cert = endorsed_node_cert.value();
              open_frontend(ActorsType::members);
              open_user_frontend();
              accept_network_tls_connections();
            }
            else
            {
              n2n_channels_cert =
                resp.network_info->endorsed_certificate.value();
            }

            setup_consensus(
              resp.network_info->service_status.value_or(
                ServiceStatus::OPENING),
              resp.network_info->reconfiguration_type.value_or(
                ReconfigurationType::ONE_TRANSACTION),
              resp.network_info->public_only,
              n2n_channels_cert);
            auto_refresh_jwt_keys();

            if (resp.network_info->public_only)
            {
              last_recovered_signed_idx =
                resp.network_info->last_recovered_signed_idx;
              setup_recovery_hook();
              snapshotter->set_snapshot_generation(false);
            }

            View view = VIEW_UNKNOWN;
            std::vector<kv::Version> view_history = {};
            if (startup_snapshot_info)
            {
              // It is only possible to deserialise the entire snapshot then,
              // once the ledger secrets have been passed in by the network
              kv::ConsensusHookPtrs hooks;
              deserialise_snapshot(
                network.tables,
                startup_snapshot_info->raw,
                hooks,
                &view_history,
                resp.network_info->public_only,
                startup_snapshot_info->evidence_seqno,
                config.recover.previous_service_identity);

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
              view = sig->view;

              if (!resp.network_info->public_only)
              {
                // Only clear snapshot if not recovering. When joining the
                // public network the snapshot is used later to initialise the
                // recovery store
                startup_snapshot_info.reset();
              }

              LOG_INFO_FMT(
                "Joiner successfully resumed from snapshot at seqno {} and "
                "view {}",
                network.tables->current_version(),
                view);
            }

            consensus->init_as_backup(
              network.tables->current_version(),
              view,
              view_history,
              last_recovered_signed_idx);

            if (resp.network_info->public_only)
            {
              sm.advance(NodeStartupState::partOfPublicNetwork);
            }
            else
            {
              reset_data(quote_info.quote);
              reset_data(quote_info.endorsements);
              sm.advance(NodeStartupState::partOfNetwork);
            }

            LOG_INFO_FMT(
              "Node has now joined the network as node {}: {}",
              self,
              (resp.network_info->public_only ? "public only" : "all domains"));
          }
          else if (resp.node_status == NodeStatus::PENDING)
          {
            LOG_INFO_FMT(
              "Node {} is waiting for votes of members to be trusted", self);
          }

          return true;
        });

      // Send RPC request to remote node to join the network.
      JoinNetworkNodeToNode::In join_params;

      join_params.node_info_network = config.network;
      join_params.public_encryption_key =
        node_encrypt_kp->public_key_pem().raw();
      join_params.quote_info = quote_info;
      join_params.consensus_type = network.consensus_type;
      join_params.startup_seqno = startup_seqno;
      join_params.certificate_signing_request = node_sign_kp->create_csr(
        config.node_certificate.subject_name, subject_alt_names);
      join_params.node_data = config.node_data;

      LOG_DEBUG_FMT(
        "Sending join request to {}", config.join.target_rpc_address);

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

      auto timer_msg = std::make_unique<threading::Tmsg<JoinTimeMsg>>(
        [](std::unique_ptr<threading::Tmsg<JoinTimeMsg>> msg) {
          if (msg->data.self.sm.check(NodeStartupState::pending))
          {
            msg->data.self.initiate_join();
            auto delay = std::chrono::milliseconds(
              msg->data.self.config.join.retry_timeout);

            threading::ThreadMessaging::thread_messaging.add_task_after(
              std::move(msg), delay);
          }
        },
        *this);

      threading::ThreadMessaging::thread_messaging.add_task_after(
        std::move(timer_msg), config.join.retry_timeout);
    }

    void join()
    {
      std::lock_guard<std::mutex> guard(lock);
      sm.expect(NodeStartupState::pending);
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
        config.jwt.key_refresh_interval.count_s(),
        network,
        consensus,
        rpcsessions,
        rpc_map,
        node_sign_kp,
        self_signed_node_cert);
      jwt_key_auto_refresh->start();

      network.tables->set_map_hook(
        network.jwt_issuers.get_name(),
        [this](kv::Version, const kv::untyped::Write&) -> kv::ConsensusHookPtr {
          jwt_key_auto_refresh->schedule_once();
          return kv::ConsensusHookPtr(nullptr);
        });
    }

    size_t get_jwt_attempts() override
    {
      return jwt_key_auto_refresh->get_attempts();
    }

    //
    // funcs in state "readingPublicLedger" or "verifyingSnapshot"
    //
    void start_ledger_recovery()
    {
      std::lock_guard<std::mutex> guard(lock);
      if (
        !sm.check(NodeStartupState::readingPublicLedger) &&
        !sm.check(NodeStartupState::verifyingSnapshot))
      {
        throw std::logic_error(fmt::format(
          "Node should be in state {} or {} to start reading ledger",
          NodeStartupState::readingPublicLedger,
          NodeStartupState::verifyingSnapshot));
      }

      LOG_INFO_FMT("Starting to read public ledger");
      read_ledger_idx(++ledger_idx);
    }

    void recover_public_ledger_entry(const std::vector<uint8_t>& ledger_entry)
    {
      std::lock_guard<std::mutex> guard(lock);

      std::shared_ptr<kv::Store> store;
      if (sm.check(NodeStartupState::readingPublicLedger))
      {
        // In recovery, use the main store to deserialise public entries
        store = network.tables;
      }
      else if (sm.check(NodeStartupState::verifyingSnapshot))
      {
        store = startup_snapshot_info->store;
      }
      else
      {
        LOG_FAIL_FMT(
          "Node should be in state {} or {} to recover public ledger entry",
          NodeStartupState::readingPublicLedger,
          NodeStartupState::verifyingSnapshot);
        return;
      }

      LOG_INFO_FMT(
        "Deserialising public ledger entry [{}]", ledger_entry.size());

      kv::ApplyResult result = kv::ApplyResult::FAIL;
      try
      {
        auto r = store->deserialize(ledger_entry, ConsensusType::CFT, true);
        result = r->apply();
        if (result == kv::ApplyResult::FAIL)
        {
          LOG_FAIL_FMT("Failed to deserialise public ledger entry: {}", result);
          recover_public_ledger_end_unsafe();
          return;
        }

        // Not synchronised because consensus isn't effectively running then
        for (auto& hook : r->get_hooks())
        {
          hook->call(consensus.get());
        }
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("Failed to deserialise public ledger entry: {}", e.what());
        recover_public_ledger_end_unsafe();
        return;
      }

      // If the ledger entry is a signature, it is safe to compact the store
      if (result == kv::ApplyResult::PASS_SIGNATURE)
      {
        // If the ledger entry is a signature, it is safe to compact the store
        store->compact(ledger_idx);
        auto tx = store->create_tx();
        GenesisGenerator g(network, tx);
        auto last_sig = tx.ro(network.signatures)->get();

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
          startup_snapshot_info->evidence_seqno.has_value() &&
          static_cast<consensus::Index>(last_sig->commit_seqno) >=
            startup_snapshot_info->evidence_seqno.value())
        {
          startup_snapshot_info->is_evidence_committed = true;
        }

        if (sm.check(NodeStartupState::readingPublicLedger))
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

        if (
          startup_snapshot_info->evidence_seqno.has_value() &&
          ledger_idx == startup_snapshot_info->evidence_seqno.value())
        {
          auto evidence = snapshot_evidence->get();
          if (!evidence.has_value())
          {
            throw std::logic_error("Invalid snapshot evidence");
          }

          if (evidence->hash == crypto::Sha256Hash(startup_snapshot_info->raw))
          {
            LOG_DEBUG_FMT(
              "Snapshot evidence for snapshot found at {}",
              startup_snapshot_info->evidence_seqno.value());
            startup_snapshot_info->has_evidence = true;
          }
        }
      }

      read_ledger_idx(++ledger_idx);
    }

    void verify_snapshot_end()
    {
      std::lock_guard<std::mutex> guard(lock);
      if (!sm.check(NodeStartupState::verifyingSnapshot))
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
          startup_snapshot_info->evidence_seqno.value(),
          ledger_idx);
        return;
      }

      ledger_truncate(startup_snapshot_info->seqno);

      sm.advance(NodeStartupState::pending);
      start_join_timer();
    }

    void recover_public_ledger_end_unsafe()
    {
      sm.expect(NodeStartupState::readingPublicLedger);

      if (
        startup_snapshot_info &&
        startup_snapshot_info->requires_ledger_verification())
      {
        if (!startup_snapshot_info->is_snapshot_verified())
        {
          throw std::logic_error(
            "Snapshot evidence was not committed in ledger");
        }

        if (
          last_recovered_signed_idx <
          startup_snapshot_info->evidence_seqno.value())
        {
          throw std::logic_error("Snapshot evidence would be rolled back");
        }
      }

      // When reaching the end of the public ledger, truncate to last signed
      // index
      const auto last_recovered_term = view_history.size();
      auto new_term = last_recovered_term + 2;
      LOG_INFO_FMT("Setting term on public recovery store to {}", new_term);

      // Note: KV term must be set before the first Tx is committed
      network.tables->rollback(
        {last_recovered_term, last_recovered_signed_idx}, new_term);
      ledger_truncate(last_recovered_signed_idx, true);
      snapshotter->rollback(last_recovered_signed_idx);

      LOG_INFO_FMT(
        "End of public ledger recovery - Truncating ledger to last signed "
        "TxID: {}.{}",
        last_recovered_term,
        last_recovered_signed_idx);

      auto tx = network.tables->create_read_only_tx();
      if (network.consensus_type == ConsensusType::BFT)
      {
        endorsed_node_cert = create_endorsed_node_cert(
          config.node_certificate.initial_validity_days);
        history->set_endorsed_certificate(endorsed_node_cert.value());
        accept_network_tls_connections();
        open_frontend(ActorsType::members);
      }

      network.ledger_secrets->init(last_recovered_signed_idx + 1);

      // Initialise snapshotter after public recovery
      snapshotter->init_after_public_recovery();
      snapshotter->set_snapshot_generation(false);

      kv::Version index = 0;
      kv::Term view = 0;
      kv::Version global_commit = 0;

      auto ls = tx.ro(network.signatures)->get();
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

      auto service_config = tx.ro(network.config)->get();
      auto reconfiguration_type = service_config->reconfiguration_type.value_or(
        ReconfigurationType::ONE_TRANSACTION);

      setup_consensus(ServiceStatus::OPENING, reconfiguration_type, true);
      auto_refresh_jwt_keys();

      LOG_DEBUG_FMT(
        "Restarting consensus at view: {} seqno: {} commit_seqno {}",
        view,
        index,
        global_commit);

      consensus->force_become_primary(index, view, view_history, index);

      if (!create_and_send_boot_request(
            false /* Restore consortium from ledger */))
      {
        throw std::runtime_error(
          "End of public recovery transaction could not be committed");
      }

      sm.advance(NodeStartupState::partOfPublicNetwork);
    }

    //
    // funcs in state "readingPrivateLedger"
    //
    void recover_private_ledger_entry(const std::vector<uint8_t>& ledger_entry)
    {
      std::lock_guard<std::mutex> guard(lock);
      if (!sm.check(NodeStartupState::readingPrivateLedger))
      {
        LOG_FAIL_FMT(
          "Node is state {} cannot recover private ledger entry", sm.value());
        return;
      }

      LOG_INFO_FMT(
        "Deserialising private ledger entry [{}]", ledger_entry.size());

      // When reading the private ledger, deserialise in the recovery store
      kv::ApplyResult result = kv::ApplyResult::FAIL;
      try
      {
        result = recovery_store->deserialize(ledger_entry, ConsensusType::CFT)
                   ->apply();
        if (result == kv::ApplyResult::FAIL)
        {
          LOG_FAIL_FMT(
            "Failed to deserialise private ledger entry: {}", result);
          // Note: rollback terms do not matter here as recovery store is about
          // to be discarded
          recovery_store->rollback({0, ledger_idx - 1}, 0);
          recover_private_ledger_end_unsafe();
          return;
        }
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "Failed to deserialise private ledger entry: {}", e.what());
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

      sm.expect(NodeStartupState::readingPrivateLedger);

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

        // Clear recovery shares that were submitted to initiate the recovery
        // procedure
        share_manager.clear_submitted_recovery_shares(tx);

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
      recovered_encrypted_ledger_secrets.clear();
      reset_data(quote_info.quote);
      reset_data(quote_info.endorsements);
      sm.advance(NodeStartupState::partOfNetwork);
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
            if (!w.has_value())
            {
              throw std::logic_error(fmt::format(
                "Unexpected removal from {} table",
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
        std::vector<kv::Version> view_history;
        kv::ConsensusHookPtrs hooks;
        deserialise_snapshot(
          recovery_store,
          startup_snapshot_info->raw,
          hooks,
          &view_history,
          false,
          startup_snapshot_info->evidence_seqno,
          config.recover.previous_service_identity);
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

    void trigger_ledger_chunk(kv::Tx& tx) override
    {
      auto tx_ = static_cast<kv::CommittableTx*>(&tx);
      if (tx_ == nullptr)
      {
        throw std::logic_error("Could not cast tx to CommittableTx");
      }
      tx_->set_flag(kv::CommittableTx::Flag::LEDGER_CHUNK_AT_NEXT_SIGNATURE);
    }

    void trigger_snapshot(kv::Tx& tx) override
    {
      auto committable_tx = static_cast<kv::CommittableTx*>(&tx);
      if (committable_tx == nullptr)
      {
        throw std::logic_error("Could not cast tx to CommittableTx");
      }
      committable_tx->set_flag(
        kv::CommittableTx::Flag::SNAPSHOT_AT_NEXT_SIGNATURE);
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

    void transition_service_to_open(
      kv::Tx& tx,
      AbstractGovernanceEffects::ServiceIdentities identities) override
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

      if (
        service_info->status == ServiceStatus::RECOVERING &&
        (!config.recover.previous_service_identity ||
         !identities.previous.has_value()))
      {
        throw std::logic_error(
          "Recovery with service certificates requires both, a previous "
          "service identity certificate during node startup and a "
          "transition_service_to_open proposal that contains previous and next "
          "service certificates");
      }

      if (identities.next != service_info->cert)
      {
        throw std::logic_error(
          "Service identity mismatch: the next service identity in the "
          "transition_service_to_open proposal does not match the current "
          "service identity");
      }

      if (identities.previous)
      {
        service_info->previous_service_identity = *identities.previous;
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
        g.open_service();
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
      sm.expect(NodeStartupState::partOfPublicNetwork);

      recovered_ledger_secrets = share_manager.restore_recovery_shares_info(
        tx, recovered_encrypted_ledger_secrets);

      // Broadcast decrypted ledger secrets to other nodes for them to initiate
      // private recovery too
      LedgerSecretsBroadcast::broadcast_some(
        network, self, tx, recovered_ledger_secrets);
    }

    //
    // funcs in state "partOfNetwork" or "partOfPublicNetwork"
    //
    void tick(std::chrono::milliseconds elapsed)
    {
      if (
        !sm.check(NodeStartupState::partOfNetwork) &&
        !sm.check(NodeStartupState::partOfPublicNetwork) &&
        !sm.check(NodeStartupState::readingPrivateLedger))
      {
        return;
      }

      consensus->periodic(elapsed);

      if (sm.check(NodeStartupState::partOfNetwork))
      {
        const auto tx_id = consensus->get_committed_txid();
        indexer->update_strategies(elapsed, {tx_id.first, tx_id.second});
      }
    }

    void tick_end()
    {
      if (
        !sm.check(NodeStartupState::partOfNetwork) &&
        !sm.check(NodeStartupState::partOfPublicNetwork) &&
        !sm.check(NodeStartupState::readingPrivateLedger))
      {
        return;
      }

      consensus->periodic_end();
    }

    void recv_node_inbound(const uint8_t* data, size_t size)
    {
      auto [msg_type, from, payload] =
        ringbuffer::read_message<ccf::node_inbound>(data, size);

      auto payload_data = payload.data;
      auto payload_size = payload.size;

      if (msg_type == ccf::NodeMsgType::forwarded_msg)
      {
        cmd_forwarder->recv_message(from, payload_data, payload_size);
      }
      else
      {
        // Only process messages once part of network
        if (
          !sm.check(NodeStartupState::partOfNetwork) &&
          !sm.check(NodeStartupState::partOfPublicNetwork) &&
          !sm.check(NodeStartupState::readingPrivateLedger))
        {
          LOG_DEBUG_FMT(
            "Ignoring node msg received too early - current state is {}",
            sm.value());
          return;
        }

        switch (msg_type)
        {
          case channel_msg:
          {
            n2n_channels->recv_channel_message(
              from, payload_data, payload_size);
            break;
          }

          case consensus_msg:
          {
            consensus->recv_message(from, payload_data, payload_size);
            break;
          }

          default:
          {
            LOG_FAIL_FMT("Unknown node message type: {}", msg_type);
            return;
          }
        }
      }
    }

    //
    // always available
    //
    bool is_primary() const override
    {
      return (
        (sm.check(NodeStartupState::partOfNetwork) ||
         sm.check(NodeStartupState::partOfPublicNetwork) ||
         sm.check(NodeStartupState::readingPrivateLedger)) &&
        consensus->is_primary());
    }

    bool can_replicate() override
    {
      return (
        (sm.check(NodeStartupState::partOfNetwork) ||
         sm.check(NodeStartupState::partOfPublicNetwork) ||
         sm.check(NodeStartupState::readingPrivateLedger)) &&
        consensus->can_replicate());
    }

    bool is_in_initialised_state() const override
    {
      return sm.check(NodeStartupState::initialized);
    }

    bool is_part_of_network() const override
    {
      return sm.check(NodeStartupState::partOfNetwork);
    }

    bool is_reading_public_ledger() const override
    {
      return sm.check(NodeStartupState::readingPublicLedger);
    }

    bool is_reading_private_ledger() const override
    {
      return sm.check(NodeStartupState::readingPrivateLedger);
    }

    bool is_verifying_snapshot() const override
    {
      return sm.check(NodeStartupState::verifyingSnapshot);
    }

    bool is_part_of_public_network() const override
    {
      return sm.check(NodeStartupState::partOfPublicNetwork);
    }

    ExtendedState state() override
    {
      std::lock_guard<std::mutex> guard(lock);
      auto s = sm.value();
      if (s == NodeStartupState::readingPrivateLedger)
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
      sm.expect(NodeStartupState::partOfNetwork);

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

    NodeId get_node_id() const
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
      return rpcsessions->get_session_metrics();
    }

  private:
    bool is_ip(const std::string_view& hostname)
    {
      // IP address components are purely numeric. DNS names may be largely
      // numeric, but at least the final component (TLD) must not be
      // all-numeric. So this distinguishes "1.2.3.4" (and IP address) from
      // "1.2.3.c4m" (a DNS name). "1.2.3." is invalid for either, and will
      // throw. Attempts to handle IPv6 by also splitting on ':', but this is
      // untested.
      const auto final_component =
        nonstd::split(nonstd::split(hostname, ".").back(), ":").back();
      if (final_component.empty())
      {
        throw std::runtime_error(fmt::format(
          "{} has a trailing period, is not a valid hostname",
          final_component));
      }
      for (const auto c : final_component)
      {
        if (c < '0' || c > '9')
        {
          return false;
        }
      }

      return true;
    }

    std::vector<crypto::SubjectAltName> get_subject_alternative_names()
    {
      // If no Subject Alternative Name (SAN) is passed in at node creation,
      // default to using node's RPC address as single SAN. Otherwise, use
      // specified SANs.
      if (!config.node_certificate.subject_alt_names.empty())
      {
        return crypto::sans_from_string_list(
          config.node_certificate.subject_alt_names);
      }
      else
      {
        // Construct SANs from RPC interfaces, manually detecting whether each
        // is a domain name or IP
        std::vector<crypto::SubjectAltName> sans;
        for (const auto& [_, interface] : config.network.rpc_interfaces)
        {
          auto host = split_net_address(interface.published_address).first;
          sans.push_back({host, is_ip(host)});
        }
        return sans;
      }
    }

    crypto::Pem create_endorsed_node_cert(size_t validity_period_days)
    {
      // Only used by a 2.x node joining an existing 1.x service which will not
      // endorsed the identity of the new joiner.
      return create_endorsed_cert(
        node_sign_kp,
        config.node_certificate.subject_name,
        subject_alt_names,
        config.startup_host_time,
        validity_period_days,
        network.identity->priv_key,
        network.identity->cert);
    }

    void accept_node_tls_connections()
    {
      // Accept TLS connections, presenting self-signed (i.e. non-endorsed)
      // node certificate.
      rpcsessions->set_node_cert(
        self_signed_node_cert, node_sign_kp->private_key_pem());
      LOG_INFO_FMT("Node TLS connections now accepted");
    }

    void accept_network_tls_connections()
    {
      // Accept TLS connections, presenting node certificate signed by network
      // certificate
      CCF_ASSERT_FMT(
        endorsed_node_cert.has_value(),
        "Node certificate should be endorsed before accepting endorsed client "
        "connections");
      rpcsessions->set_network_cert(
        endorsed_node_cert.value(), node_sign_kp->private_key_pem());
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

    std::vector<uint8_t> serialize_create_request(bool create_consortium = true)
    {
      CreateNetworkNodeToNode::In create_params;

      // False on recovery where the consortium is read from the existing
      // ledger
      if (create_consortium)
      {
        create_params.genesis_info = config.start;
      }

      create_params.node_id = self;
      create_params.certificate_signing_request = node_sign_kp->create_csr(
        config.node_certificate.subject_name, subject_alt_names);
      create_params.node_endorsed_certificate = crypto::create_endorsed_cert(
        create_params.certificate_signing_request,
        config.startup_host_time,
        config.node_certificate.initial_validity_days,
        network.identity->priv_key,
        network.identity->cert);

      // Even though endorsed certificate is updated on (global) hook, history
      // requires it to generate signatures
      history->set_endorsed_certificate(
        create_params.node_endorsed_certificate);

      create_params.public_key = node_sign_kp->public_key_pem();
      create_params.service_cert = network.identity->cert;
      create_params.quote_info = quote_info;
      create_params.public_encryption_key = node_encrypt_kp->public_key_pem();
      create_params.code_digest = node_code_id;
      create_params.node_info_network = config.network;
      create_params.node_data = config.node_data;

      const auto body = serdes::pack(create_params, serdes::Pack::Text);

      http::Request request(fmt::format(
        "/{}/{}", ccf::get_actor_prefix(ccf::ActorsType::nodes), "create"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      request.set_body(&body);

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
      auto node_session = std::make_shared<ccf::SessionContext>(
        ccf::InvalidSessionId, self_signed_node_cert.raw());
      auto ctx = ccf::make_rpc_context(node_session, packed);

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

    bool create_and_send_boot_request(bool create_consortium = true)
    {
      return send_create_request(serialize_create_request(create_consortium));
    }

    void backup_initiate_private_recovery()
    {
      if (!consensus->is_backup())
        return;

      sm.expect(NodeStartupState::partOfPublicNetwork);

      LOG_INFO_FMT("Initiating end of recovery (backup)");

      setup_private_recovery_store();

      reset_recovery_hook();
      setup_one_off_secret_hook();

      // Start reading private security domain of ledger
      ledger_idx = recovery_store->current_version();
      read_ledger_idx(++ledger_idx);

      sm.advance(NodeStartupState::readingPrivateLedger);
    }

    void setup_basic_hooks()
    {
      network.tables->set_map_hook(
        network.secrets.get_name(),
        network.secrets.wrap_map_hook(
          [this](kv::Version hook_version, const Secrets::Write& w)
            -> kv::ConsensusHookPtr {
            // Used to rekey the ledger on a live service
            if (!is_part_of_network())
            {
              // Ledger rekey is not allowed during recovery
              return kv::ConsensusHookPtr(nullptr);
            }

            const auto& ledger_secrets_for_nodes = w;
            if (!ledger_secrets_for_nodes.has_value())
            {
              throw std::logic_error(fmt::format(
                "Unexpected removal from {} table",
                network.secrets.get_name()));
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

                // When rekeying, set the encryption key for the next version
                // onward (backups deserialise this transaction with the
                // previous ledger secret)
                network.ledger_secrets->set_secret(
                  hook_version + 1,
                  std::make_shared<LedgerSecret>(
                    std::move(plain_ledger_secret), hook_version));
              }
            }

            return kv::ConsensusHookPtr(nullptr);
          }));

      network.tables->set_global_hook(
        network.secrets.get_name(),
        network.secrets.wrap_commit_hook([this](
                                           kv::Version hook_version,
                                           const Secrets::Write& w) {
          // Used on recovery to initiate private recovery on backup nodes.
          if (!is_part_of_public_network())
          {
            return;
          }

          const auto& ledger_secrets_for_nodes = w;
          if (!ledger_secrets_for_nodes.has_value())
          {
            throw std::logic_error(fmt::format(
              "Unexpected removal from {} table", network.secrets.get_name()));
          }

          for (const auto& [node_id, encrypted_ledger_secrets] :
               ledger_secrets_for_nodes.value())
          {
            if (node_id != self)
            {
              // Only consider ledger secrets for this node
              continue;
            }

            LedgerSecretsMap restored_ledger_secrets = {};
            for (const auto& encrypted_ledger_secret : encrypted_ledger_secrets)
            {
              // On rekey, the version is inferred from the version at which
              // the hook is executed. Otherwise, on recovery, use the version
              // read from the write set.
              if (!encrypted_ledger_secret.version.has_value())
              {
                throw std::logic_error(fmt::format(
                  "Commit hook at seqno {} for table {}: no version for "
                  "encrypted ledger secret",
                  hook_version,
                  network.secrets.get_name()));
              }

              auto plain_ledger_secret = LedgerSecretsBroadcast::decrypt(
                node_encrypt_kp, encrypted_ledger_secret.encrypted_secret);

              restored_ledger_secrets.emplace(
                encrypted_ledger_secret.version.value(),
                std::make_shared<LedgerSecret>(
                  std::move(plain_ledger_secret),
                  encrypted_ledger_secret.previous_secret_stored_version));
            }

            if (!restored_ledger_secrets.empty())
            {
              // When recovering, restore ledger secrets and trigger end of
              // recovery protocol (backup only)
              network.ledger_secrets->restore_historical(
                std::move(restored_ledger_secrets));
              backup_initiate_private_recovery();
              return;
            }
          }
        }));

      network.tables->set_global_hook(
        network.encrypted_submitted_shares.get_name(),
        network.encrypted_submitted_shares.wrap_commit_hook(
          [this](
            kv::Version hook_version,
            const EncryptedSubmittedShares::Write& w) {
            // Initiate recovery procedure from global hook, once all recovery
            // shares have been submitted (i.e. recovered_ledger_secrets is set)
            if (!recovered_ledger_secrets.empty())
            {
              network.ledger_secrets->restore_historical(
                std::move(recovered_ledger_secrets));

              LOG_INFO_FMT("Initiating end of recovery (primary)");

              setup_private_recovery_store();
              reset_recovery_hook();

              // Start reading private security domain of ledger
              ledger_idx = recovery_store->current_version();
              read_ledger_idx(++ledger_idx);

              sm.advance(NodeStartupState::readingPrivateLedger);
            }

            return;
          }));

      network.tables->set_global_hook(
        network.node_endorsed_certificates.get_name(),
        network.node_endorsed_certificates.wrap_commit_hook(
          [this](
            kv::Version hook_version,
            const NodeEndorsedCertificates::Write& w) {
            for (auto const& [node_id, endorsed_certificate] : w)
            {
              if (node_id != self)
              {
                continue;
              }

              if (!endorsed_certificate.has_value())
              {
                throw std::logic_error(fmt::format(
                  "Could not find endorsed node certificate for {}", self));
              }

              endorsed_node_cert = endorsed_certificate.value();
              history->set_endorsed_certificate(endorsed_node_cert.value());
              n2n_channels->set_endorsed_node_cert(endorsed_node_cert.value());
              accept_network_tls_connections();

              open_frontend(ActorsType::members);
            }
          }));

      network.tables->set_global_hook(
        network.service.get_name(),
        network.service.wrap_commit_hook([this](
                                           kv::Version hook_version,
                                           const Service::Write& w) {
          if (!w.has_value())
          {
            throw std::logic_error("Unexpected deletion in service value");
          }

          // Service open on historical service has no effect
          auto hook_pubk_pem =
            crypto::public_key_pem_from_cert(crypto::cert_pem_to_der(w->cert));
          auto current_pubk_pem =
            crypto::make_key_pair(network.identity->priv_key)->public_key_pem();
          if (hook_pubk_pem != current_pubk_pem)
          {
            LOG_TRACE_FMT(
              "Ignoring historical service open at seqno {} for {}",
              hook_version,
              w->cert.str());
            return;
          }

          network.identity->set_certificate(w->cert);
          if (w->status == ServiceStatus::OPEN)
          {
            open_user_frontend();

            RINGBUFFER_WRITE_MESSAGE(consensus::ledger_open, to_host);
            LOG_INFO_FMT("Service open at seqno {}", hook_version);
          }
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
            auto encrypted_ledger_secret_info = w;
            if (!encrypted_ledger_secret_info.has_value())
            {
              throw std::logic_error(fmt::format(
                "Unexpected removal from {} table",
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
                "Recovering encrypted ledger secret valid at seqno {}",
                encrypted_ledger_secret_info->previous_ledger_secret->version);
            }

            recovered_encrypted_ledger_secrets.emplace_back(
              std::move(encrypted_ledger_secret_info.value()));

            return kv::ConsensusHookPtr(nullptr);
          }));
    }

    void reset_recovery_hook()
    {
      network.tables->unset_map_hook(
        network.encrypted_ledger_secrets.get_name());
    }

    void setup_n2n_channels(
      const std::optional<crypto::Pem>& endorsed_node_certificate_ =
        std::nullopt)
    {
      // If the endorsed node certificate is available at the time the
      // consensus/node-to-node channels are initialised, use it (i.e. join).
      // Otherwise, specify it later, on endorsed certificate table hook (i.e.
      // start or recover).
      n2n_channels->initialize(
        self, network.identity->cert, node_sign_kp, endorsed_node_certificate_);
    }

    void setup_cmd_forwarder()
    {
      cmd_forwarder->initialize(self);
    }

    void setup_history()
    {
      if (history)
      {
        throw std::logic_error("History already initialised");
      }

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
      if (encryptor)
      {
        throw std::logic_error("Encryptor already initialised");
      }

      encryptor = make_encryptor();
      network.tables->set_encryptor(encryptor);
    }

    void setup_consensus(
      ServiceStatus service_status,
      ReconfigurationType reconfiguration_type,
      bool public_only = false,
      const std::optional<crypto::Pem>& endorsed_node_certificate_ =
        std::nullopt)
    {
      setup_n2n_channels(endorsed_node_certificate_);
      setup_cmd_forwarder();

      auto shared_state = std::make_shared<aft::State>(self);

      auto resharing_tracker = nullptr;
      if (consensus_config.type == ConsensusType::BFT)
      {
        std::make_shared<ccf::SplitIdentityResharingTracker>(
          shared_state,
          rpc_map,
          node_sign_kp,
          self_signed_node_cert,
          endorsed_node_cert);
      }

      auto node_client = std::make_shared<HTTPNodeClient>(
        rpc_map, node_sign_kp, self_signed_node_cert, endorsed_node_cert);

      kv::MembershipState membership_state =
        (reconfiguration_type == ReconfigurationType::TWO_TRANSACTION &&
         service_status == ServiceStatus::OPEN) ?
        kv::MembershipState::Learner :
        kv::MembershipState::Active;

      consensus = std::make_shared<RaftType>(
        consensus_config,
        std::make_unique<aft::Adaptor<kv::Store>>(network.tables),
        std::make_unique<consensus::LedgerEnclave>(writer_factory),
        n2n_channels,
        snapshotter,
        shared_state,
        std::move(resharing_tracker),
        node_client,
        public_only,
        membership_state,
        reconfiguration_type);

      network.tables->set_consensus(consensus);

      // When a node is added, even locally, inform consensus so that it
      // can add a new active configuration.
      network.tables->set_map_hook(
        network.nodes.get_name(),
        network.nodes.wrap_map_hook(
          [](kv::Version version, const Nodes::Write& w)
            -> kv::ConsensusHookPtr {
            return std::make_unique<ConfigurationChangeHook>(version, w);
          }));

      network.tables->set_map_hook(
        network.resharings.get_name(),
        network.resharings.wrap_map_hook(
          [](kv::Version version, const Resharings::Write& w)
            -> kv::ConsensusHookPtr {
            return std::make_unique<ResharingsHook>(version, w);
          }));

      network.tables->set_map_hook(
        network.signatures.get_name(),
        network.signatures.wrap_map_hook(
          [](kv::Version version, const Signatures::Write& w)
            -> kv::ConsensusHookPtr {
            return std::make_unique<SignaturesHook>(version, w);
          }));

      network.tables->set_map_hook(
        network.serialise_tree.get_name(),
        network.serialise_tree.wrap_map_hook(
          [](kv::Version version, const SerialisedMerkleTree::Write& w)
            -> kv::ConsensusHookPtr {
            return std::make_unique<SerialisedMerkleTreeHook>(version, w);
          }));

      network.tables->set_global_hook(
        network.config.get_name(),
        network.config.wrap_commit_hook(
          [c = this->consensus](
            kv::Version version, const Configuration::Write& w) {
            service_configuration_commit_hook(version, w, c);
          }));

      setup_basic_hooks();
    }

    void setup_snapshotter()
    {
      if (snapshotter)
      {
        throw std::logic_error("Snapshotter already initialised");
      }
      snapshotter = std::make_shared<Snapshotter>(
        writer_factory, network.tables, config.snapshot_tx_interval);
    }

    void read_ledger_idx(consensus::Index idx)
    {
      RINGBUFFER_WRITE_MESSAGE(
        consensus::ledger_get_range,
        to_host,
        idx,
        idx,
        consensus::LedgerRequestPurpose::Recovery);
    }

    void ledger_truncate(consensus::Index idx, bool recovery_mode = false)
    {
      RINGBUFFER_WRITE_MESSAGE(
        consensus::ledger_truncate, to_host, idx, recovery_mode);
    }
  };
}