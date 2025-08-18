// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/entropy.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/json.h"
#include "ccf/ds/logger.h"
#include "ccf/ds/unit_strings.h"
#include "ccf/js/core/context.h"
#include "ccf/json_handler.h"
#include "ccf/node/cose_signatures_config.h"
#include "ccf/odata_error.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/locking.h"
#include "ccf/pal/platform.h"
#include "ccf/pal/snp_ioctl.h"
#include "ccf/pal/uvm_endorsements.h"
#include "ccf/service/node_info_network.h"
#include "ccf/service/reconfiguration_type.h"
#include "ccf/service/tables/acme_certificates.h"
#include "ccf/service/tables/self_heal_open.h"
#include "ccf/service/tables/service.h"
#include "ccf/threading/thread_ids.h"
#include "ccf/tx.h"
#include "ccf_acme_client.h"
#include "consensus/aft/raft.h"
#include "consensus/ledger_enclave.h"
#include "crypto/certs.h"
#include "ds/ccf_assert.h"
#include "ds/files.h"
#include "ds/ring_buffer_types.h"
#include "ds/state_machine.h"
#include "ds/thread_messaging.h"
#include "enclave/interface.h"
#include "enclave/rpc_sessions.h"
#include "encryptor.h"
#include "history.h"
#include "http/curl.h"
#include "http/http_parser.h"
#include "indexing/indexer.h"
#include "js/global_class_ids.h"
#include "network_state.h"
#include "node/hooks.h"
#include "node/http_node_client.h"
#include "node/jwt_key_auto_refresh.h"
#include "node/ledger_secret.h"
#include "node/ledger_secrets.h"
#include "node/local_sealing.h"
#include "node/node_to_node_channel_manager.h"
#include "node/self_healing_open.h"
#include "node/snapshotter.h"
#include "node_to_node.h"
#include "pal/quote_generation.h"
#include "quote_endorsements_client.h"
#include "rpc/frontend.h"
#include "rpc/serialization.h"
#include "secret_broadcast.h"
#include "service/internal_tables_access.h"
#include "service/tables/recovery_type.h"
#include "share_manager.h"
#include "uvm_endorsements.h"

#include <optional>

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
  using RaftType = aft::Aft<::consensus::LedgerEnclave>;

  struct NodeCreateInfo
  {
    ccf::crypto::Pem self_signed_node_cert;
    ccf::crypto::Pem service_cert;
  };

  void reset_data(std::vector<uint8_t>& data)
  {
    data.clear();
    data.shrink_to_fit();
  }

  class NodeState : public AbstractNodeState
  {
  private:
    //
    // this node's core state
    //
    ::ds::StateMachine<NodeStartupState> sm;
    pal::Mutex lock;
    StartType start_type;

    ccf::crypto::CurveID curve_id;
    std::vector<ccf::crypto::SubjectAltName> subject_alt_names = {};

    std::shared_ptr<ccf::crypto::KeyPair_OpenSSL> node_sign_kp;
    NodeId self;
    std::shared_ptr<ccf::crypto::RSAKeyPair> node_encrypt_kp;
    ccf::crypto::Pem self_signed_node_cert;
    std::optional<ccf::crypto::Pem> endorsed_node_cert = std::nullopt;
    QuoteInfo quote_info;
    pal::PlatformAttestationMeasurement node_measurement;
    std::optional<pal::snp::TcbVersionRaw> snp_tcb_version = std::nullopt;
    ccf::StartupConfig config;
    std::optional<pal::UVMEndorsements> snp_uvm_endorsements = std::nullopt;
    std::vector<uint8_t> startup_snapshot;
    std::shared_ptr<QuoteEndorsementsClient> quote_endorsements_client =
      nullptr;

    std::atomic<bool> stop_noticed = false;

    struct NodeStateMsg
    {
      NodeStateMsg(
        NodeState& self_,
        View create_view_ = 0,
        bool create_consortium_ = true) :
        self(self_),
        create_view(create_view_),
        create_consortium(create_consortium_)
      {}
      NodeState& self;
      View create_view;
      bool create_consortium;
    };

    //
    // kv store, replication, and I/O
    //
    ringbuffer::AbstractWriterFactory& writer_factory;
    ringbuffer::WriterPtr to_host;
    ccf::consensus::Configuration consensus_config;
    size_t sig_tx_interval;
    size_t sig_ms_interval;

    NetworkState& network;

    std::shared_ptr<ccf::kv::Consensus> consensus;
    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<indexing::Indexer> indexer;
    std::shared_ptr<NodeToNode> n2n_channels;
    std::shared_ptr<Forwarder<NodeToNode>> cmd_forwarder;
    std::shared_ptr<RPCSessions> rpcsessions;

    std::shared_ptr<ccf::kv::TxHistory> history;
    std::shared_ptr<ccf::kv::AbstractTxEncryptor> encryptor;

    ShareManager share_manager;
    std::shared_ptr<Snapshotter> snapshotter;

    //
    // recovery
    //
    std::shared_ptr<ccf::kv::Store> recovery_store;

    ccf::kv::Version recovery_v;
    ccf::crypto::Sha256Hash recovery_root;
    std::vector<ccf::kv::Version> view_history;
    ::consensus::Index last_recovered_signed_idx = 0;
    RecoveredEncryptedLedgerSecrets recovered_encrypted_ledger_secrets = {};
    ::consensus::Index last_recovered_idx = 0;
    static const size_t recovery_batch_size = 100;

    //
    // JWT key auto-refresh
    //
    std::shared_ptr<JwtKeyAutoRefresh> jwt_key_auto_refresh;

    std::unique_ptr<StartupSnapshotInfo> startup_snapshot_info = nullptr;
    // Set to the snapshot seqno when a node starts from one and remembered for
    // the lifetime of the node
    ccf::kv::Version startup_seqno = 0;

    // ACME certificate endorsement client
    std::map<NodeInfoNetwork::RpcInterfaceID, std::shared_ptr<ACMEClient>>
      acme_clients;
    std::map<
      NodeInfoNetwork::RpcInterfaceID,
      std::shared_ptr<ACMEChallengeHandler>>
      acme_challenge_handlers;
    size_t num_acme_interfaces = 0;

    std::shared_ptr<ccf::kv::AbstractTxEncryptor> make_encryptor()
    {
#ifdef USE_NULL_ENCRYPTOR
      return std::make_shared<ccf::kv::NullTxEncryptor>();
#else
      return std::make_shared<NodeEncryptor>(network.ledger_secrets);
#endif
    }

    // Returns true if the snapshot is already verified (via embedded receipt)
    void initialise_startup_snapshot(bool recovery = false)
    {
      std::shared_ptr<ccf::kv::Store> snapshot_store;
      if (!recovery)
      {
        // Create a new store to verify the snapshot only
        snapshot_store = make_store();
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

      ccf::kv::ConsensusHookPtrs hooks;
      startup_snapshot_info = initialise_from_snapshot(
        snapshot_store,
        std::move(startup_snapshot),
        hooks,
        &view_history,
        true,
        config.recover.previous_service_identity);

      startup_seqno = startup_snapshot_info->seqno;
      last_recovered_idx = startup_seqno;
      last_recovered_signed_idx = last_recovered_idx;
    }

  public:
    NodeState(
      ringbuffer::AbstractWriterFactory& writer_factory,
      NetworkState& network,
      std::shared_ptr<RPCSessions> rpcsessions,
      ccf::crypto::CurveID curve_id_) :
      sm("NodeState", NodeStartupState::uninitialized),
      curve_id(curve_id_),
      node_sign_kp(std::make_shared<ccf::crypto::KeyPair_OpenSSL>(curve_id_)),
      self(compute_node_id_from_kp(node_sign_kp)),
      node_encrypt_kp(ccf::crypto::make_rsa_key_pair()),
      writer_factory(writer_factory),
      to_host(writer_factory.create_writer_to_outside()),
      network(network),
      rpcsessions(rpcsessions),
      share_manager(network.ledger_secrets)
    {}

    QuoteVerificationResult verify_quote(
      ccf::kv::ReadOnlyTx& tx,
      const QuoteInfo& quote_info_,
      const std::vector<uint8_t>& expected_node_public_key_der,
      pal::PlatformAttestationMeasurement& measurement) override
    {
      return AttestationProvider::verify_quote_against_store(
        tx, quote_info_, expected_node_public_key_der, measurement);
    }

    //
    // funcs in state "uninitialized"
    //
    void initialize(
      const ccf::consensus::Configuration& consensus_config_,
      std::shared_ptr<RPCMap> rpc_map_,
      std::shared_ptr<AbstractRPCResponder> rpc_sessions_,
      std::shared_ptr<indexing::Indexer> indexer_,
      size_t sig_tx_interval_,
      size_t sig_ms_interval_)
    {
      std::lock_guard<pal::Mutex> guard(lock);
      sm.expect(NodeStartupState::uninitialized);

      consensus_config = consensus_config_;
      rpc_map = rpc_map_;
      indexer = indexer_;
      sig_tx_interval = sig_tx_interval_;
      sig_ms_interval = sig_ms_interval_;

      n2n_channels = std::make_shared<NodeToNodeChannelManager>(writer_factory);

      cmd_forwarder = std::make_shared<Forwarder<NodeToNode>>(
        rpc_sessions_, n2n_channels, rpc_map);

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
    void launch_node()
    {
      auto measurement = AttestationProvider::get_measurement(quote_info);
      if (measurement.has_value())
      {
        node_measurement = measurement.value();
      }
      else
      {
        throw std::logic_error("Failed to extract code id from quote");
      }

      auto snp_attestation =
        AttestationProvider::get_snp_attestation(quote_info);
      if (snp_attestation.has_value())
      {
        snp_tcb_version = snp_attestation.value().reported_tcb;
      }

      // Verify that the security policy matches the quoted digest of the policy
      if (!config.attestation.environment.security_policy.has_value())
      {
        LOG_INFO_FMT(
          "Security policy not set, skipping check against attestation host "
          "data");
      }
      else
      {
        auto quoted_digest = AttestationProvider::get_host_data(quote_info);
        if (!quoted_digest.has_value())
        {
          throw std::logic_error("Unable to find host data in attestation");
        }

        auto const& security_policy =
          config.attestation.environment.security_policy.value();

        auto security_policy_digest =
          quote_info.format == QuoteFormat::amd_sev_snp_v1 ?
          ccf::crypto::Sha256Hash(ccf::crypto::raw_from_b64(security_policy)) :
          ccf::crypto::Sha256Hash(security_policy);
        if (security_policy_digest != quoted_digest.value())
        {
          throw std::logic_error(fmt::format(
            "Digest of decoded security policy \"{}\" {} does not match "
            "attestation host data {}",
            security_policy,
            security_policy_digest.hex_str(),
            quoted_digest.value().hex_str()));
        }
        LOG_INFO_FMT(
          "Successfully verified attested security policy {}",
          security_policy_digest);
      }

      if (quote_info.format == QuoteFormat::amd_sev_snp_v1)
      {
        if (!config.attestation.environment.uvm_endorsements.has_value())
        {
          LOG_INFO_FMT(
            "UVM endorsements not set, skipping check against attestation "
            "measurement");
        }
        else
        {
          try
          {
            auto uvm_endorsements_raw = ccf::crypto::raw_from_b64(
              config.attestation.environment.uvm_endorsements.value());
            // A node at this stage does not have a notion of what UVM
            // descriptor is acceptable. That is decided either by the Joinee,
            // or by Consortium endorsing the Start or Recovery node. For that
            // reason, we extract an endorsement descriptor from the UVM
            // endorsements and make it available in the ledger's initial or
            // recovery transaction.
            snp_uvm_endorsements = pal::verify_uvm_endorsements_descriptor(
              uvm_endorsements_raw, node_measurement);
            quote_info.uvm_endorsements = uvm_endorsements_raw;
            LOG_INFO_FMT(
              "Successfully verified attested UVM endorsements: {}",
              snp_uvm_endorsements->to_str());
          }
          catch (const std::exception& e)
          {
            throw std::logic_error(
              fmt::format("Error verifying UVM endorsements: {}", e.what()));
          }
        }
      }

      switch (start_type)
      {
        case StartType::Start:
        {
          LOG_INFO_FMT("Creating boot request");
          create_and_send_boot_request(
            aft::starting_view_change, true /* Create new consortium */);
          return;
        }
        case StartType::Join:
        {
          if (!startup_snapshot.empty())
          {
            initialise_startup_snapshot();
          }

          sm.advance(NodeStartupState::pending);
          start_join_timer();
          return;
        }
        case StartType::Recover:
        {
          setup_recovery_hook();
          if (!startup_snapshot.empty())
          {
            initialise_startup_snapshot(true);
            snapshotter->set_last_snapshot_idx(last_recovered_idx);
          }

          sm.advance(NodeStartupState::readingPublicLedger);
          start_ledger_recovery_unsafe();
          return;
        }
        default:
        {
          throw std::logic_error(
            fmt::format("Node was launched in unknown mode {}", start_type));
        }
      }
    }

    void initiate_quote_generation()
    {
      auto fetch_endorsements = [this](
                                  const QuoteInfo& qi,
                                  const pal::snp::
                                    EndorsementEndpointsConfiguration&
                                      endpoint_config) {
        // Note: Node lock is already taken here as this is called back
        // synchronously with the call to pal::generate_quote
        this->quote_info = qi;

        if (quote_info.format == QuoteFormat::amd_sev_snp_v1)
        {
          // Use endorsements retrieved from file, if available
          if (config.attestation.environment.snp_endorsements.has_value())
          {
            try
            {
              const auto raw_data = ccf::crypto::raw_from_b64(
                config.attestation.environment.snp_endorsements.value());

              const auto j = nlohmann::json::parse(raw_data);
              const auto aci_endorsements =
                j.get<ccf::pal::snp::ACIReportEndorsements>();

              // Check that tcbm in endorsement matches reported TCB in our
              // retrieved attestation
              auto* quote = reinterpret_cast<const ccf::pal::snp::Attestation*>(
                quote_info.quote.data());
              const auto reported_tcb = quote->reported_tcb;

              // tcbm is a single hex value, like DB18000000000004. To match
              // that with a TcbVersion, reverse the bytes.
              const uint8_t* tcb_begin =
                reinterpret_cast<const uint8_t*>(&reported_tcb);
              const std::span<const uint8_t> tcb_bytes{
                tcb_begin, tcb_begin + sizeof(reported_tcb)};
              auto tcb_as_hex = fmt::format(
                "{:02x}", fmt::join(tcb_bytes.rbegin(), tcb_bytes.rend(), ""));
              ccf::nonstd::to_upper(tcb_as_hex);

              if (tcb_as_hex == aci_endorsements.tcbm)
              {
                LOG_INFO_FMT(
                  "Using SNP endorsements loaded from file, endorsing TCB {}",
                  tcb_as_hex);

                auto& endorsements_pem = quote_info.endorsements;
                endorsements_pem.insert(
                  endorsements_pem.end(),
                  aci_endorsements.vcek_cert.begin(),
                  aci_endorsements.vcek_cert.end());
                endorsements_pem.insert(
                  endorsements_pem.end(),
                  aci_endorsements.certificate_chain.begin(),
                  aci_endorsements.certificate_chain.end());

                try
                {
                  launch_node();
                  return;
                }
                catch (const std::exception& e)
                {
                  LOG_FAIL_FMT("Failed to launch node: {}", e.what());
                  throw;
                }
              }
              else
              {
                LOG_FAIL_FMT(
                  "SNP endorsements loaded from disk ({}) contained tcbm {}, "
                  "which does not match reported TCB of current attestation "
                  "{}. "
                  "Falling back to fetching fresh endorsements from server.",
                  config.attestation.snp_endorsements_file.value(),
                  aci_endorsements.tcbm,
                  tcb_as_hex);
              }
            }
            catch (const std::exception& e)
            {
              LOG_FAIL_FMT(
                "Error attempting to use SNP endorsements from file: {}",
                e.what());
            }
          }

          if (config.attestation.snp_endorsements_servers.empty())
          {
            throw std::runtime_error(
              "One or more SNP endorsements servers must be specified to fetch "
              "the collateral for the attestation");
          }
          // On SEV-SNP, fetch endorsements from servers if specified
          quote_endorsements_client = std::make_shared<QuoteEndorsementsClient>(
            rpcsessions,
            endpoint_config,
            [this](std::vector<uint8_t>&& endorsements) {
              std::lock_guard<pal::Mutex> guard(lock);
              quote_info.endorsements = std::move(endorsements);
              try
              {
                launch_node();
              }
              catch (const std::exception& e)
              {
                LOG_FAIL_FMT("{}", e.what());
                throw;
              }
              quote_endorsements_client.reset();
            });

          quote_endorsements_client->fetch_endorsements();
          return;
        }
        else // Non-SNP
        {
          if (!((quote_info.format == QuoteFormat::oe_sgx_v1 &&
                 !quote_info.endorsements.empty()) ||
                (quote_info.format != QuoteFormat::oe_sgx_v1 &&
                 quote_info.endorsements.empty())))
          {
            throw std::runtime_error(
              "SGX quote generation should have already fetched endorsements");
          }

          launch_node();
        }
      };

      pal::PlatformAttestationReportData report_data =
        ccf::crypto::Sha256Hash((node_sign_kp->public_key_der()));

      pal::generate_quote(
        report_data,
        fetch_endorsements,
        config.attestation.snp_endorsements_servers);
    }

    NodeCreateInfo create(
      StartType start_type_,
      const ccf::StartupConfig& config_,
      std::vector<uint8_t>&& startup_snapshot_)
    {
      std::lock_guard<pal::Mutex> guard(lock);
      sm.expect(NodeStartupState::initialized);
      start_type = start_type_;

      config = config_;
      startup_snapshot = std::move(startup_snapshot_);
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

      // Signatures are only emitted on a timer once the public ledger has been
      // recovered
      setup_history();
      setup_snapshotter();
      setup_encryptor();

      setup_acme_clients();

      initiate_quote_generation();

      switch (start_type)
      {
        case StartType::Start:
        {
          network.identity = std::make_unique<ccf::NetworkIdentity>(
            config.service_subject_name,
            curve_id,
            config.startup_host_time,
            config.initial_service_certificate_validity_days);

          network.ledger_secrets->init();
          // Safe as initiate_quote_generation has previously set the
          // snp_tcb_version
          seal_ledger_secret(network.ledger_secrets->get_first());

          history->set_service_signing_identity(
            network.identity->get_key_pair(), config.cose_signatures);

          setup_consensus(
            ServiceStatus::OPENING,
            ccf::ReconfigurationType::ONE_TRANSACTION,
            false,
            endorsed_node_cert);

          // Become the primary and force replication
          consensus->force_become_primary();

          LOG_INFO_FMT("Created new node {}", self);
          return {self_signed_node_cert, network.identity->cert};
        }
        case StartType::Join:
        {
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

          ccf::crypto::Pem previous_service_identity_cert(
            config.recover.previous_service_identity.value());

          network.identity = std::make_unique<ccf::NetworkIdentity>(
            ccf::crypto::get_subject_name(previous_service_identity_cert),
            curve_id,
            config.startup_host_time,
            config.initial_service_certificate_validity_days);

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

    void initiate_join_unsafe()
    {
      sm.expect(NodeStartupState::pending);

      auto network_ca = std::make_shared<::tls::CA>(std::string(
        config.join.service_cert.begin(), config.join.service_cert.end()));

      auto join_client_cert = std::make_unique<::tls::Cert>(
        network_ca,
        self_signed_node_cert,
        node_sign_kp->private_key_pem(),
        config.join.target_rpc_address);

      // Create RPC client and connect to remote node
      // Note: For now, assume that target node accepts same application
      // protocol as this node's main RPC interface
      auto join_client = rpcsessions->create_client(
        std::move(join_client_cert),
        rpcsessions->get_app_protocol_main_interface());

      auto [target_host, target_port] =
        split_net_address(config.join.target_rpc_address);

      join_client->connect(
        target_host,
        target_port,
        [this](
          ccf::http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          std::lock_guard<pal::Mutex> guard(lock);
          if (!sm.check(NodeStartupState::pending))
          {
            return;
          }

          if (is_http_status_client_error(status))
          {
            auto error_msg = fmt::format(
              "Join request to {} returned {} Bad Request: {}. Shutting "
              "down node gracefully.",
              config.join.target_rpc_address,
              status,
              std::string(data.begin(), data.end()));
            LOG_FAIL_FMT("{}", error_msg);
            RINGBUFFER_WRITE_MESSAGE(
              AdminMessage::fatal_error_msg, to_host, error_msg);
          }
          else if (status != HTTP_STATUS_OK)
          {
            const auto& location = headers.find(http::headers::LOCATION);
            if (
              config.join.follow_redirect &&
              (status == HTTP_STATUS_PERMANENT_REDIRECT ||
               status == HTTP_STATUS_TEMPORARY_REDIRECT) &&
              location != headers.end())
            {
              const auto& url = ::http::parse_url_full(location->second);
              config.join.target_rpc_address =
                make_net_address(url.host, url.port);
              LOG_INFO_FMT("Target node redirected to {}", location->second);
            }
            else
            {
              LOG_FAIL_FMT(
                "An error occurred while joining the network: {} {}{}",
                status,
                ccf::http_status_str(status),
                data.empty() ?
                  "" :
                  fmt::format("  '{}'", std::string(data.begin(), data.end())));
            }
            return;
          }

          auto j = nlohmann::json::parse(data);

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
            return;
          }

          // Set network secrets, node id and become part of network.
          if (resp.node_status == NodeStatus::TRUSTED)
          {
            if (!resp.network_info.has_value())
            {
              throw std::logic_error("Expected network info in join response");
            }

            network.identity = std::make_unique<ccf::NetworkIdentity>(
              resp.network_info->identity);
            seal_ledger_secret(*resp.network_info->ledger_secrets.rbegin());
            network.ledger_secrets->init_from_map(
              std::move(resp.network_info->ledger_secrets));

            history->set_service_signing_identity(
              network.identity->get_key_pair(),
              resp.network_info->cose_signatures_config.value_or(
                ccf::COSESignaturesConfig{}));

            ccf::crypto::Pem n2n_channels_cert;
            if (!resp.network_info->endorsed_certificate.has_value())
            {
              // Endorsed certificate was added to join response in 2.x
              throw std::logic_error(
                "Expected endorsed certificate in join response");
            }
            n2n_channels_cert = resp.network_info->endorsed_certificate.value();

            setup_consensus(
              resp.network_info->service_status.value_or(
                ServiceStatus::OPENING),
              ccf::ReconfigurationType::ONE_TRANSACTION,
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
            std::vector<ccf::kv::Version> view_history_ = {};
            if (startup_snapshot_info)
            {
              // It is only possible to deserialise the entire snapshot then,
              // once the ledger secrets have been passed in by the network
              ccf::kv::ConsensusHookPtrs hooks;
              deserialise_snapshot(
                network.tables,
                startup_snapshot_info->raw,
                hooks,
                &view_history_,
                resp.network_info->public_only,
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
              view_history_,
              last_recovered_signed_idx);

            snapshotter->set_last_snapshot_idx(
              network.tables->current_version());
            history->start_signature_emit_timer();

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
        },
        [this](const std::string& error_msg) {
          std::lock_guard<pal::Mutex> guard(lock);
          auto long_error_msg = fmt::format(
            "Early error when joining existing network at {}: {}. Shutting "
            "down node gracefully...",
            config.join.target_rpc_address,
            error_msg);
          LOG_FAIL_FMT("{}", long_error_msg);
          RINGBUFFER_WRITE_MESSAGE(
            AdminMessage::fatal_error_msg, to_host, long_error_msg);
        });

      // Send RPC request to remote node to join the network.
      JoinNetworkNodeToNode::In join_params;

      join_params.node_info_network = config.network;
      join_params.public_encryption_key = node_encrypt_kp->public_key_pem();
      join_params.quote_info = quote_info;
      join_params.startup_seqno = startup_seqno;
      join_params.certificate_signing_request = node_sign_kp->create_csr(
        config.node_certificate.subject_name, subject_alt_names);
      join_params.node_data = config.node_data;

      LOG_DEBUG_FMT(
        "Sending join request to {}", config.join.target_rpc_address);

      const auto body = nlohmann::json(join_params).dump();

      LOG_DEBUG_FMT("Sending join request body: {}", body);

      ::http::Request r(
        fmt::format("/{}/{}", get_actor_prefix(ActorsType::nodes), "join"));
      r.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
      r.set_body(body);

      join_client->send_request(std::move(r));
    }

    void initiate_join()
    {
      std::lock_guard<pal::Mutex> guard(lock);
      initiate_join_unsafe();
    }

    void start_join_timer()
    {
      initiate_join_unsafe();

      auto timer_msg = std::make_unique<::threading::Tmsg<NodeStateMsg>>(
        [](std::unique_ptr<::threading::Tmsg<NodeStateMsg>> msg) {
          std::lock_guard<pal::Mutex> guard(msg->data.self.lock);
          if (msg->data.self.sm.check(NodeStartupState::pending))
          {
            msg->data.self.initiate_join_unsafe();
            auto delay = std::chrono::milliseconds(
              msg->data.self.config.join.retry_timeout);

            ::threading::ThreadMessaging::instance().add_task_after(
              std::move(msg), delay);
          }
        },
        *this);

      ::threading::ThreadMessaging::instance().add_task_after(
        std::move(timer_msg), config.join.retry_timeout);
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
        [this](ccf::kv::Version, const ccf::kv::untyped::Write&)
          -> ccf::kv::ConsensusHookPtr {
          jwt_key_auto_refresh->schedule_once();
          return ccf::kv::ConsensusHookPtr(nullptr);
        });
    }

    size_t get_jwt_attempts() override
    {
      return jwt_key_auto_refresh->get_attempts();
    }

    //
    // funcs in state "readingPublicLedger"
    //
    void start_ledger_recovery_unsafe()
    {
      if (!sm.check(NodeStartupState::readingPublicLedger))
      {
        throw std::logic_error(fmt::format(
          "Node should be in state {} to start reading ledger",
          NodeStartupState::readingPublicLedger));
      }

      LOG_INFO_FMT("Starting to read public ledger");

      read_ledger_entries(
        last_recovered_idx + 1, last_recovered_idx + recovery_batch_size);
    }

    void recover_public_ledger_entries(const std::vector<uint8_t>& entries)
    {
      std::lock_guard<pal::Mutex> guard(lock);

      sm.expect(NodeStartupState::readingPublicLedger);

      auto data = entries.data();
      auto size = entries.size();

      if (size == 0)
      {
        recover_public_ledger_end_unsafe();
        return;
      }

      while (size > 0)
      {
        auto entry = ::consensus::LedgerEnclave::get_entry(data, size);

        LOG_INFO_FMT(
          "Deserialising public ledger entry #{} [{} bytes]",
          last_recovered_idx,
          entry.size());

        // When reading the private ledger, deserialise in the recovery store

        ccf::kv::ApplyResult result = ccf::kv::ApplyResult::FAIL;
        try
        {
          auto r = network.tables->deserialize(entry, true);
          result = r->apply();
          if (result == ccf::kv::ApplyResult::FAIL)
          {
            LOG_FAIL_FMT(
              "Failed to deserialise public ledger entry: {}", result);
            recover_public_ledger_end_unsafe();
            return;
          }
          ++last_recovered_idx;

          // Not synchronised because consensus isn't effectively running then
          for (auto& hook : r->get_hooks())
          {
            hook->call(consensus.get());
          }
        }
        catch (const std::exception& e)
        {
          LOG_FAIL_FMT(
            "Failed to deserialise public ledger entry: {}", e.what());
          recover_public_ledger_end_unsafe();
          return;
        }

        // If the ledger entry is a signature, it is safe to compact the store
        if (result == ccf::kv::ApplyResult::PASS_SIGNATURE)
        {
          // If the ledger entry is a signature, it is safe to compact the store
          network.tables->compact(last_recovered_idx);
          auto tx = network.tables->create_read_only_tx();
          auto last_sig = tx.ro(network.signatures)->get();

          if (!last_sig.has_value())
          {
            throw std::logic_error("Signature missing");
          }

          LOG_DEBUG_FMT(
            "Read signature at {} for view {}",
            last_recovered_idx,
            last_sig->view);
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
            last_sig->view >= 0,
            "last_sig->view is invalid, {}",
            last_sig->view);
          for (auto i = view_history.size();
               i < static_cast<size_t>(last_sig->view);
               ++i)
          {
            view_history.push_back(view_start_idx);
          }
          last_recovered_signed_idx = last_recovered_idx;
        }
      }

      read_ledger_entries(
        last_recovered_idx + 1, last_recovered_idx + recovery_batch_size);
    }

    void advance_part_of_public_network()
    {
      std::lock_guard<pal::Mutex> guard(lock);
      sm.expect(NodeStartupState::readingPublicLedger);
      history->start_signature_emit_timer();
      sm.advance(NodeStartupState::partOfPublicNetwork);
    }

    void advance_part_of_network()
    {
      std::lock_guard<pal::Mutex> guard(lock);
      sm.expect(NodeStartupState::initialized);
      history->start_signature_emit_timer();
      auto_refresh_jwt_keys();
      reset_data(quote_info.quote);
      reset_data(quote_info.endorsements);
      sm.advance(NodeStartupState::partOfNetwork);
    }

    void recover_public_ledger_end_unsafe()
    {
      sm.expect(NodeStartupState::readingPublicLedger);

      // When reaching the end of the public ledger, truncate to last signed
      // index
      const auto last_recovered_term = view_history.size();
      auto new_term = last_recovered_term + aft::starting_view_change;
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
      network.ledger_secrets->init(last_recovered_signed_idx + 1);

      // Initialise snapshotter after public recovery
      snapshotter->init_after_public_recovery();
      snapshotter->set_snapshot_generation(false);

      ccf::kv::Version index = 0;
      ccf::kv::Term view = 0;

      auto ls = tx.ro(network.signatures)->get();
      if (ls.has_value())
      {
        auto s = ls.value();
        index = s.seqno;
        view = s.view;
      }
      else
      {
        throw std::logic_error("No signature found after recovery");
      }

      ccf::COSESignaturesConfig cs_cfg{};
      auto lcs = tx.ro(network.cose_signatures)->get();
      if (lcs.has_value())
      {
        CoseSignature cs = lcs.value();
        LOG_INFO_FMT("COSE signature found after recovery");
        try
        {
          auto [issuer, subject] = cose::extract_iss_sub_from_sig(cs);
          LOG_INFO_FMT(
            "COSE signature issuer: {}, subject: {}", issuer, subject);
          cs_cfg = ccf::COSESignaturesConfig{issuer, subject};
        }
        catch (const cose::COSEDecodeError& e)
        {
          LOG_FAIL_FMT("COSE signature decode error: {}", e.what());
          throw;
        }
      }
      else
      {
        LOG_INFO_FMT("No COSE signature found after recovery");
      }

      history->set_service_signing_identity(
        network.identity->get_key_pair(), cs_cfg);

      auto h = dynamic_cast<MerkleTxHistory*>(history.get());
      if (h)
      {
        h->set_node_id(self);
      }

      auto service_config = tx.ro(network.config)->get();

      setup_consensus(
        ServiceStatus::OPENING,
        ccf::ReconfigurationType::ONE_TRANSACTION,
        true);
      auto_refresh_jwt_keys();

      LOG_DEBUG_FMT("Restarting consensus at view: {} seqno: {}", view, index);

      consensus->force_become_primary(index, view, view_history, index);

      create_and_send_boot_request(
        new_term, false /* Restore consortium from ledger */);
    }

    //
    // funcs in state "readingPrivateLedger"
    //
    void recover_private_ledger_entries(const std::vector<uint8_t>& entries)
    {
      std::lock_guard<pal::Mutex> guard(lock);
      if (!sm.check(NodeStartupState::readingPrivateLedger))
      {
        LOG_FAIL_FMT(
          "Node in state {} cannot recover private ledger entries", sm.value());
        return;
      }

      auto data = entries.data();
      auto size = entries.size();

      if (size == 0)
      {
        recover_private_ledger_end_unsafe();
        return;
      }

      while (size > 0)
      {
        auto entry = ::consensus::LedgerEnclave::get_entry(data, size);

        LOG_INFO_FMT(
          "Deserialising private ledger entry {} [{}]",
          last_recovered_idx + 1,
          entry.size());

        // When reading the private ledger, deserialise in the recovery store
        ccf::kv::ApplyResult result = ccf::kv::ApplyResult::FAIL;
        try
        {
          result = recovery_store->deserialize(entry)->apply();
          if (result == ccf::kv::ApplyResult::FAIL)
          {
            LOG_FAIL_FMT(
              "Failed to deserialise private ledger entry: {}", result);
            // Note: rollback terms do not matter here as recovery store is
            // about to be discarded
            recovery_store->rollback({0, last_recovered_idx}, 0);
            recover_private_ledger_end_unsafe();
            return;
          }
          ++last_recovered_idx;
        }
        catch (const std::exception& e)
        {
          LOG_FAIL_FMT(
            "Failed to deserialise private ledger entry: {}", e.what());
          recover_private_ledger_end_unsafe();
          return;
        }

        if (result == ccf::kv::ApplyResult::PASS_SIGNATURE)
        {
          recovery_store->compact(last_recovered_idx);
        }
      }

      if (recovery_store->current_version() == recovery_v)
      {
        LOG_INFO_FMT("Reached recovery final version at {}", recovery_v);
        recover_private_ledger_end_unsafe();
      }
      else
      {
        read_ledger_entries(
          last_recovered_idx + 1,
          std::min(last_recovered_idx + recovery_batch_size, recovery_v));
      }
    }

    void recover_private_ledger_end_unsafe()
    {
      // When reaching the end of the private ledger, make sure the same
      // ledger has been read and swap in private state

      sm.expect(NodeStartupState::readingPrivateLedger);

      LOG_INFO_FMT(
        "Try end private recovery at {}. Is primary: {}",
        recovery_v,
        consensus->is_primary());

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
        LOG_INFO_FMT(
          "Try end private recovery at {}. Trigger service opening",
          recovery_v);

        auto tx = network.tables->create_tx();

        {
          // Ensure this transition happens at-most-once, by checking that no
          // other node has already advanced the state
          auto service = tx.ro<ccf::Service>(Tables::SERVICE);
          auto active_service = service->get();

          if (!active_service.has_value())
          {
            throw std::logic_error(fmt::format(
              "Error in {}: no value in {}", __func__, Tables::SERVICE));
          }

          if (
            active_service->status !=
            ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
          {
            throw std::logic_error(fmt::format(
              "Error in {}: current service status is {}",
              __func__,
              active_service->status));
          }
        }

        // Clear recovery shares that were submitted to initiate the recovery
        // procedure
        ShareManager::clear_submitted_recovery_shares(tx);

        // Shares for the new ledger secret can only be issued now, once the
        // previous ledger secrets have been recovered
        share_manager.issue_recovery_shares(tx);

        if (
          !InternalTablesAccess::open_service(tx) ||
          !InternalTablesAccess::endorse_previous_identity(
            tx, *network.identity->get_key_pair()))
        {
          throw std::logic_error("Service could not be opened");
        }

        // Trigger a snapshot (at next signature) to ensure we have a working
        // snapshot signed by the current (now new) service identity, in case
        // we need to recover soon again.
        trigger_snapshot(tx);

        if (tx.commit() != ccf::kv::CommitResult::SUCCESS)
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
      // secret before recovery is recorded in the store. This can only be
      // fired once, after the recovery shares for the post-recovery ledger
      // secret are issued.
      network.tables->set_map_hook(
        network.encrypted_ledger_secrets.get_name(),
        network.encrypted_ledger_secrets.wrap_map_hook(
          [this](
            ccf::kv::Version version,
            const EncryptedLedgerSecretsInfo::Write& w)
            -> ccf::kv::ConsensusHookPtr {
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

            return ccf::kv::ConsensusHookPtr(nullptr);
          }));
    }

    //
    // funcs in state "readingPublicLedger" or "readingPrivateLedger"
    //
    void recover_ledger_end()
    {
      std::lock_guard<pal::Mutex> guard(lock);

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
      recovery_store = std::make_shared<ccf::kv::Store>(
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
        std::vector<ccf::kv::Version> view_history_;
        ccf::kv::ConsensusHookPtrs hooks;
        deserialise_snapshot(
          recovery_store,
          startup_snapshot_info->raw,
          hooks,
          &view_history_,
          false,
          config.recover.previous_service_identity);
        startup_snapshot_info.reset();
      }

      LOG_DEBUG_FMT(
        "Recovery store successfully setup at {}. Target recovery seqno: {}",
        recovery_store->current_version(),
        recovery_v);
    }

    void trigger_recovery_shares_refresh(ccf::kv::Tx& tx) override
    {
      share_manager.shuffle_recovery_shares(tx);
    }

    void trigger_ledger_chunk(ccf::kv::Tx& tx) override
    {
      auto tx_ = static_cast<ccf::kv::CommittableTx*>(&tx);
      if (tx_ == nullptr)
      {
        throw std::logic_error("Could not cast tx to CommittableTx");
      }
      tx_->set_tx_flag(
        ccf::kv::CommittableTx::TxFlag::LEDGER_CHUNK_AT_NEXT_SIGNATURE);
    }

    void trigger_snapshot(ccf::kv::Tx& tx) override
    {
      auto committable_tx = static_cast<ccf::kv::CommittableTx*>(&tx);
      if (committable_tx == nullptr)
      {
        throw std::logic_error("Could not cast tx to CommittableTx");
      }
      committable_tx->set_tx_flag(
        ccf::kv::CommittableTx::TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
    }

    void trigger_acme_refresh(
      ccf::kv::Tx& tx,
      const std::optional<std::vector<std::string>>& interfaces =
        std::nullopt) override
    {
      if (!network.identity)
      {
        return;
      }

      num_acme_interfaces = 0;

      for (const auto& [iname, interface] : config.network.rpc_interfaces)
      {
        if (
          !interface.endorsement ||
          interface.endorsement->authority != Authority::ACME ||
          !interface.endorsement->acme_configuration)
        {
          continue;
        }

        num_acme_interfaces++;

        if (
          !interfaces ||
          std::find(interfaces->begin(), interfaces->end(), iname) !=
            interfaces->end())
        {
          auto challenge_frontend = find_acme_challenge_frontend();

          const std::string& cfg_name =
            *interface.endorsement->acme_configuration;
          auto cit = config.network.acme->configurations.find(cfg_name);
          if (cit == config.network.acme->configurations.end())
          {
            LOG_INFO_FMT("Unknown ACME configuration '{}'", cfg_name);
            continue;
          }

          if (
            !cit->second.directory_url.empty() &&
            acme_clients.find(cfg_name) == acme_clients.end())
          {
            const auto& cfg = cit->second;

            auto client = std::make_shared<ACMEClient>(
              cfg_name,
              cfg,
              rpc_map,
              rpcsessions,
              challenge_frontend,
              network.tables,
              node_sign_kp);

            auto chit = acme_challenge_handlers.find(iname);
            if (chit != acme_challenge_handlers.end())
            {
              client->install_custom_challenge_handler(chit->second);
            }

            acme_clients.emplace(cfg_name, client);
          }

          auto client = acme_clients[cfg_name];
          if (client && !client->has_active_orders())
          {
            client->get_certificate(
              make_key_pair(network.identity->priv_key), true);
          }
        }
      }
    }

    void trigger_host_process_launch(
      const std::vector<std::string>& args,
      const std::vector<uint8_t>& input) override
    {
      HostProcessArguments msg{args};
      nlohmann::json j = msg;
      auto json = j.dump();
      LOG_DEBUG_FMT(
        "Triggering host process launch: {} size={}", json, input.size());
      RINGBUFFER_WRITE_MESSAGE(
        AppMessage::launch_host_process, to_host, json, input);
    }

    void transition_service_to_open(
      ccf::kv::Tx& tx,
      AbstractGovernanceEffects::ServiceIdentities identities) override
    {
      std::lock_guard<pal::Mutex> guard(lock);

      auto service = tx.rw<Service>(Tables::SERVICE);
      auto service_info = service->get();
      if (!service_info.has_value())
      {
        throw std::logic_error(
          "Service information cannot be found to transition service to "
          "open");
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

      if (service_info->status == ServiceStatus::RECOVERING)
      {
        const auto prev_ident =
          tx.ro<PreviousServiceIdentity>(Tables::PREVIOUS_SERVICE_IDENTITY)
            ->get();
        if (!prev_ident.has_value() || !identities.previous.has_value())
        {
          throw std::logic_error(
            "Recovery with service certificates requires both, a previous "
            "service identity written to the KV during recovery genesis and a "
            "transition_service_to_open proposal that contains previous and "
            "next service certificates");
        }

        const ccf::crypto::Pem from_proposal(
          identities.previous->data(), identities.previous->size());
        if (prev_ident.value() != from_proposal)
        {
          throw std::logic_error(fmt::format(
            "Previous service identity does not match.\nActual:\n{}\nIn "
            "proposal:\n{}",
            prev_ident->str(),
            from_proposal.str()));
        }
      }

      if (identities.next != service_info->cert)
      {
        throw std::logic_error(fmt::format(
          "Service identity mismatch: the next service identity in the "
          "transition_service_to_open proposal does not match the current "
          "service identity:\nNext:\n{}\nCurrent:\n{}",
          identities.next.str(),
          service_info->cert.str()));
      }

      service_info->previous_service_identity_version =
        service->get_version_of_previous_write();

      if (is_part_of_public_network())
      {
        // If the node is in public mode, start accepting member recovery
        // shares
        ShareManager::clear_submitted_recovery_shares(tx);
        service_info->status = ServiceStatus::WAITING_FOR_RECOVERY_SHARES;
        service->put(service_info.value());
        if (config.recover.previous_sealed_ledger_secret_location.has_value())
        {
          tx.wo<LastRecoveryType>(Tables::LAST_RECOVERY_TYPE)
            ->put(RecoveryType::LOCAL_UNSEALING);
          auto unsealed_ls = unseal_ledger_secret();
          LOG_INFO_FMT("Unsealed ledger secret, initiating private recovery");
          initiate_private_recovery_unsafe(tx, unsealed_ls);
        }
        else
        {
          tx.wo<LastRecoveryType>(Tables::LAST_RECOVERY_TYPE)
            ->put(RecoveryType::RECOVERY_SHARES);
        }
        return;
      }
      else if (is_part_of_network())
      {
        // Otherwise, if the node is part of the network. Open the network
        // straight away. Recovery shares are allocated to each recovery
        // member.
        try
        {
          share_manager.issue_recovery_shares(tx);
        }
        catch (const std::logic_error& e)
        {
          throw std::logic_error(
            fmt::format("Failed to issue recovery shares: {}", e.what()));
        }

        InternalTablesAccess::open_service(tx);
        InternalTablesAccess::endorse_previous_identity(
          tx, *network.identity->get_key_pair());
        trigger_snapshot(tx);
        return;
      }
      else
      {
        throw std::logic_error(
          fmt::format("Node in state {} cannot open service", sm.value()));
      }
    }

    // Decrypts chain of ledger secrets, and writes those to the ledger
    // encrypted for each node. On a commit hook for this write, each node
    // (including this one!) will begin_private_recovery().
    void initiate_private_recovery_unsafe(
      ccf::kv::Tx& tx,
      const std::optional<LedgerSecretPtr>& unsealed_ledger_secret =
        std::nullopt)
    {
      sm.expect(NodeStartupState::partOfPublicNetwork);
      LedgerSecretsMap recovered_ledger_secrets =
        share_manager.restore_recovery_shares_info(
          tx, recovered_encrypted_ledger_secrets, unsealed_ledger_secret);

      // Broadcast decrypted ledger secrets to other nodes for them to
      // initiate private recovery too
      LedgerSecretsBroadcast::broadcast_some(
        InternalTablesAccess::get_trusted_nodes(tx),
        tx.wo(network.secrets),
        std::move(recovered_ledger_secrets));
    }

    void initiate_private_recovery(
      ccf::kv::Tx& tx,
      const std::optional<LedgerSecretPtr>& unsealed_ledger_secret =
        std::nullopt) override
    {
      std::lock_guard<pal::Mutex> guard(lock);
      initiate_private_recovery_unsafe(tx, unsealed_ledger_secret);
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

      n2n_channels->tick(elapsed);
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

    void stop_notice() override
    {
      stop_noticed = true;
    }

    bool has_received_stop_notice() override
    {
      return stop_noticed;
    }

    void recv_node_inbound(const uint8_t* data, size_t size)
    {
      auto [msg_type, from, payload] =
        ringbuffer::read_message<node_inbound>(data, size);

      auto payload_data = payload.data;
      auto payload_size = payload.size;

      if (msg_type == NodeMsgType::forwarded_msg)
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

    bool is_part_of_public_network() const override
    {
      return sm.check(NodeStartupState::partOfPublicNetwork);
    }

    bool is_accessible_to_members() const override
    {
      const auto val = sm.value();
      return val == NodeStartupState::partOfNetwork ||
        val == NodeStartupState::partOfPublicNetwork ||
        val == NodeStartupState::readingPrivateLedger;
    }

    ExtendedState state() override
    {
      std::lock_guard<pal::Mutex> guard(lock);
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

    bool rekey_ledger(ccf::kv::Tx& tx) override
    {
      std::lock_guard<pal::Mutex> guard(lock);
      sm.expect(NodeStartupState::partOfNetwork);

      // The ledger should not be re-keyed when the service is not open
      // because:
      // - While waiting for recovery shares, the submitted shares are stored
      // in a public table, encrypted with the ledger secret generated at
      // startup of the first recovery node
      // - On recovery, historical ledger secrets can only be looked up in the
      // ledger once all ledger secrets have been restored
      const auto service_status = InternalTablesAccess::get_service_status(tx);
      if (
        !service_status.has_value() ||
        service_status.value() != ServiceStatus::OPEN)
      {
        LOG_FAIL_FMT("Cannot rekey ledger while the service is not open");
        return false;
      }

      // Effects of ledger rekey are only observed from the next transaction,
      // once the local hook on the secrets table has been triggered.

      auto new_ledger_secret = make_ledger_secret();
      share_manager.issue_recovery_shares(tx, new_ledger_secret);
      LedgerSecretsBroadcast::broadcast_new(
        InternalTablesAccess::get_trusted_nodes(tx),
        tx.wo(network.secrets),
        std::move(new_ledger_secret));

      return true;
    }

    NodeId get_node_id() const
    {
      return self;
    }

    ccf::kv::Version get_startup_snapshot_seqno() override
    {
      std::lock_guard<pal::Mutex> guard(lock);
      return startup_seqno;
    }

    SessionMetrics get_session_metrics() override
    {
      return rpcsessions->get_session_metrics();
    }

    ccf::crypto::Pem get_self_signed_certificate() override
    {
      std::lock_guard<pal::Mutex> guard(lock);
      return self_signed_node_cert;
    }

    const ccf::COSESignaturesConfig& get_cose_signatures_config() override
    {
      if (history == nullptr)
      {
        throw std::logic_error(
          "Attempting to access COSE signatures config before history has been "
          "constructed");
      }

      return history->get_cose_signatures_config();
    }

    void self_healing_open_try_start_timers(
      ccf::kv::Tx& tx, bool recovering) override
    {
      if (
        !recovering || !config.recover.self_healing_open_addresses.has_value())
      {
        LOG_TRACE_FMT(
          "Not recovering, or no self-healing-open addresses configured, "
          "not starting self-healing-open timers");
        return;
      }

      auto* state_handle = tx.rw(network.self_healing_open_sm_state);
      state_handle->put(SelfHealingOpenSM::GOSSIPPING);
      auto* timeout_state_handle =
        tx.rw(network.self_healing_open_timeout_sm_state);
      timeout_state_handle->put(SelfHealingOpenSM::GOSSIPPING);

      auto retry_timer_msg = std::make_unique<::threading::Tmsg<NodeStateMsg>>(
        [](std::unique_ptr<::threading::Tmsg<NodeStateMsg>> msg) {
          std::lock_guard<pal::Mutex> guard(msg->data.self.lock);

          auto tx = msg->data.self.network.tables->create_read_only_tx();
          auto* sm_state_handle =
            tx.ro(msg->data.self.network.self_healing_open_sm_state);
          if (!sm_state_handle->get().has_value())
          {
            throw std::logic_error(
              "Self-healing-open state not set, cannot retry "
              "self-healing-open");
          }
          auto sm_state = sm_state_handle->get().value();

          // Keep doing this until the node is no longer in recovery
          if (sm_state == SelfHealingOpenSM::OPEN)
          {
            LOG_INFO_FMT("Self-healing-open complete, stopping timers.");
            return;
          }

          switch (sm_state)
          {
            case SelfHealingOpenSM::GOSSIPPING:
              msg->data.self.self_healing_open_gossip_unsafe();
              break;
            case SelfHealingOpenSM::VOTING:
            {
              auto* node_info_handle =
                tx.ro(msg->data.self.network.self_healing_open_node_info);
              auto* chosen_replica_handle =
                tx.ro(msg->data.self.network.self_healing_open_chosen_replica);
              if (!chosen_replica_handle->get().has_value())
              {
                throw std::logic_error(
                  "Self-healing-open chosen node not set, cannot vote");
              }
              auto chosen_node_info =
                node_info_handle->get(chosen_replica_handle->get().value());
              if (!chosen_node_info.has_value())
              {
                throw std::logic_error(fmt::format(
                  "Self-healing-open chosen node {} not found",
                  chosen_replica_handle->get().value()));
              }
              msg->data.self.self_healing_open_vote_unsafe(
                chosen_node_info.value());
              // keep gossiping to allow lagging nodes to eventually vote
              msg->data.self.self_healing_open_gossip_unsafe();
              break;
            }
            case SelfHealingOpenSM::OPENING:
              msg->data.self.self_healing_open_iamopen_unsafe();
              break;
            case SelfHealingOpenSM::JOINING:
              return;
            default:
              throw std::logic_error(fmt::format(
                "Unknown self-healing-open state: {}",
                static_cast<int>(sm_state)));
          }

          auto delay =
            msg->data.self.config.recover.self_healing_open_retry_timeout;
          ::threading::ThreadMessaging::instance().add_task_after(
            std::move(msg), delay);
        },
        *this);
      // kick this off asynchronously as this can be called from a curl callback
      ::threading::ThreadMessaging::instance().add_task(
        threading::get_current_thread_id(), std::move(retry_timer_msg));

      // Dispatch timeouts
      auto timeout_msg = std::make_unique<::threading::Tmsg<NodeStateMsg>>(
        [](std::unique_ptr<::threading::Tmsg<NodeStateMsg>> msg) {
          std::lock_guard<pal::Mutex> guard(msg->data.self.lock);
          LOG_TRACE_FMT(
            "Self-healing-open timeout, sending timeout to internal handlers");

          curl::UniqueCURL curl_handle;

          auto cert = msg->data.self.self_signed_node_cert;
          curl_handle.set_opt(CURLOPT_SSL_VERIFYHOST, 0L);
          curl_handle.set_opt(CURLOPT_SSL_VERIFYPEER, 0L);
          curl_handle.set_opt(CURLOPT_SSL_VERIFYSTATUS, 0L);

          curl_handle.set_blob_opt(
            CURLOPT_SSLCERT_BLOB, cert.data(), cert.size());
          curl_handle.set_opt(CURLOPT_SSLCERTTYPE, "PEM");

          auto privkey_pem = msg->data.self.node_sign_kp->private_key_pem();
          curl_handle.set_blob_opt(
            CURLOPT_SSLKEY_BLOB, privkey_pem.data(), privkey_pem.size());
          curl_handle.set_opt(CURLOPT_SSLKEYTYPE, "PEM");

          auto url = fmt::format(
            "https://{}/{}/self_healing_open/timeout",
            msg->data.self.config.network.rpc_interfaces
              .at("primary_rpc_interface")
              .published_address,
            get_actor_prefix(ActorsType::nodes));

          curl::UniqueSlist headers;
          headers.append("Content-Type: application/json");

          // This is simpler than going via the internal handlers...
          auto curl_request = std::make_unique<curl::CurlRequest>(
            std::move(curl_handle),
            HTTP_PUT,
            std::move(url),
            std::move(headers),
            nullptr,
            std::nullopt);
          curl::CurlmLibuvContextSingleton::get_instance().attach_request(
            curl_request);

          auto delay = msg->data.self.config.recover.self_healing_open_timeout;
          ::threading::ThreadMessaging::instance().add_task_after(
            std::move(msg), delay);
        },
        *this);
      ::threading::ThreadMessaging::instance().add_task_after(
        std::move(timeout_msg), config.recover.self_healing_open_timeout);
    }

    void self_healing_open_advance(ccf::kv::Tx& tx, bool timeout) override
    {
      auto* sm_state_handle = tx.rw(network.self_healing_open_sm_state);
      auto* timeout_state_handle =
        tx.rw(network.self_healing_open_timeout_sm_state);
      if (
        !sm_state_handle->get().has_value() ||
        !timeout_state_handle->get().has_value())
      {
        throw std::logic_error(
          "Self-healing-open state not set, cannot advance self-healing-open");
      }

      bool valid_timeout = timeout &&
        timeout_state_handle->get().value() == sm_state_handle->get().value();

      // Advance timeout SM
      if (timeout)
      {
        switch (timeout_state_handle->get().value())
        {
          case SelfHealingOpenSM::GOSSIPPING:
            LOG_TRACE_FMT("Advancing timeout SM to VOTING");
            timeout_state_handle->put(SelfHealingOpenSM::VOTING);
            break;
          case SelfHealingOpenSM::VOTING:
            LOG_TRACE_FMT("Advancing timeout SM to OPENING");
            timeout_state_handle->put(SelfHealingOpenSM::OPENING);
            break;
          case SelfHealingOpenSM::OPENING:
          case SelfHealingOpenSM::JOINING:
          case SelfHealingOpenSM::OPEN:
          default:
            LOG_TRACE_FMT("Timeout SM complete");
        }
      }

      switch (sm_state_handle->get().value())
      {
        case SelfHealingOpenSM::GOSSIPPING:
        {
          auto* gossip_handle = tx.ro(network.self_healing_open_gossip);
          if (
            gossip_handle->size() ==
              config.recover.self_healing_open_addresses.value().size() ||
            valid_timeout)
          {
            if (gossip_handle->size() == 0)
            {
              throw std::logic_error("No gossip addresses provided yet");
            }

            std::optional<std::pair<std::string, ccf::kv::Version>> min_iid;
            gossip_handle->foreach(
              [&min_iid](const auto& iid, const auto& txid) {
                if (
                  !min_iid.has_value() || min_iid->second < txid ||
                  (min_iid->second == txid && min_iid->first > iid))
                {
                  min_iid = std::make_pair(iid, txid);
                }
                return true;
              });

            auto* chosen_replica =
              tx.rw(network.self_healing_open_chosen_replica);
            chosen_replica->put(min_iid->first);
            sm_state_handle->put(SelfHealingOpenSM::VOTING);
          }
          return;
        }
        case SelfHealingOpenSM::VOTING:
        {
          auto* votes = tx.rw(network.self_healing_open_votes);
          if (
            votes->size() >=
              config.recover.self_healing_open_addresses.value().size() / 2 +
                1 ||
            valid_timeout)
          {
            if (votes->size() == 0)
            {
              throw std::logic_error(
                "We didn't even vote for ourselves, so why should we open?");
            }
            LOG_INFO_FMT("Self-healing-open succeeded, now opening network");

            sm_state_handle->put(SelfHealingOpenSM::OPENING);
          }
          return;
        }
        case SelfHealingOpenSM::JOINING:
        {
          auto chosen_replica =
            tx.ro(network.self_healing_open_chosen_replica)->get();
          if (!chosen_replica.has_value())
          {
            throw std::logic_error(
              "Self-healing-open chosen node not set, cannot join");
          }
          auto node_config = tx.ro(this->network.self_healing_open_node_info)
                               ->get(chosen_replica.value());
          if (!node_config.has_value())
          {
            throw std::logic_error(fmt::format(
              "Self-healing-open chosen node {} not found",
              chosen_replica.value()));
          }

          LOG_INFO_FMT(
            "Self-healing-open joining {} with service identity {}",
            node_config->published_network_address,
            node_config->service_identity);

          RINGBUFFER_WRITE_MESSAGE(
            AdminMessage::restart_and_join,
            to_host,
            node_config->published_network_address,
            node_config->service_identity);
        }
        case SelfHealingOpenSM::OPENING:
        {
          // TODO: Add fast path if enough replicas have joined already
          // THIS IS POSSIBLY DANGEROUS as these joining replicas are not signed
          // off...
          if (valid_timeout)
          {
            auto* service = tx.ro<Service>(Tables::SERVICE);
            auto service_info = service->get();
            if (!service_info.has_value())
            {
              throw std::logic_error(
                "Service information cannot be found to transition service to "
                "open");
            }
            const auto prev_ident =
              tx.ro<PreviousServiceIdentity>(Tables::PREVIOUS_SERVICE_IDENTITY)
                ->get();
            AbstractGovernanceEffects::ServiceIdentities identities{
              .previous = prev_ident, .next = service_info->cert};

            sm_state_handle->put(SelfHealingOpenSM::OPEN);

            transition_service_to_open(tx, identities);
          }
        }
        case SelfHealingOpenSM::OPEN:
        {
          // Nothing to do here, we are already opening or open or joining
          return;
        }
        default:
          throw std::logic_error(fmt::format(
            "Unknown self-healing-open state: {}",
            static_cast<int>(sm_state_handle->get().value())));
      }
    }

  private:
    bool is_ip(const std::string_view& hostname)
    {
      // IP address components are purely numeric. DNS names may be largely
      // numeric, but at least the final component (TLD) must not be
      // all-numeric. So this distinguishes "1.2.3.4" (an IP address) from
      // "1.2.3.c4m" (a DNS name). "1.2.3." is invalid for either, and will
      // throw. Attempts to handle IPv6 by also splitting on ':', but this is
      // untested.
      const auto final_component =
        ccf::nonstd::split(ccf::nonstd::split(hostname, ".").back(), ":")
          .back();
      if (final_component.empty())
      {
        throw std::runtime_error(fmt::format(
          "{} has a trailing period, is not a valid hostname", hostname));
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

    std::vector<ccf::crypto::SubjectAltName> get_subject_alternative_names()
    {
      // If no Subject Alternative Name (SAN) is passed in at node creation,
      // default to using node's RPC address as single SAN. Otherwise, use
      // specified SANs.
      if (!config.node_certificate.subject_alt_names.empty())
      {
        return ccf::crypto::sans_from_string_list(
          config.node_certificate.subject_alt_names);
      }
      else
      {
        // Construct SANs from RPC interfaces, manually detecting whether each
        // is a domain name or IP
        std::vector<ccf::crypto::SubjectAltName> sans;
        for (const auto& [_, interface] : config.network.rpc_interfaces)
        {
          auto host = split_net_address(interface.published_address).first;
          sans.push_back({host, is_ip(host)});
        }
        return sans;
      }
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
        "Node certificate should be endorsed before accepting endorsed "
        "client "
        "connections");
      rpcsessions->set_network_cert(
        endorsed_node_cert.value(), node_sign_kp->private_key_pem());
      LOG_INFO_FMT("Network TLS connections now accepted");
    }

    auto find_frontend(ActorsType actor)
    {
      auto fe = rpc_map->find(actor);
      if (!fe.has_value())
      {
        throw std::logic_error(
          fmt::format("Cannot find {} frontend", (int)actor));
      }
      return fe.value();
    }

    void open_frontend(ActorsType actor)
    {
      find_frontend(actor)->open();
    }

    void open_user_frontend()
    {
      open_frontend(ActorsType::users);
    }

    bool is_member_frontend_open_unsafe()
    {
      return find_frontend(ActorsType::members)->is_open();
    }

    bool is_member_frontend_open() override
    {
      std::lock_guard<pal::Mutex> guard(lock);
      return is_member_frontend_open_unsafe();
    }

    bool is_user_frontend_open() override
    {
      std::lock_guard<pal::Mutex> guard(lock);
      return find_frontend(ActorsType::users)->is_open();
    }

    std::shared_ptr<ACMERpcFrontend> find_acme_challenge_frontend()
    {
      auto acme_challenge_opt = rpc_map->find(ActorsType::acme_challenge);
      if (!acme_challenge_opt)
      {
        throw std::runtime_error("Missing ACME challenge frontend");
      }
      return std::static_pointer_cast<ACMERpcFrontend>(*acme_challenge_opt);
    }

    void open_acme_challenge_frontend()
    {
      if (config.network.acme && !config.network.acme->configurations.empty())
      {
        auto fe = find_frontend(ActorsType::acme_challenge);
        if (fe)
        {
          fe->open();
        }
      }
    }

    std::vector<uint8_t> serialize_create_request(
      View create_view, bool create_consortium = true)
    {
      CreateNetworkNodeToNode::In create_params;

      // False on recovery where the consortium is read from the existing
      // ledger
      if (create_consortium)
      {
        create_params.genesis_info = config.start;
      }
      create_params.recovery_constitution = config.recover.constitution;
      LOG_INFO_FMT("serialise_create_request, set recovery_constitution to:");
      if (create_params.recovery_constitution.has_value())
      {
        LOG_INFO_FMT("{}", create_params.recovery_constitution.value());
      }
      else
      {
        LOG_INFO_FMT("No recovery constitution provided");
      }

      create_params.node_id = self;
      create_params.certificate_signing_request = node_sign_kp->create_csr(
        config.node_certificate.subject_name, subject_alt_names);
      create_params.node_endorsed_certificate =
        ccf::crypto::create_endorsed_cert(
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
      create_params.measurement = node_measurement;
      create_params.snp_uvm_endorsements = snp_uvm_endorsements;
      create_params.snp_security_policy =
        config.attestation.environment.security_policy;

      create_params.node_info_network = config.network;
      create_params.node_data = config.node_data;
      create_params.service_data = config.service_data;
      create_params.create_txid = {create_view, last_recovered_signed_idx + 1};

      const auto body = nlohmann::json(create_params).dump();

      ::http::Request request(
        fmt::format("/{}/{}", get_actor_prefix(ActorsType::nodes), "create"));
      request.set_header(
        ccf::http::headers::CONTENT_TYPE,
        ccf::http::headervalues::contenttype::JSON);

      request.set_body(body);

      return request.build_request();
    }

    bool extract_create_result(const std::shared_ptr<RpcContext>& ctx)
    {
      if (ctx == nullptr)
      {
        LOG_FAIL_FMT("Expected non-null context");
        return false;
      }

      const auto status = ctx->get_response_status();
      const auto& raw_body = ctx->get_response_body();
      if (status != HTTP_STATUS_OK)
      {
        LOG_FAIL_FMT(
          "Create response is error: {} {}\n{}",
          status,
          ccf::http_status_str((ccf::http_status)status),
          std::string(raw_body.begin(), raw_body.end()));
        return false;
      }

      const auto body = nlohmann::json::parse(raw_body);
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
      auto node_session = std::make_shared<SessionContext>(
        InvalidSessionId, self_signed_node_cert.raw());
      auto ctx = make_rpc_context(node_session, packed);

      std::shared_ptr<ccf::RpcHandler> search =
        ::http::fetch_rpc_handler(ctx, this->rpc_map);

      search->process(ctx);

      return extract_create_result(ctx);
    }

    void create_and_send_boot_request(
      View create_view, bool create_consortium = true)
    {
      // Service creation transaction is asynchronous to avoid deadlocks
      // (e.g. https://github.com/microsoft/CCF/issues/3788)
      auto msg = std::make_unique<::threading::Tmsg<NodeStateMsg>>(
        [](std::unique_ptr<::threading::Tmsg<NodeStateMsg>> msg) {
          if (!msg->data.self.send_create_request(
                msg->data.self.serialize_create_request(
                  msg->data.create_view, msg->data.create_consortium)))
          {
            throw std::runtime_error(
              "Service creation request could not be committed");
          }
          if (msg->data.create_consortium)
          {
            msg->data.self.advance_part_of_network();
          }
          else
          {
            msg->data.self.advance_part_of_public_network();
          }
        },
        *this,
        create_view,
        create_consortium);

      ::threading::ThreadMessaging::instance().add_task(
        threading::get_current_thread_id(), std::move(msg));
    }

    void begin_private_recovery()
    {
      sm.expect(NodeStartupState::partOfPublicNetwork);

      LOG_INFO_FMT("Beginning private recovery");

      setup_private_recovery_store();

      reset_recovery_hook();
      setup_one_off_secret_hook();

      // Start reading private security domain of ledger
      sm.advance(NodeStartupState::readingPrivateLedger);
      last_recovered_idx = recovery_store->current_version();
      read_ledger_entries(
        last_recovered_idx + 1, last_recovered_idx + recovery_batch_size);
    }

    void setup_basic_hooks()
    {
      network.tables->set_map_hook(
        network.secrets.get_name(),
        network.secrets.wrap_map_hook(
          [this](ccf::kv::Version hook_version, const Secrets::Write& w)
            -> ccf::kv::ConsensusHookPtr {
            // Used to rekey the ledger on a live service
            if (!is_part_of_network())
            {
              // Ledger rekey is not allowed during recovery
              return ccf::kv::ConsensusHookPtr(nullptr);
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
                auto ledger_secret = std::make_shared<LedgerSecret>(
                  std::move(plain_ledger_secret), hook_version);
                seal_ledger_secret(hook_version + 1, ledger_secret);
                network.ledger_secrets->set_secret(
                  hook_version + 1, std::move(ledger_secret));
              }
            }

            return ccf::kv::ConsensusHookPtr(nullptr);
          }));

      network.tables->set_global_hook(
        network.secrets.get_name(),
        network.secrets.wrap_commit_hook([this](
                                           ccf::kv::Version hook_version,
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
              // the hook is executed. Otherwise, on recovery, use the
              // version read from the write set.
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
              begin_private_recovery();
              return;
            }
          }

          LOG_INFO_FMT(
            "Found no ledger secrets for this node ({}) in global commit hook "
            "for {} @ {}",
            self,
            network.secrets.get_name(),
            hook_version);
        }));

      network.tables->set_global_hook(
        network.nodes.get_name(),
        network.nodes.wrap_commit_hook(
          [this](ccf::kv::Version hook_version, const Nodes::Write& w) {
            std::vector<NodeId> retired_committed_nodes;
            for (const auto& [node_id, node_info] : w)
            {
              if (node_info.has_value() && node_info->retired_committed)
              {
                retired_committed_nodes.push_back(node_id);
              }
            }
            consensus->set_retired_committed(
              hook_version, retired_committed_nodes);
          }));

      // Service-endorsed certificate is passed to history as early as _local_
      // commit since a new node may become primary (and thus, e.g. generate
      // signatures) before the transaction that added it is _globally_
      // committed (see https://github.com/microsoft/CCF/issues/4063). It is OK
      // if this transaction is rolled back as the node will no longer be part
      // of the service.
      network.tables->set_map_hook(
        network.node_endorsed_certificates.get_name(),
        network.node_endorsed_certificates.wrap_map_hook(
          [this](
            ccf::kv::Version hook_version,
            const NodeEndorsedCertificates::Write& w)
            -> ccf::kv::ConsensusHookPtr {
            LOG_INFO_FMT(
              "[local] node_endorsed_certificates local hook at version {}, "
              "with {} writes",
              hook_version,
              w.size());
            for (auto const& [node_id, endorsed_certificate] : w)
            {
              if (node_id != self)
              {
                LOG_INFO_FMT(
                  "[local] Ignoring endorsed certificate for other node {}",
                  node_id);
                continue;
              }

              if (!endorsed_certificate.has_value())
              {
                LOG_FAIL_FMT(
                  "[local] Endorsed cert for self ({}) has been deleted", self);
                throw std::logic_error(fmt::format(
                  "Could not find endorsed node certificate for {}", self));
              }

              std::lock_guard<pal::Mutex> guard(lock);

              if (endorsed_node_cert.has_value())
              {
                LOG_INFO_FMT(
                  "[local] Previous endorsed node cert was:\n{}",
                  endorsed_node_cert->str());
              }

              endorsed_node_cert = endorsed_certificate.value();
              LOG_INFO_FMT(
                "[local] Under lock, setting endorsed node cert to:\n{}",
                endorsed_node_cert->str());
              history->set_endorsed_certificate(endorsed_node_cert.value());
              n2n_channels->set_endorsed_node_cert(endorsed_node_cert.value());
            }

            return ccf::kv::ConsensusHookPtr(nullptr);
          }));

      network.tables->set_global_hook(
        network.node_endorsed_certificates.get_name(),
        network.node_endorsed_certificates.wrap_commit_hook(
          [this](
            ccf::kv::Version hook_version,
            const NodeEndorsedCertificates::Write& w) {
            LOG_INFO_FMT(
              "[global] node_endorsed_certificates global hook at version {}, "
              "with {} writes",
              hook_version,
              w.size());
            for (auto const& [node_id, endorsed_certificate] : w)
            {
              if (node_id != self)
              {
                LOG_INFO_FMT(
                  "[global] Ignoring endorsed certificate for other node {}",
                  node_id);
                continue;
              }

              if (!endorsed_certificate.has_value())
              {
                LOG_FAIL_FMT(
                  "[global] Endorsed cert for self ({}) has been deleted",
                  self);
                throw std::logic_error(fmt::format(
                  "Could not find endorsed node certificate for {}", self));
              }

              std::lock_guard<pal::Mutex> guard(lock);

              LOG_INFO_FMT("[global] Accepting network connections");
              accept_network_tls_connections();

              if (is_member_frontend_open_unsafe())
              {
                // Also, automatically refresh self-signed node certificate,
                // using the same validity period as the endorsed certificate.
                // Note that this is only done when the certificate is renewed
                // via proposal (i.e. when the member frontend is open), and not
                // for the initial addition of the node (the self-signed
                // certificate is output to disk then).
                auto [valid_from, valid_to] =
                  ccf::crypto::make_verifier(endorsed_node_cert.value())
                    ->validity_period();
                LOG_INFO_FMT(
                  "[global] Member frontend is open, so refreshing self-signed "
                  "node cert");
                LOG_INFO_FMT(
                  "[global] Previously:\n{}", self_signed_node_cert.str());
                self_signed_node_cert = create_self_signed_cert(
                  node_sign_kp,
                  config.node_certificate.subject_name,
                  subject_alt_names,
                  valid_from,
                  valid_to);
                LOG_INFO_FMT("[global] Now:\n{}", self_signed_node_cert.str());

                LOG_INFO_FMT("[global] Accepting node connections");
                accept_node_tls_connections();
              }
              else
              {
                LOG_INFO_FMT("[global] Member frontend is NOT open");
                LOG_INFO_FMT(
                  "[global] Self-signed node cert remains:\n{}",
                  self_signed_node_cert.str());
              }

              LOG_INFO_FMT("[global] Opening members frontend");
              open_frontend(ActorsType::members);
            }
          }));

      network.tables->set_global_hook(
        network.service.get_name(),
        network.service.wrap_commit_hook(
          [this](ccf::kv::Version hook_version, const Service::Write& w) {
            if (!w.has_value())
            {
              throw std::logic_error("Unexpected deletion in service value");
            }

            // Service open on historical service has no effect
            auto hook_pubk_pem = ccf::crypto::public_key_pem_from_cert(
              ccf::crypto::cert_pem_to_der(w->cert));
            auto current_pubk_pem =
              ccf::crypto::make_key_pair(network.identity->priv_key)
                ->public_key_pem();
            if (hook_pubk_pem != current_pubk_pem)
            {
              LOG_TRACE_FMT(
                "Ignoring historical service open at seqno {} for {}",
                hook_version,
                w->cert.str());
              return;
            }

            LOG_INFO_FMT(
              "Executing global hook for service table at {}, to service "
              "status {}. Cert is:\n{}",
              hook_version,
              w->status,
              w->cert.str());

            network.identity->set_certificate(w->cert);
            if (w->status == ServiceStatus::OPEN)
            {
              open_user_frontend();

              RINGBUFFER_WRITE_MESSAGE(::consensus::ledger_open, to_host);
              LOG_INFO_FMT("Service open at seqno {}", hook_version);
            }
          }));

      network.tables->set_global_hook(
        network.acme_certificates.get_name(),
        network.acme_certificates.wrap_commit_hook(
          [this](
            ccf::kv::Version hook_version, const ACMECertificates::Write& w) {
            for (auto const& [interface_id, interface] :
                 config.network.rpc_interfaces)
            {
              if (interface.endorsement->acme_configuration)
              {
                auto cit = w.find(*interface.endorsement->acme_configuration);
                if (cit != w.end())
                {
                  LOG_INFO_FMT(
                    "ACME: new certificate for interface '{}' with "
                    "configuration '{}'",
                    interface_id,
                    *interface.endorsement->acme_configuration);
                  rpcsessions->set_cert(
                    Authority::ACME,
                    *cit->second,
                    network.identity->priv_key,
                    cit->first);
                }
              }
            }
          }));
    }

    ccf::kv::Version get_last_recovered_signed_idx() override
    {
      // On recovery, only one node recovers the public ledger and is thus
      // aware of the version at which the new ledger secret is applicable
      // from. If the primary changes while the network is public-only, the
      // new primary should also know at which version the new ledger secret
      // is applicable from.
      std::lock_guard<pal::Mutex> guard(lock);
      return last_recovered_signed_idx;
    }

    void setup_recovery_hook()
    {
      network.tables->set_map_hook(
        network.encrypted_ledger_secrets.get_name(),
        network.encrypted_ledger_secrets.wrap_map_hook(
          [this](
            ccf::kv::Version version,
            const EncryptedLedgerSecretsInfo::Write& w)
            -> ccf::kv::ConsensusHookPtr {
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

            return ccf::kv::ConsensusHookPtr(nullptr);
          }));
    }

    void reset_recovery_hook()
    {
      network.tables->unset_map_hook(
        network.encrypted_ledger_secrets.get_name());
    }

    void setup_n2n_channels(
      const std::optional<ccf::crypto::Pem>& endorsed_node_certificate_ =
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
        false /* start timed signatures after first tx */);
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
      ccf::ReconfigurationType reconfiguration_type,
      bool public_only = false,
      const std::optional<ccf::crypto::Pem>& endorsed_node_certificate_ =
        std::nullopt)
    {
      setup_n2n_channels(endorsed_node_certificate_);
      setup_cmd_forwarder();

      auto shared_state = std::make_shared<aft::State>(self);

      auto node_client = std::make_shared<HTTPNodeClient>(
        rpc_map, node_sign_kp, self_signed_node_cert, endorsed_node_cert);

      ccf::kv::MembershipState membership_state =
        ccf::kv::MembershipState::Active;

      consensus = std::make_shared<RaftType>(
        consensus_config,
        std::make_unique<aft::Adaptor<ccf::kv::Store>>(network.tables),
        std::make_unique<::consensus::LedgerEnclave>(writer_factory),
        n2n_channels,
        shared_state,
        node_client,
        public_only,
        membership_state,
        reconfiguration_type);

      network.tables->set_consensus(consensus);
      network.tables->set_snapshotter(snapshotter);

      // When a node is added, even locally, inform consensus so that it
      // can add a new active configuration.
      network.tables->set_map_hook(
        network.nodes.get_name(),
        network.nodes.wrap_map_hook(
          [](ccf::kv::Version version, const Nodes::Write& w)
            -> ccf::kv::ConsensusHookPtr {
            return std::make_unique<ConfigurationChangeHook>(version, w);
          }));

      // Note: The Signatures hook and SerialisedMerkleTree hook are separate
      // because the signature and the Merkle tree are recorded in distinct
      // tables (for serialisation performance reasons). However here, they are
      // expected to always be called together and for the same version as they
      // are always written by each signature transaction.

      network.tables->set_map_hook(
        network.signatures.get_name(),
        network.signatures.wrap_map_hook(
          [s = this->snapshotter](
            ccf::kv::Version version, const Signatures::Write& w) {
            assert(w.has_value());
            auto sig = w.value();
            s->record_signature(version, sig.sig, sig.node, sig.cert);
            return ccf::kv::ConsensusHookPtr(nullptr);
          }));

      network.tables->set_map_hook(
        network.serialise_tree.get_name(),
        network.serialise_tree.wrap_map_hook(
          [s = this->snapshotter](
            ccf::kv::Version version, const SerialisedMerkleTree::Write& w) {
            assert(w.has_value());
            auto tree = w.value();
            s->record_serialised_tree(version, tree);
            return ccf::kv::ConsensusHookPtr(nullptr);
          }));

      network.tables->set_map_hook(
        network.snapshot_evidence.get_name(),
        network.snapshot_evidence.wrap_map_hook(
          [s = this->snapshotter](
            ccf::kv::Version version, const SnapshotEvidence::Write& w) {
            assert(w.has_value());
            auto snapshot_evidence = w.value();
            s->record_snapshot_evidence_idx(version, snapshot_evidence);
            return ccf::kv::ConsensusHookPtr(nullptr);
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
        writer_factory, network.tables, config.snapshots.tx_count);
    }

    void read_ledger_entries(::consensus::Index from, ::consensus::Index to)
    {
      RINGBUFFER_WRITE_MESSAGE(
        ::consensus::ledger_get_range,
        to_host,
        from,
        to,
        ::consensus::LedgerRequestPurpose::Recovery);
    }

    void ledger_truncate(::consensus::Index idx, bool recovery_mode = false)
    {
      RINGBUFFER_WRITE_MESSAGE(
        ::consensus::ledger_truncate, to_host, idx, recovery_mode);
    }

    void setup_acme_clients()
    {
      if (!config.network.acme || config.network.acme->configurations.empty())
      {
        return;
      }

      open_acme_challenge_frontend();

      const auto& ifaces = config.network.rpc_interfaces;
      num_acme_interfaces =
        std::count_if(ifaces.begin(), ifaces.end(), [](const auto& id_iface) {
          return id_iface.second.endorsement->authority == Authority::ACME;
        });

      if (num_acme_interfaces > 0)
      {
        using namespace threading;

        // Start task to periodically check whether any of the certs are
        // expired.
        auto msg = std::make_unique<::threading::Tmsg<NodeStateMsg>>(
          [](std::unique_ptr<::threading::Tmsg<NodeStateMsg>> msg) {
            auto& state = msg->data.self;

            if (state.consensus && state.consensus->can_replicate())
            {
              if (state.acme_clients.size() != state.num_acme_interfaces)
              {
                auto tx = state.network.tables->create_tx();
                state.trigger_acme_refresh(tx);
                tx.commit();
              }
              else
              {
                for (auto& [cfg_name, client] : state.acme_clients)
                {
                  if (client)
                  {
                    client->check_expiry(
                      state.network.tables, state.network.identity);
                  }
                }
              }
            }

            auto delay = std::chrono::minutes(1);
            ::threading::ThreadMessaging::instance().add_task_after(
              std::move(msg), delay);
          },
          *this);

        ::threading::ThreadMessaging::instance().add_task_after(
          std::move(msg), std::chrono::seconds(2));
      }
    }

    void seal_ledger_secret(const VersionedLedgerSecret& ledger_secret)
    {
      seal_ledger_secret(ledger_secret.first, ledger_secret.second);
    }

    void seal_ledger_secret(
      const kv::Version& version, const LedgerSecretPtr& ledger_secret)
    {
      if (!config.sealed_ledger_secret_location.has_value())
      {
        return;
      }

      CCF_ASSERT(
        snp_tcb_version.has_value(), "TCB version must be set before sealing");

      seal_ledger_secret_to_disk(
        config.sealed_ledger_secret_location.value(),
        snp_tcb_version.value(),
        version,
        ledger_secret);
    }

    LedgerSecretPtr unseal_ledger_secret()
    {
      CCF_ASSERT(
        snp_tcb_version.has_value(),
        "TCB version must be set when unsealing ledger sec/ret");

      CCF_ASSERT(
        config.recover.previous_sealed_ledger_secret_location.has_value(),
        "Previous sealed ledger secret location must be set");
      auto ledger_secret_path =
        config.recover.previous_sealed_ledger_secret_location.value();

      auto max_version = network.tables->current_version();

      return find_and_unseal_ledger_secret_from_disk(
        config.recover.previous_sealed_ledger_secret_location.value(),
        max_version);
    }

    self_healing_open::RequestNodeInfo self_healing_open_node_info()
    {
      return {
        .quote_info = quote_info,
        .published_network_address =
          config.network.rpc_interfaces.at("primary_rpc_interface")
            .published_address,
        .intrinsic_id =
          config.network.rpc_interfaces.at("primary_rpc_interface")
            .published_address,
        .service_identity = network.identity->cert.str(),
      };
    }

    void self_healing_open_gossip_unsafe()
    {
      // Caller must ensure that the current node's quote_info is populated:
      // ie not yet reached partOfNetwork
      if (!config.recover.self_healing_open_addresses.has_value())
      {
        LOG_TRACE_FMT(
          "Self-healing-open addresses not set, cannot start gossip retries");
        return;
      }

      LOG_TRACE_FMT("Broadcasting self-healing-open gossip");

      self_healing_open::GossipRequest request{
        .info = self_healing_open_node_info(),
        // TODO fix: This isn't quite right, as it should be the highest txid
        // with a signature,before the recovery txs
        .txid = network.tables->current_version(),
      };

      for (auto& target_address :
           config.recover.self_healing_open_addresses.value())
      {
        self_healing_open::dispatch_authenticated_message(
          std::move(request),
          target_address,
          "gossip",
          self_signed_node_cert,
          node_sign_kp->private_key_pem());
      }
    }

    void self_healing_open_vote_unsafe(SelfHealingOpenNodeInfo_t& node_info)
    {
      // Caller must ensure that the current node's quote_info is populated:
      // ie not yet reached partOfNetwork
      LOG_TRACE_FMT(
        "Sending self-healing-open vote to {} at {}",
        node_info.intrinsic_id,
        node_info.published_network_address);

      self_healing_open::VoteRequest request{
        .info = self_healing_open_node_info()};

      self_healing_open::dispatch_authenticated_message(
        std::move(request),
        node_info.published_network_address,
        "vote",
        self_signed_node_cert,
        node_sign_kp->private_key_pem());
    }

    void self_healing_open_iamopen_unsafe()
    {
      // Caller must ensure that the current node's quote_info is populated:
      // ie not yet reached partOfNetwork
      if (!config.recover.self_healing_open_addresses.has_value())
      {
        LOG_TRACE_FMT(
          "Self-healing-open addresses not set, cannot send iamopen");
        return;
      }

      LOG_TRACE_FMT("Sending self-healing-open iamopen");

      self_healing_open::IAmOpenRequest request{
        .info = self_healing_open_node_info()};

      for (auto& target_address :
           config.recover.self_healing_open_addresses.value())
      {
        if (
          target_address ==
          config.network.rpc_interfaces.at("primary_rpc_interface")
            .published_address)
        {
          // Don't send to self
          continue;
        }
        self_healing_open::dispatch_authenticated_message(
          std::move(request),
          target_address,
          "iamopen",
          self_signed_node_cert,
          node_sign_kp->private_key_pem());
      }
    }

  public:
    void set_n2n_message_limit(size_t message_limit)
    {
      n2n_channels->set_message_limit(message_limit);
    }

    void set_n2n_idle_timeout(std::chrono::milliseconds idle_timeout)
    {
      n2n_channels->set_idle_timeout(idle_timeout);
    }

    virtual const ccf::StartupConfig& get_node_config() const override
    {
      return config;
    }

    virtual ccf::crypto::Pem get_network_cert() override
    {
      return network.identity->cert;
    }

    virtual void install_custom_acme_challenge_handler(
      const ccf::NodeInfoNetwork::RpcInterfaceID& interface_id,
      std::shared_ptr<ACMEChallengeHandler> h) override
    {
      acme_challenge_handlers[interface_id] = h;
    }

    // Stop-gap until it becomes easier to use other HTTP clients
    virtual void make_http_request(
      const ::http::URL& url,
      ::http::Request&& req,
      std::function<bool(
        ccf::http_status status, http::HeaderMap&&, std::vector<uint8_t>&&)>
        callback,
      const std::vector<std::string>& ca_certs = {},
      const std::string& app_protocol = "HTTP1",
      bool authenticate_as_node_client_certificate = false) override
    {
      std::optional<ccf::crypto::Pem> client_cert = std::nullopt;
      std::optional<ccf::crypto::Pem> client_cert_key = std::nullopt;
      if (authenticate_as_node_client_certificate)
      {
        client_cert =
          endorsed_node_cert ? *endorsed_node_cert : self_signed_node_cert;
        client_cert_key = node_sign_kp->private_key_pem();
      }

      auto ca = std::make_shared<::tls::CA>(ca_certs, true);
      std::shared_ptr<::tls::Cert> ca_cert =
        std::make_shared<::tls::Cert>(ca, client_cert, client_cert_key);
      auto client = rpcsessions->create_client(ca_cert, app_protocol);
      client->connect(
        url.host,
        url.port,
        [callback](
          ccf::http_status status,
          http::HeaderMap&& headers,
          std::vector<uint8_t>&& data) {
          return callback(status, std::move(headers), std::move(data));
        });
      client->send_request(std::move(req));
    }

    void write_snapshot(std::span<uint8_t> snapshot_buf, size_t request_id)
    {
      snapshotter->write_snapshot(snapshot_buf, request_id);
    }

    virtual std::shared_ptr<ccf::kv::Store> get_store() override
    {
      return network.tables;
    }

    virtual ringbuffer::AbstractWriterFactory& get_writer_factory() override
    {
      return writer_factory;
    }
  };
}
