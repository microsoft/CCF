// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/self_healing_open_impl.h"

#include "ccf/crypto/verifier.h"
#include "ccf/pal/locking.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/self_healing_open.h"
#include "ccf/tx.h"
#include "ccf/tx_id.h"
#include "http/curl.h"
#include "node_state.h"
#include "tasks/basic_task.h"
#include "tasks/task_system.h"

#include <stdexcept>
#include <tuple>

namespace ccf
{

  SelfHealingOpenSubsystem::SelfHealingOpenSubsystem(NodeState* node_state_) :
    node_state(node_state_)
  {}

  void SelfHealingOpenSubsystem::reset_state(ccf::kv::Tx& tx)
  {
    // Clear any previous state
    tx.rw<self_healing_open::SMState>(Tables::SELF_HEALING_OPEN_SM_STATE)
      ->clear();
    tx.rw<self_healing_open::TimeoutSMState>(
        Tables::SELF_HEALING_OPEN_TIMEOUT_SM_STATE)
      ->clear();
    tx.rw<self_healing_open::NodeInfoMap>(Tables::SELF_HEALING_OPEN_NODES)
      ->clear();
    tx.rw<self_healing_open::Gossips>(Tables::SELF_HEALING_OPEN_GOSSIPS)
      ->clear();
    tx.rw<self_healing_open::ChosenNode>(Tables::SELF_HEALING_OPEN_CHOSEN_NODE)
      ->clear();
    tx.rw<self_healing_open::Votes>(Tables::SELF_HEALING_OPEN_VOTES)->clear();
    tx.rw<self_healing_open::OpenKind>(Tables::SELF_HEALING_OPEN_OPEN_KIND)
      ->clear();
  }

  void SelfHealingOpenSubsystem::try_start(ccf::kv::Tx& tx, bool recovering)
  {
    auto& config = node_state->config.recover.self_healing_open;
    if (!recovering || !config.has_value())
    {
      LOG_INFO_FMT("Skipping self-healing-open");
      return;
    }

    LOG_INFO_FMT("Starting self-healing-open");

    tx.rw<self_healing_open::SMState>(Tables::SELF_HEALING_OPEN_SM_STATE)
      ->put(self_healing_open::StateMachine::GOSSIPING);
    tx.rw<self_healing_open::TimeoutSMState>(
        Tables::SELF_HEALING_OPEN_TIMEOUT_SM_STATE)
      ->put(self_healing_open::StateMachine::GOSSIPING);

    // Delay start of message retry and failover timers until after commit
    node_state->network.tables->set_global_hook(
      Tables::SELF_HEALING_OPEN_SM_STATE,
      self_healing_open::SMState::wrap_commit_hook(
        [this](
          ccf::kv::Version /*hook_version*/,
          const self_healing_open::SMState::Write& w) {
          if (
            w.has_value() &&
            w.value() == self_healing_open::StateMachine::GOSSIPING)
          {
            start_message_retry_timers();
            start_failover_timers();
          }
        }));
  }

  void SelfHealingOpenSubsystem::advance(ccf::kv::Tx& tx, bool timeout)
  {
    auto& config = get_config();

    auto* sm_state_handle =
      tx.rw<self_healing_open::SMState>(Tables::SELF_HEALING_OPEN_SM_STATE);
    auto* timeout_state_handle = tx.rw<self_healing_open::TimeoutSMState>(
      Tables::SELF_HEALING_OPEN_TIMEOUT_SM_STATE);

    auto sm_state_opt = sm_state_handle->get();
    auto timeout_state_opt = timeout_state_handle->get();
    if ((!sm_state_opt.has_value()) || (!timeout_state_opt.has_value()))
    {
      throw std::logic_error(
        "Self-healing-open state not set, cannot advance self-healing-open");
    }
    auto& sm_state = sm_state_opt.value();
    auto& timeout_state = timeout_state_opt.value();

    bool valid_timeout = timeout && sm_state == timeout_state;

    // Advance self-healing-open SM
    switch (sm_state)
    {
      case self_healing_open::StateMachine::GOSSIPING:
      {
        auto* gossip_handle =
          tx.ro<self_healing_open::Gossips>(Tables::SELF_HEALING_OPEN_GOSSIPS);
        auto quorum_size = config.cluster_identities.size();
        if (gossip_handle->size() >= quorum_size || valid_timeout)
        {
          if (gossip_handle->size() == 0)
          {
            throw std::logic_error("No gossip addresses provided yet");
          }

          // Find the lexographical maximum by <view, seqno, intrinsic_id>
          std::optional<std::tuple<ccf::View, ccf::SeqNo, std::string>> maximum;
          gossip_handle->foreach([&maximum](const auto& iid, const auto& txid) {
            if (
              !maximum.has_value() ||
              maximum.value() < std::make_tuple(txid.view, txid.seqno, iid))
            {
              maximum = std::make_tuple(txid.view, txid.seqno, iid);
            }
            return true;
          });

          if (!maximum.has_value())
          {
            throw std::logic_error("No valid gossip addresses provided");
          }
          tx.rw<self_healing_open::ChosenNode>(
              Tables::SELF_HEALING_OPEN_CHOSEN_NODE)
            ->put(std::get<2>(maximum.value()));

          sm_state_handle->put(self_healing_open::StateMachine::VOTING);
        }
        break;
      }
      case self_healing_open::StateMachine::VOTING:
      {
        auto* votes =
          tx.rw<self_healing_open::Votes>(Tables::SELF_HEALING_OPEN_VOTES);

        auto sufficient_quorum =
          votes->size() >= config.cluster_identities.size() / 2 + 1;
        if (sufficient_quorum || valid_timeout)
        {
          if (valid_timeout && votes->size() == 0)
          {
            // If we have voted for another node, that node is better placed
            // than ourselves to begin operating
            // So we do not attempt to open the service ourselves
            LOG_FAIL_FMT(
              "Self-healing-open timeout without any votes for ourselves, "
              "skipping opening network");
            return;
          }

          auto timeout_used = valid_timeout && !sufficient_quorum;
          if (timeout_used)
          {
            tx.rw<self_healing_open::OpenKind>(
                Tables::SELF_HEALING_OPEN_OPEN_KIND)
              ->put(self_healing_open::OpenKinds::FAILOVER);
            LOG_INFO_FMT("Self-healing-open succeeded on the failover path");
          }
          else
          {
            tx.rw<self_healing_open::OpenKind>(
                Tables::SELF_HEALING_OPEN_OPEN_KIND)
              ->put(self_healing_open::OpenKinds::QUORUM);
            LOG_INFO_FMT("Self-healing-open succeeded on the quorum path");
          }

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

          sm_state_handle->put(self_healing_open::StateMachine::OPENING);

          node_state->transition_service_to_open(tx, identities);
        }
        break;
      }
      case self_healing_open::StateMachine::JOINING:
      {
        auto chosen_replica = tx.ro<self_healing_open::ChosenNode>(
                                  Tables::SELF_HEALING_OPEN_CHOSEN_NODE)
                                ->get();
        if (!chosen_replica.has_value())
        {
          throw std::logic_error(
            "Self-healing-open chosen node not set, cannot join");
        }
        auto node_config =
          tx.ro<self_healing_open::NodeInfoMap>(Tables::SELF_HEALING_OPEN_NODES)
            ->get(chosen_replica.value());
        if (!node_config.has_value())
        {
          throw std::logic_error(fmt::format(
            "Self-healing-open chosen node {} not found",
            chosen_replica.value()));
        }

        LOG_INFO_FMT(
          "Self-healing-open joining {} at {} with fingerprint {}",
          node_config->identity.intrinsic_id,
          node_config->identity.published_address,
          self_healing_open::service_fingerprint_from_pem(
            ccf::crypto::cert_der_to_pem(node_config->service_cert_der)));
        auto service_cert =
          ccf::crypto::cert_der_to_pem(node_config->service_cert_der);
        LOG_INFO_FMT("{}", service_cert.str());

        RINGBUFFER_WRITE_MESSAGE(AdminMessage::restart, node_state->to_host);
      }
      case self_healing_open::StateMachine::OPENING:
      {
        if (valid_timeout)
        {
          sm_state_handle->put(self_healing_open::StateMachine::OPEN);
        }
        break;
      }
      case self_healing_open::StateMachine::OPEN:
      {
        // Nothing to do here, we are already opening or open or joining
        break;
      }
      default:
        throw std::logic_error(fmt::format(
          "Unknown self-healing-open state: {}", static_cast<int>(sm_state)));
    }

    // Advance timeout SM
    if (timeout)
    {
      switch (timeout_state)
      {
        case self_healing_open::StateMachine::GOSSIPING:
          LOG_TRACE_FMT("Advancing timeout SM to VOTING");
          timeout_state_handle->put(self_healing_open::StateMachine::VOTING);
          break;
        case self_healing_open::StateMachine::VOTING:
          LOG_TRACE_FMT("Advancing timeout SM to OPENING");
          timeout_state_handle->put(self_healing_open::StateMachine::OPENING);
          break;
        case self_healing_open::StateMachine::OPENING:
        case self_healing_open::StateMachine::JOINING:
        case self_healing_open::StateMachine::OPEN:
        default:
          LOG_TRACE_FMT("Timeout SM complete");
      }
    }
  }

  void SelfHealingOpenSubsystem::start_message_retry_timers()
  {
    LOG_TRACE_FMT("Self-healing-open: Setting up retry timers");

    auto& config = get_config();

    retry_task = ccf::tasks::make_basic_task(
      [this]() {
        auto& config = node_state->config.recover.self_healing_open;
        if (!config.has_value())
        {
          throw std::logic_error("Self-healing-open not configured");
        }

        auto tx = node_state->network.tables->create_read_only_tx();
        auto* sm_state_handle =
          tx.ro<self_healing_open::SMState>(Tables::SELF_HEALING_OPEN_SM_STATE);

        auto sm_state_opt = sm_state_handle->get();
        if (!sm_state_opt.has_value())
        {
          throw std::logic_error(
            "Self-healing-open state not set, cannot retry self-healing-open");
        }
        auto& sm_state = sm_state_opt.value();

        // Stop if self-healing-open is complete
        if (sm_state == self_healing_open::StateMachine::OPEN)
        {
          LOG_INFO_FMT("Self-healing-open complete, stopping retry timers.");
          stop_timers();
          return;
        }

        switch (sm_state)
        {
          case self_healing_open::StateMachine::GOSSIPING:
            send_gossip_unsafe(tx);
            break;
          case self_healing_open::StateMachine::VOTING:
          {
            auto* node_info_handle = tx.ro<self_healing_open::NodeInfoMap>(
              Tables::SELF_HEALING_OPEN_NODES);
            auto* chosen_replica_handle = tx.ro<self_healing_open::ChosenNode>(
              Tables::SELF_HEALING_OPEN_CHOSEN_NODE);
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
            send_vote_unsafe(tx, chosen_node_info.value());
            // keep gossiping to allow lagging nodes to eventually vote
            send_gossip_unsafe(tx);
            break;
          }
          case self_healing_open::StateMachine::OPENING:
            send_iamopen_unsafe(tx);
            break;
          case self_healing_open::StateMachine::JOINING:
            stop_timers();
            return;
          default:
            throw std::logic_error(fmt::format(
              "Unknown self-healing-open state: {}",
              static_cast<int>(sm_state)));
        }
      },
      "SelfHealingOpenRetry");

    ccf::tasks::add_periodic_task(
      retry_task,
      std::chrono::milliseconds(0),
      std::chrono::milliseconds(config.retry_timeout));
  }

  void SelfHealingOpenSubsystem::start_failover_timers()
  {
    auto& config = get_config();

    LOG_TRACE_FMT("Self-healing-open: Setting up failover timers");

    failover_task = ccf::tasks::make_basic_task(
      [this]() {
        auto& config = get_config();

        LOG_TRACE_FMT(
          "Self-healing-open timeout, sending timeout to internal handlers");

        // Stop the timer if the node has completed its self-healing-open
        auto tx = node_state->network.tables->create_read_only_tx();
        auto* sm_state_handle =
          tx.ro<self_healing_open::SMState>(Tables::SELF_HEALING_OPEN_SM_STATE);
        if (!sm_state_handle->get().has_value())
        {
          throw std::logic_error(
            "Self-healing-open state not set, cannot retry self-healing-open");
        }
        auto sm_state = sm_state_handle->get().value();
        if (sm_state == self_healing_open::StateMachine::OPEN)
        {
          LOG_INFO_FMT("Self-healing-open complete, stopping failover timers.");
          stop_timers();
          return;
        }

        // Send a timeout to the internal handlers
        curl::UniqueCURL curl_handle;

        crypto::Pem cert;
        crypto::Pem privkey_pem;
        {
          std::lock_guard<pal::Mutex> guard(node_state->lock);
          cert = node_state->self_signed_node_cert;
          privkey_pem = node_state->node_sign_kp->private_key_pem();
        }

        curl_handle.set_opt(CURLOPT_SSL_VERIFYHOST, 0L);
        curl_handle.set_opt(CURLOPT_SSL_VERIFYPEER, 0L);
        curl_handle.set_opt(CURLOPT_SSL_VERIFYSTATUS, 0L);

        curl_handle.set_blob_opt(
          CURLOPT_SSLCERT_BLOB, cert.data(), cert.size());
        curl_handle.set_opt(CURLOPT_SSLCERTTYPE, "PEM");

        curl_handle.set_blob_opt(
          CURLOPT_SSLKEY_BLOB, privkey_pem.data(), privkey_pem.size());
        curl_handle.set_opt(CURLOPT_SSLKEYTYPE, "PEM");

        auto url = fmt::format(
          "https://{}/{}/self_healing_open/timeout",
          config.identity.published_address,
          get_actor_prefix(ActorsType::nodes));

        curl::UniqueSlist headers;
        headers.append("Content-Type: application/json");

        auto curl_request = std::make_unique<curl::CurlRequest>(
          std::move(curl_handle),
          HTTP_PUT,
          std::move(url),
          std::move(headers),
          nullptr,
          nullptr,
          std::nullopt);
        curl::CurlmLibuvContextSingleton::get_instance()->attach_request(
          std::move(curl_request));
      },
      "SelfHealingOpenFailover");

    ccf::tasks::add_periodic_task(
      failover_task,
      std::chrono::milliseconds(config.failover_timeout),
      std::chrono::milliseconds(config.failover_timeout));
  }

  void SelfHealingOpenSubsystem::stop_timers()
  {
    if (retry_task)
    {
      retry_task->cancel_task();
      retry_task = nullptr;
    }
    if (failover_task)
    {
      failover_task->cancel_task();
      failover_task = nullptr;
    }
  }

  void dispatch_authenticated_message(
    nlohmann::json& request,
    const std::string& target_address,
    const std::string& endpoint,
    const crypto::Pem& self_signed_node_cert,
    const crypto::Pem& privkey_pem)
  {
    curl::UniqueCURL curl_handle;

    // disable SSL verification as no confidential information is sent
    curl_handle.set_opt(CURLOPT_SSL_VERIFYHOST, 0L);
    curl_handle.set_opt(CURLOPT_SSL_VERIFYPEER, 0L);
    curl_handle.set_opt(CURLOPT_SSL_VERIFYSTATUS, 0L);

    curl_handle.set_blob_opt(
      CURLOPT_SSLCERT_BLOB,
      self_signed_node_cert.data(),
      self_signed_node_cert.size());
    curl_handle.set_opt(CURLOPT_SSLCERTTYPE, "PEM");

    curl_handle.set_blob_opt(
      CURLOPT_SSLKEY_BLOB, privkey_pem.data(), privkey_pem.size());
    curl_handle.set_opt(CURLOPT_SSLKEYTYPE, "PEM");

    auto url = fmt::format(
      "https://{}/{}/self_healing_open/{}",
      target_address,
      get_actor_prefix(ActorsType::nodes),
      endpoint);

    curl::UniqueSlist headers;
    headers.append("Content-Type", "application/json");

    auto body = std::make_unique<curl::RequestBody>(request);

    auto response_callback =
      [](
        std::unique_ptr<ccf::curl::CurlRequest>&& request,
        CURLcode curl_code,
        long status_code) {
        LOG_TRACE_FMT(
          "Response received for {} to {}: curl_result {} ({}), status code {}",
          request->get_method().c_str(),
          request->get_url(),
          curl_easy_strerror(curl_code),
          curl_code,
          status_code);
      };

    auto curl_request = std::make_unique<curl::CurlRequest>(
      std::move(curl_handle),
      HTTP_PUT,
      std::move(url),
      std::move(headers),
      std::move(body),
      nullptr,
      std::move(response_callback));

    LOG_TRACE_FMT(
      "Dispatching attested {} message to {}",
      curl_request->get_method().c_str(),
      curl_request->get_url());

    curl::CurlmLibuvContextSingleton::get_instance()->attach_request(
      std::move(curl_request));
  }

  self_healing_open::RequestNodeInfo& SelfHealingOpenSubsystem::get_node_info(
    kv::ReadOnlyTx& tx)
  {
    std::lock_guard<pal::Mutex> guard(self_healing_open_lock);

    if (node_info_cache.has_value())
    {
      return node_info_cache.value();
    }

    auto* nodes_handle = tx.ro<Nodes>(Tables::NODES);
    auto node_info_opt = nodes_handle->get(node_state->get_node_id());
    if (!node_info_opt.has_value())
    {
      throw std::logic_error(fmt::format(
        "Node {} not found in nodes table", node_state->get_node_id()));
    }
    auto& config = get_config();
    {
      std::lock_guard<pal::Mutex> ns_guard(node_state->lock);
      node_info_cache = self_healing_open::RequestNodeInfo{
        .quote_info = node_info_opt->quote_info,
        .identity = config.identity,
        .service_cert_der =
          ccf::crypto::cert_pem_to_der(node_state->network.identity->cert),
      };
    }
    return node_info_cache.value();
  }

  void SelfHealingOpenSubsystem::send_gossip_unsafe(kv::ReadOnlyTx& tx)
  {
    auto& config = get_config();

    LOG_TRACE_FMT("Broadcasting self-healing-open gossip");

    self_healing_open::GossipRequest request;
    request.info = get_node_info(tx);
    request.txid = get_last_recovered_signed_txid();
    nlohmann::json request_json = request;

    for (auto& target : config.cluster_identities)
    {
      auto target_address = target.published_address;
      dispatch_authenticated_message(
        request_json,
        target_address,
        "gossip",
        node_state->self_signed_node_cert,
        node_state->node_sign_kp->private_key_pem());
    }
  }

  void SelfHealingOpenSubsystem::send_vote_unsafe(
    kv::ReadOnlyTx& tx, const self_healing_open::NodeInfo& node_info)
  {
    LOG_TRACE_FMT(
      "Sending self-healing-open vote to {} at {}",
      node_info.identity.intrinsic_id,
      node_info.identity.published_address);

    self_healing_open::TaggedWithNodeInfo request{.info = get_node_info(tx)};

    nlohmann::json request_json = request;

    dispatch_authenticated_message(
      request_json,
      node_info.identity.published_address,
      "vote",
      node_state->self_signed_node_cert,
      node_state->node_sign_kp->private_key_pem());
  }

  self_healing_open::IAmOpenRequest& SelfHealingOpenSubsystem::
    get_iamopen_request(kv::ReadOnlyTx& tx)
  {
    {
      std::lock_guard<pal::Mutex> guard(self_healing_open_lock);
      if (iamopen_request_cache.has_value())
      {
        return iamopen_request_cache.value();
      }
    }

    auto previous_service_cert =
      tx.ro(node_state->network.previous_service_identity)->get();
    if (!previous_service_cert.has_value())
    {
      throw std::logic_error(
        "Previous service identity not found in table but expected as "
        "recovering");
    }
    auto previous_service_identity_fingerprint =
      self_healing_open::service_fingerprint_from_pem(
        previous_service_cert.value());

    auto& node_info = get_node_info(tx);

    {
      std::lock_guard<pal::Mutex> guard(self_healing_open_lock);
      iamopen_request_cache = self_healing_open::IAmOpenRequest{};
      iamopen_request_cache->info = node_info;
      iamopen_request_cache->prev_service_fingerprint =
        previous_service_identity_fingerprint;
      iamopen_request_cache->txid = get_last_recovered_signed_txid();
    }

    return iamopen_request_cache.value();
  }

  void SelfHealingOpenSubsystem::send_iamopen_unsafe(ccf::kv::ReadOnlyTx& tx)
  {
    auto config = get_config();

    LOG_TRACE_FMT("Sending self-healing-open iamopen");

    nlohmann::json request_json = get_iamopen_request(tx);

    for (auto& target : config.cluster_identities)
    {
      if (target.intrinsic_id == config.identity.intrinsic_id)
      {
        // Don't send to self
        continue;
      }
      dispatch_authenticated_message(
        request_json,
        target.published_address,
        "iamopen",
        node_state->self_signed_node_cert,
        node_state->node_sign_kp->private_key_pem());
    }
  }

  SelfHealingOpenConfig& SelfHealingOpenSubsystem::get_config()
  {
    auto& config = node_state->config.recover.self_healing_open;
    if (!config.has_value())
    {
      throw std::logic_error("Self-healing-open not configured");
    }
    return config.value();
  }

  ccf::TxID SelfHealingOpenSubsystem::get_last_recovered_signed_txid()
  {
    auto recovery_seqno = node_state->last_recovered_signed_idx;
    auto recovery_view = node_state->consensus->get_view(recovery_seqno);
    // get_view returns VIEW_UNKNOWN=InvalidView if the view is not in the view
    // history (too old or too new)
    if (recovery_view == ccf::VIEW_UNKNOWN)
    {
      throw std::logic_error(fmt::format(
        "Could not find view for last recovered signed seqno {}",
        recovery_seqno));
    }
    return ccf::TxID{recovery_view, recovery_seqno};
  }
}