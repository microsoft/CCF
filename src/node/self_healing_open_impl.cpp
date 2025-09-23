// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/self_healing_open_impl.h"

#include "ccf/service/tables/self_healing_open.h"
#include "node_state.h"

#include <stdexcept>

namespace ccf
{

  SelfHealingOpenSubSystem::SelfHealingOpenSubSystem(NodeState* node_state_) :
    node_state(node_state_)
  {}

  void SelfHealingOpenSubSystem::try_start(ccf::kv::Tx& tx, bool recovering)
  {
    // Clear any previous state
    tx.rw<SelfHealingOpenSMState>(Tables::SELF_HEALING_OPEN_SM_STATE)->clear();
    tx.rw<SelfHealingOpenTimeoutSMState>(
        Tables::SELF_HEALING_OPEN_TIMEOUT_SM_STATE)
      ->clear();
    tx.rw<SelfHealingOpenNodeInfoMap>(Tables::SELF_HEALING_OPEN_NODES)->clear();
    tx.rw<SelfHealingOpenGossips>(Tables::SELF_HEALING_OPEN_GOSSIPS)->clear();
    tx.rw<SelfHealingOpenChosenReplica>(
        Tables::SELF_HEALING_OPEN_CHOSEN_REPLICA)
      ->clear();
    tx.rw<SelfHealingOpenVotes>(Tables::SELF_HEALING_OPEN_VOTES)->clear();
    tx.rw<SelfHealingOpenFailoverFlag>(Tables::SELF_HEALING_OPEN_FAILOVER_FLAG)
      ->clear();

    auto& config = node_state->config.recover.self_healing_open;
    if (!recovering || !config.has_value())
    {
      LOG_INFO_FMT("Skipping self-healing-open");
      return;
    }

    LOG_INFO_FMT("Starting self-healing-open");

    tx.rw<SelfHealingOpenSMState>(Tables::SELF_HEALING_OPEN_SM_STATE)
      ->put(SelfHealingOpenSM::GOSSIPING);
    tx.rw<SelfHealingOpenTimeoutSMState>(
        Tables::SELF_HEALING_OPEN_TIMEOUT_SM_STATE)
      ->put(SelfHealingOpenSM::GOSSIPING);

    start_message_retry_timers();
    start_failover_timers();
  }

  void SelfHealingOpenSubSystem::advance(ccf::kv::Tx& tx, bool timeout)
  {
    auto& config = node_state->config.recover.self_healing_open;
    if (!config.has_value())
    {
      throw std::logic_error("Self-healing-open not configured");
    }

    auto* sm_state_handle =
      tx.rw<SelfHealingOpenSMState>(Tables::SELF_HEALING_OPEN_SM_STATE);
    auto* timeout_state_handle = tx.rw<SelfHealingOpenTimeoutSMState>(
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
      case SelfHealingOpenSM::GOSSIPING:
      {
        auto* gossip_handle =
          tx.ro<SelfHealingOpenGossips>(Tables::SELF_HEALING_OPEN_GOSSIPS);
        auto quorum_size = config->addresses.size();
        if (gossip_handle->size() >= quorum_size || valid_timeout)
        {
          if (gossip_handle->size() == 0)
          {
            throw std::logic_error("No gossip addresses provided yet");
          }

          // Lexographically maximum <txid, iid> pair
          std::optional<std::pair<ccf::kv::Version, std::string>> maximum;
          gossip_handle->foreach([&maximum](const auto& iid, const auto& txid) {
            if (
              !maximum.has_value() ||
              maximum.value() < std::make_pair(txid, iid))
            {
              maximum = std::make_pair(txid, iid);
            }
            return true;
          });

          if (!maximum.has_value())
          {
            throw std::logic_error("No valid gossip addresses provided");
          }
          tx.rw<SelfHealingOpenChosenReplica>(
              Tables::SELF_HEALING_OPEN_CHOSEN_REPLICA)
            ->put(maximum->second);

          sm_state_handle->put(SelfHealingOpenSM::VOTING);
        }
        break;
      }
      case SelfHealingOpenSM::VOTING:
      {
        auto* votes =
          tx.rw<SelfHealingOpenVotes>(Tables::SELF_HEALING_OPEN_VOTES);

        auto sufficient_quorum =
          votes->size() >= config->addresses.size() / 2 + 1;
        if (sufficient_quorum || valid_timeout)
        {
          if (valid_timeout && !sufficient_quorum)
          {
            tx.rw<SelfHealingOpenFailoverFlag>(
                Tables::SELF_HEALING_OPEN_FAILOVER_FLAG)
              ->put(true);
          }
          if (votes->size() == 0)
          {
            throw std::logic_error(
              "We didn't even vote for ourselves, so why should we open?");
          }
          LOG_INFO_FMT("Self-healing-open succeeded, now opening network");

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

          sm_state_handle->put(SelfHealingOpenSM::OPENING);

          node_state->transition_service_to_open(tx, identities);
        }
        break;
      }
      case SelfHealingOpenSM::JOINING:
      {
        auto chosen_replica = tx.ro<SelfHealingOpenChosenReplica>(
                                  Tables::SELF_HEALING_OPEN_CHOSEN_REPLICA)
                                ->get();
        if (!chosen_replica.has_value())
        {
          throw std::logic_error(
            "Self-healing-open chosen node not set, cannot join");
        }
        auto node_config =
          tx.ro<SelfHealingOpenNodeInfoMap>(Tables::SELF_HEALING_OPEN_NODES)
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

        RINGBUFFER_WRITE_MESSAGE(AdminMessage::restart, node_state->to_host);
      }
      case SelfHealingOpenSM::OPENING:
      {
        if (valid_timeout)
        {
          sm_state_handle->put(SelfHealingOpenSM::OPEN);
        }
        break;
      }
      case SelfHealingOpenSM::OPEN:
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
        case SelfHealingOpenSM::GOSSIPING:
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
  }

  void SelfHealingOpenSubSystem::start_message_retry_timers()
  {
    LOG_TRACE_FMT("Self-healing-open: Setting up retry timers");
    auto retry_timer_msg = std::make_unique<::threading::Tmsg<SHOMsg>>(
      [](std::unique_ptr<::threading::Tmsg<SHOMsg>> msg) {
        auto& config =
          msg->data.self.node_state->config.recover.self_healing_open;
        if (!config.has_value())
        {
          throw std::logic_error("Self-healing-open not configured");
        }
        auto& node_state_ = msg->data.self.node_state;
        std::lock_guard<pal::Mutex> guard(node_state_->lock);

        auto tx = node_state_->network.tables->create_read_only_tx();
        auto* sm_state_handle =
          tx.ro<SelfHealingOpenSMState>(Tables::SELF_HEALING_OPEN_SM_STATE);

        auto sm_state_opt = sm_state_handle->get();
        if (!sm_state_opt.has_value())
        {
          throw std::logic_error(
            "Self-healing-open state not set, cannot retry "
            "self-healing-open");
        }
        auto& sm_state = sm_state_opt.value();

        // Keep doing this until the node is no longer in recovery
        if (sm_state == SelfHealingOpenSM::OPEN)
        {
          LOG_INFO_FMT("Self-healing-open complete, stopping timers.");
          return;
        }

        switch (sm_state)
        {
          case SelfHealingOpenSM::GOSSIPING:
            msg->data.self.send_gossip_unsafe();
            break;
          case SelfHealingOpenSM::VOTING:
          {
            auto* node_info_handle = tx.ro<SelfHealingOpenNodeInfoMap>(
              Tables::SELF_HEALING_OPEN_NODES);
            auto* chosen_replica_handle = tx.ro<SelfHealingOpenChosenReplica>(
              Tables::SELF_HEALING_OPEN_CHOSEN_REPLICA);
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
            msg->data.self.send_vote_unsafe(chosen_node_info.value());
            // keep gossiping to allow lagging nodes to eventually vote
            msg->data.self.send_gossip_unsafe();
            break;
          }
          case SelfHealingOpenSM::OPENING:
            msg->data.self.send_iamopen_unsafe();
            break;
          case SelfHealingOpenSM::JOINING:
            return;
          default:
            throw std::logic_error(fmt::format(
              "Unknown self-healing-open state: {}",
              static_cast<int>(sm_state)));
        }

        auto delay = config->retry_timeout;
        ::threading::ThreadMessaging::instance().add_task_after(
          std::move(msg), delay);
      },
      *this);
    // kick this off asynchronously as this can be called from a curl callback
    ::threading::ThreadMessaging::instance().add_task(
      threading::get_current_thread_id(), std::move(retry_timer_msg));
  }

  void SelfHealingOpenSubSystem::start_failover_timers()
  {
    auto& config = node_state->config.recover.self_healing_open;
    if (!config.has_value())
    {
      throw std::logic_error("Self-healing-open not configured");
    }

    LOG_TRACE_FMT("Self-healing-open: Setting up failover timers");
    // Dispatch timeouts
    auto timeout_msg = std::make_unique<::threading::Tmsg<SHOMsg>>(
      [](std::unique_ptr<::threading::Tmsg<SHOMsg>> msg) {
        auto& config =
          msg->data.self.node_state->config.recover.self_healing_open;
        if (!config.has_value())
        {
          throw std::logic_error("Self-healing-open not configured");
        }
        auto* node_state_ = msg->data.self.node_state;
        std::lock_guard<pal::Mutex> guard(node_state_->lock);
        LOG_TRACE_FMT(
          "Self-healing-open timeout, sending timeout to internal handlers");

        // Stop the timer if the node has completed its self-healing-open
        auto tx = node_state_->network.tables->create_read_only_tx();
        auto* sm_state_handle =
          tx.ro<SelfHealingOpenSMState>(Tables::SELF_HEALING_OPEN_SM_STATE);
        if (!sm_state_handle->get().has_value())
        {
          throw std::logic_error(
            "Self-healing-open state not set, cannot retry "
            "self-healing-open");
        }
        auto sm_state = sm_state_handle->get().value();
        if (sm_state == SelfHealingOpenSM::OPEN)
        {
          LOG_INFO_FMT("Self-healing-open complete, stopping timers.");
          return;
        }

        // Send a timeout to the internal handlers
        curl::UniqueCURL curl_handle;

        auto cert = node_state_->self_signed_node_cert;
        curl_handle.set_opt(CURLOPT_SSL_VERIFYHOST, 0L);
        curl_handle.set_opt(CURLOPT_SSL_VERIFYPEER, 0L);
        curl_handle.set_opt(CURLOPT_SSL_VERIFYSTATUS, 0L);

        curl_handle.set_blob_opt(
          CURLOPT_SSLCERT_BLOB, cert.data(), cert.size());
        curl_handle.set_opt(CURLOPT_SSLCERTTYPE, "PEM");

        auto privkey_pem = node_state_->node_sign_kp->private_key_pem();
        curl_handle.set_blob_opt(
          CURLOPT_SSLKEY_BLOB, privkey_pem.data(), privkey_pem.size());
        curl_handle.set_opt(CURLOPT_SSLKEYTYPE, "PEM");

        auto url = fmt::format(
          "https://{}/{}/self_healing_open/timeout",
          node_state_->config.network.rpc_interfaces.at("primary_rpc_interface")
            .published_address,
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

        auto delay = config->failover_timeout;
        ::threading::ThreadMessaging::instance().add_task_after(
          std::move(msg), delay);
      },
      *this);
    ::threading::ThreadMessaging::instance().add_task_after(
      std::move(timeout_msg), config->failover_timeout);
  }

  void dispatch_authenticated_message(
    nlohmann::json& request,
    const std::string& target_address,
    const std::string& endpoint,
    const crypto::Pem& self_signed_node_cert,
    const crypto::Pem& privkey_pem)
  {
    curl::UniqueCURL curl_handle;

    // diable SSL verification as no private information is sent
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

    auto response_callback = [](
                               const ccf::curl::CurlRequest& request,
                               CURLcode curl_code,
                               long status_code) {
      LOG_TRACE_FMT(
        "Response received for {} to {}: curl_result {} ({}), status code {}",
        request.get_method().c_str(),
        request.get_url(),
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

  self_healing_open::RequestNodeInfo SelfHealingOpenSubSystem::make_node_info()
  {
    return {
      .quote_info = node_state->quote_info,
      .published_network_address =
        node_state->config.network.rpc_interfaces.at("primary_rpc_interface")
          .published_address,
      .intrinsic_id =
        node_state->config.network.rpc_interfaces.at("primary_rpc_interface")
          .published_address,
      .service_identity = node_state->network.identity->cert.str(),
    };
  }

  void SelfHealingOpenSubSystem::send_gossip_unsafe()
  {
    auto& config = node_state->config.recover.self_healing_open;
    if (!config.has_value())
    {
      throw std::logic_error("Self-healing-open not configured");
    }

    LOG_TRACE_FMT("Broadcasting self-healing-open gossip");

    self_healing_open::GossipRequest request{
      .info = make_node_info(),
      .txid = node_state->last_recovered_signed_idx,
    };
    nlohmann::json request_json = request;

    for (auto& target_address : config->addresses)
    {
      dispatch_authenticated_message(
        request_json,
        target_address,
        "gossip",
        node_state->self_signed_node_cert,
        node_state->node_sign_kp->private_key_pem());
    }
  }

  void SelfHealingOpenSubSystem::send_vote_unsafe(
    const SelfHealingOpenNodeInfo& node_info)
  {
    auto& config = node_state->config.recover.self_healing_open;
    if (!config.has_value())
    {
      throw std::logic_error("Self-healing-open not configured");
    }

    LOG_TRACE_FMT(
      "Sending self-healing-open vote to {} at {}",
      node_info.intrinsic_id,
      node_info.published_network_address);

    self_healing_open::VoteRequest request{.info = make_node_info()};

    nlohmann::json request_json = request;

    dispatch_authenticated_message(
      request_json,
      node_info.published_network_address,
      "vote",
      node_state->self_signed_node_cert,
      node_state->node_sign_kp->private_key_pem());
  }

  void SelfHealingOpenSubSystem::send_iamopen_unsafe()
  {
    auto& config = node_state->config.recover.self_healing_open;
    if (!config.has_value())
    {
      throw std::logic_error("Self-healing-open not configured");
    }

    LOG_TRACE_FMT("Sending self-healing-open iamopen");

    self_healing_open::IAmOpenRequest request{.info = make_node_info()};
    nlohmann::json request_json = request;

    for (auto& target_address : config->addresses)
    {
      if (
        target_address ==
        node_state->config.network.rpc_interfaces.at("primary_rpc_interface")
          .published_address)
      {
        // Don't send to self
        continue;
      }
      dispatch_authenticated_message(
        request_json,
        target_address,
        "iamopen",
        node_state->self_signed_node_cert,
        node_state->node_sign_kp->private_key_pem());
    }
  }

}