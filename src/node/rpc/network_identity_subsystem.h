// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_verifier.h"
#include "ccf/network_identity_interface.h"
#include "ccf/node/startup_config.h"
#include "crypto/cose.h"
#include "ds/internal_logger.h"
#include "node/identity.h"
#include "node/rpc/network_identity_accessors.h"
#include "node/rpc/network_identity_chain_helpers.h"

#include <atomic>
#include <chrono>

namespace ccf
{
  inline std::string format_epoch(const std::optional<ccf::TxID>& epoch_end)
  {
    return epoch_end.has_value() ? epoch_end->to_str() : "null";
  }

  inline void validate_fetched_endorsement(
    const ccf::CoseEndorsement& endorsement)
  {
    LOG_INFO_FMT(
      "Validating fetched endorsement from {} to {}",
      endorsement.endorsement_epoch_begin.to_str(),
      format_epoch(endorsement.endorsement_epoch_end));

    if (!is_self_endorsement(endorsement))
    {
      const auto [from, to] =
        ccf::crypto::extract_cose_endorsement_validity(endorsement.endorsement);

      const auto from_txid = ccf::TxID::from_str(from);
      if (!from_txid.has_value())
      {
        throw std::logic_error(fmt::format(
          "Cannot parse COSE endorsement header: {}",
          ccf::cose::header::custom::TX_RANGE_BEGIN));
      }

      const auto to_txid = ccf::TxID::from_str(to);
      if (!to_txid.has_value())
      {
        throw std::logic_error(fmt::format(
          "Cannot parse COSE endorsement header: {}",
          ccf::cose::header::custom::TX_RANGE_END));
      }

      if (!endorsement.endorsement_epoch_end.has_value())
      {
        throw std::logic_error(
          "COSE endorsement does not contain epoch end in the table entry");
      }
      if (
        endorsement.endorsement_epoch_begin != *from_txid ||
        *endorsement.endorsement_epoch_end != *to_txid)
      {
        throw std::logic_error(fmt::format(
          "COSE endorsement fetched but range is invalid, epoch begin {}, "
          "epoch end {}, header epoch begin: {}, header epoch end: {}",
          endorsement.endorsement_epoch_begin.to_str(),
          endorsement.endorsement_epoch_end->to_str(),
          from,
          to));
      }
    }
  }

  class NetworkIdentitySubsystem : public NetworkIdentitySubsystemInterface
  {
  protected:
    std::shared_ptr<INodeStateAccessor> node_state_accessor;
    std::shared_ptr<IHistoricalStateAccessor> historical_state_accessor;
    const std::unique_ptr<NetworkIdentity>& network_identity;
    std::shared_ptr<TaskScheduler> scheduler;

    // Retry budget. Set once by start_with_config(); thereafter only
    // read by the scheduler thread. Happens-before from the writing
    // thread is established by the task scheduler when fetch_first()
    // is submitted.
    size_t max_attempts{CCFConfig::IdentityHistoryFetch{}.max_attempts};
    int64_t retry_interval_ms{static_cast<int64_t>(
      CCFConfig::IdentityHistoryFetch{}.retry_interval.count_ms())};
    // Single-shot guard: start_with_config() must be called exactly
    // once over the lifetime of the subsystem.
    bool started{false};

    std::map<SeqNo, CoseEndorsement> endorsements;
    std::map<SeqNo, ccf::crypto::ECPublicKeyPtr> trusted_keys;
    std::optional<TxID> current_service_from;
    SeqNo earliest_endorsed_seq{0};
    // Atomic: written by the scheduler thread when fetching settles,
    // read by RPC threads on every reader call.
    std::atomic<FetchStatus> fetch_status{FetchStatus::Retry};
    bool has_predecessors{false};
    size_t fetch_attempts{0};

  public:
    NetworkIdentitySubsystem(
      std::shared_ptr<INodeStateAccessor> node_state_accessor_,
      std::shared_ptr<IHistoricalStateAccessor> historical_state_accessor_,
      const std::unique_ptr<NetworkIdentity>& network_identity_,
      std::shared_ptr<TaskScheduler> scheduler_) :
      node_state_accessor(std::move(node_state_accessor_)),
      historical_state_accessor(std::move(historical_state_accessor_)),
      network_identity(network_identity_),
      scheduler(std::move(scheduler_))
    {
      // Note: bootstrap does not start until start_with_config() is
      // called. Until then the subsystem stays in Retry and readers
      // throw IdentityHistoryNotFetched.
    }

    // Apply the retry-budget configuration and kick off the initial
    // bootstrap. Must be called exactly once over the subsystem's
    // lifetime; subsequent calls throw std::logic_error. The default
    // argument uses the default-constructed config.
    void start_with_config(const CCFConfig::IdentityHistoryFetch& config = {})
    {
      if (started)
      {
        throw std::logic_error(
          "NetworkIdentitySubsystem::start_with_config called more than "
          "once");
      }
      started = true;
      max_attempts = config.max_attempts;
      retry_interval_ms =
        static_cast<int64_t>(config.retry_interval.count_ms());
      fetch_first();
    }

    [[nodiscard]] FetchStatus endorsements_fetching_status() const override
    {
      return fetch_status.load();
    }

    const std::unique_ptr<NetworkIdentity>& get() override
    {
      return network_identity;
    }

    [[nodiscard]] std::optional<CoseEndorsementsChain>
    get_cose_endorsements_chain(ccf::SeqNo seqno) const override
    {
      const auto status = fetch_status.load();
      if (status != FetchStatus::Done && status != FetchStatus::Partial)
      {
        throw IdentityHistoryNotFetched(fmt::format(
          "COSE endorsements chain requested for seqno {} but identity "
          "history fetching has not been completed yet",
          seqno));
      }

      if (!current_service_from.has_value())
      {
        LOG_FAIL_FMT(
          "Unset current_service_from when fetching endorsements chain");
        return std::nullopt;
      }

      // In Partial we cannot tell whether seqnos below the validated
      // suffix were ever endorsed; signal absence via nullopt.
      if (
        status == FetchStatus::Partial && seqno < current_service_from->seqno &&
        seqno < earliest_endorsed_seq)
      {
        return std::nullopt;
      }

      if (!has_predecessors || seqno >= current_service_from->seqno)
      {
        return CoseEndorsementsChain{};
      }

      auto it = endorsements.upper_bound(seqno);
      if (it == endorsements.begin())
      {
        LOG_INFO_FMT(
          "No endorsements found for seqno {}, earliest endorsed is {}",
          seqno,
          earliest_endorsed_seq);
        return CoseEndorsementsChain{};
      }

      CoseEndorsementsChain result;
      for (--it; it != endorsements.end(); ++it)
      {
        result.push_back(it->second.endorsement);
      }
      std::reverse(result.begin(), result.end());
      return result;
    }

    [[nodiscard]] ccf::crypto::ECPublicKeyPtr get_trusted_identity_for(
      ccf::SeqNo seqno) const override
    {
      const auto status = fetch_status.load();
      if (status != FetchStatus::Done && status != FetchStatus::Partial)
      {
        throw IdentityHistoryNotFetched(fmt::format(
          "Trusted key requested for seqno {} but identity history "
          "fetching has not been completed yet",
          seqno));
      }
      if (trusted_keys.empty())
      {
        throw std::logic_error(fmt::format(
          "No trusted keys fetched when requested one for seqno {}", seqno));
      }
      auto it = trusted_keys.upper_bound(seqno);
      if (it == trusted_keys.begin())
      {
        // The earliest known trusted seqno is greater than the requested one.
        return nullptr;
      }
      const auto& [key_seqno, key_ptr] = *(--it);
      if (key_seqno > seqno)
      {
        throw std::logic_error(fmt::format(
          "Resolved trusted key for {} with wrong starting seqno {}",
          seqno,
          key_seqno));
      }
      return key_ptr;
    }

    [[nodiscard]] TrustedKeys get_trusted_keys() const override
    {
      const auto status = fetch_status.load();
      if (status != FetchStatus::Done && status != FetchStatus::Partial)
      {
        throw IdentityHistoryNotFetched(
          "Trusted keys requested but identity history fetching has not "
          "completed yet");
      }
      return trusted_keys;
    }

  protected:
    // Returns true if a retry was scheduled. Returns false if the
    // budget is exhausted.
    [[nodiscard]] bool schedule_retry(std::function<void()> fn)
    {
      ++fetch_attempts;
      if (fetch_attempts >= max_attempts)
      {
        return false;
      }
      scheduler->add_delayed_task(
        std::move(fn), std::chrono::milliseconds(retry_interval_ms));
      return true;
    }

    [[noreturn]] void fail_fetching(const std::string& err = "")
    {
      if (!err.empty())
      {
        LOG_FAIL_FMT("Failed fetching network identity: {}", err);
      }
      fetch_status.store(FetchStatus::Failed);

      // The caller may want to re-capture this, but by default it is
      // supposed to fail the node startup early. The endorsement chain
      // is essential for the node to produce receipts for past epochs,
      // which is a must-have functionality.
      throw std::runtime_error("Failed fetching network identity: " + err);
    }

    void complete_fetching(FetchStatus target_status)
    {
      if (!current_service_from.has_value())
      {
        // Invariant: every complete_fetching call site is downstream of
        // current_service_from being set. Reaching this branch means a
        // caller violated that contract.
        fail_fetching("Unset current_service_from when completing fetching");
      }

      try
      {
        if (!endorsements.empty())
        {
          auto next = endorsements.begin();
          auto prev = next++;
          while (next != endorsements.end())
          {
            verify_endorsements_connected(next->second, prev->second);
            ++prev;
            ++next;
          }
          validate_chain_front_connection(prev->second, *current_service_from);
        }
        build_trusted_key_chain();
      }
      catch (const std::exception& e)
      {
        fail_fetching(e.what());
      }

      log_status(target_status);
      fetch_status.store(target_status);
    }

    static void log_status(FetchStatus status)
    {
      LOG_INFO_FMT(
        "Network identity fetching settled at {}", ccf::to_string(status));
    }

    void fetch_first()
    {
      // Pre-bootstrap waits are unbounded: KV reads can legitimately
      // block for arbitrary durations (e.g. waiting for service open
      // during recovery). The budget only applies to historical reads
      // in fetch_next_at.
      if (!node_state_accessor->is_part_of_network())
      {
        LOG_INFO_FMT(
          "Retry fetching network identity as node is not part of the network "
          "yet");
        scheduler->add_delayed_task(
          [this]() { this->fetch_first(); },
          std::chrono::milliseconds(retry_interval_ms));
        return;
      }

      if (!current_service_from.has_value())
      {
        auto cs = node_state_accessor->get_current_service_txid();
        if (!cs.has_value())
        {
          LOG_INFO_FMT(
            "Retrying fetching network identity as current service create "
            "txid is not yet available or service is not yet open");
          scheduler->add_delayed_task(
            [this]() { this->fetch_first(); },
            std::chrono::milliseconds(retry_interval_ms));
          return;
        }
        current_service_from = cs;
      }

      auto endorsement = node_state_accessor->get_current_endorsement();
      if (!endorsement.has_value())
      {
        LOG_INFO_FMT(
          "Retrying fetching network identity as there is no previous "
          "service identity endorsement yet");
        scheduler->add_delayed_task(
          [this]() { this->fetch_first(); },
          std::chrono::milliseconds(retry_interval_ms));
        return;
      }

      if (is_self_endorsement(endorsement.value()))
      {
        if (
          current_service_from->seqno !=
          endorsement->endorsement_epoch_begin.seqno)
        {
          fail_fetching(fmt::format(
            "The first fetched endorsement is a self-endorsement at {} "
            "which is different from current_service_create_txid {}",
            endorsement->endorsement_epoch_begin.to_str(),
            current_service_from->to_str()));
        }

        LOG_INFO_FMT(
          "The very first service endorsement is self-signed at {}, no "
          "endorsement chain will be preloaded",
          current_service_from->seqno);

        has_predecessors = false;
        complete_fetching(FetchStatus::Done);
        return;
      }

      has_predecessors = true;
      earliest_endorsed_seq = current_service_from->seqno;
      process_endorsement(endorsement.value());
    }

    void process_endorsement(const ccf::CoseEndorsement& endorsement)
    {
      if (has_ill_formed_epoch_range(endorsement))
      {
        // For double-sealed cases, which could have happened in the past.
        // Skip intentionally if a predecessor exists; the next link's
        // chain-integrity check will fail-hard if the resulting chain is
        // inconsistent.
        if (endorsement.previous_version.has_value())
        {
          LOG_INFO_FMT(
            "Fetched endorsement for {} - {} is ill-formed but has a "
            "predecessor, so skipping this entry",
            endorsement.endorsement_epoch_begin.to_str(),
            format_epoch(endorsement.endorsement_epoch_end));
          fetch_next_at(endorsement.previous_version.value());
          return;
        }
        fail_fetching(fmt::format(
          "Found an ill-formed endorsement for {} - {} which has no "
          "predecessor",
          endorsement.endorsement_epoch_begin.to_str(),
          format_epoch(endorsement.endorsement_epoch_end)));
      }

      const auto from = endorsement.endorsement_epoch_begin.seqno;
      const auto from_str = endorsement.endorsement_epoch_begin.to_str();
      if (is_self_endorsement(endorsement))
      {
        if (endorsements.find(from) == endorsements.end())
        {
          fail_fetching(fmt::format(
            "Fetched self-endorsement at {} which has not been seen",
            from_str));
        }
        LOG_INFO_FMT("Got self-endorsement at {}, stopping fetching", from);
        complete_fetching(FetchStatus::Done);
        return;
      }

      if (from >= earliest_endorsed_seq)
      {
        fail_fetching(fmt::format(
          "Fetched service endorsement at {} which is greater than the "
          "earliest known seqno in the chain {}",
          from_str,
          earliest_endorsed_seq));
      }

      if (!endorsement.endorsement_epoch_end.has_value())
      {
        fail_fetching(
          fmt::format("Fetched endorsement at {} has no epoch end", from_str));
      }

      earliest_endorsed_seq = from;
      if (endorsements.find(from) != endorsements.end())
      {
        fail_fetching(fmt::format(
          "Fetched service endorsement at {} which already exists", from_str));
      }

      LOG_INFO_FMT(
        "Fetched service endorsement from {} to {}",
        from,
        endorsement.endorsement_epoch_end->seqno);
      endorsements.insert({from, endorsement});

      if (endorsement.previous_version.has_value())
      {
        fetch_next_at(endorsement.previous_version.value());
        return;
      }

      complete_fetching(FetchStatus::Done);
    }

    void build_trusted_key_chain()
    {
      if (!current_service_from.has_value())
      {
        throw std::logic_error(
          "Attempting to build trusted key chain but no current service "
          "created seqno fetched");
      }

      std::span<const uint8_t> previous_key_der{};
      for (const auto& [seqno, endorsement] : endorsements)
      {
        auto verifier =
          ccf::crypto::make_cose_verifier_from_key(endorsement.endorsing_key);
        std::span<uint8_t> endorsed_key;
        if (!verifier->verify(endorsement.endorsement, endorsed_key))
        {
          throw std::logic_error(fmt::format(
            "COSE endorsement chain integrity is violated, endorsement from "
            "{} to {} failed signature verification",
            endorsement.endorsement_epoch_begin.to_str(),
            format_epoch(endorsement.endorsement_epoch_end)));
        }

        LOG_INFO_FMT(
          "Adding trusted seq {} key {}",
          endorsement.endorsement_epoch_begin.seqno,
          ccf::crypto::b64_from_raw(endorsed_key));
        trusted_keys.insert(
          {endorsement.endorsement_epoch_begin.seqno,
           ccf::crypto::make_ec_public_key(endorsed_key)});

        if (
          !previous_key_der.empty() &&
          !std::equal(
            previous_key_der.begin(),
            previous_key_der.end(),
            endorsed_key.begin(),
            endorsed_key.end()))
        {
          throw std::logic_error(fmt::format(
            "Endorsement from {} to {} over public key {} doesn't chain with "
            "the previous endorsement with key {}",
            endorsement.endorsement_epoch_begin.to_str(),
            format_epoch(endorsement.endorsement_epoch_end),
            ccf::ds::to_hex(endorsed_key),
            ccf::ds::to_hex(previous_key_der)));
        }

        previous_key_der = endorsement.endorsing_key;
      }

      const auto& current_pkey =
        network_identity->get_key_pair()->public_key_der();
      if (
        !previous_key_der.empty() &&
        !std::equal(
          previous_key_der.begin(),
          previous_key_der.end(),
          current_pkey.begin(),
          current_pkey.end()))
      {
        throw std::logic_error(fmt::format(
          "Current service identity public key {} does not match the last "
          "endorsing key {}",
          ccf::ds::to_hex(current_pkey),
          ccf::ds::to_hex(previous_key_der)));
      }

      LOG_INFO_FMT(
        "Adding trusted seq {} key {}",
        current_service_from->seqno,
        ccf::crypto::b64_from_raw(current_pkey));
      trusted_keys.insert(
        {current_service_from->seqno,
         ccf::crypto::make_ec_public_key(current_pkey)});
    }

    void fetch_next_at(ccf::SeqNo seq)
    {
      std::optional<CoseEndorsement> endorsement;
      try
      {
        endorsement = historical_state_accessor->get_endorsement_at(seq);
      }
      catch (const std::exception& e)
      {
        fail_fetching(e.what());
      }

      if (!endorsement.has_value())
      {
        if (!schedule_retry([this, seq]() { this->fetch_next_at(seq); }))
        {
          LOG_FAIL_FMT(
            "Exhausted retry budget fetching previous-identity endorsement "
            "at seqno {}",
            seq);
          complete_fetching(FetchStatus::Partial);
        }
        return;
      }

      // Successful fetch: reset attempt counter.
      fetch_attempts = 0;

      try
      {
        validate_fetched_endorsement(endorsement.value());
      }
      catch (const std::exception& e)
      {
        fail_fetching(e.what());
      }

      process_endorsement(endorsement.value());
    }
  };
}
