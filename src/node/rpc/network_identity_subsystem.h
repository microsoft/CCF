// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_verifier.h"
#include "ccf/network_identity_interface.h"
#include "ccf/node/configuration.h"
#include "crypto/cose.h"
#include "ds/internal_logger.h"
#include "node/identity.h"
#include "node/rpc/network_identity_accessors.h"
#include "node/rpc/network_identity_chain_helpers.h"

#include <atomic>
#include <chrono>

namespace ccf
{
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

    // PQ chain, fetched from the historical states of the CLASSICAL one: a PQ
    // back-endorsement is written with a CLASSICAL one, over the same epochs
    // and with the same previous version. It ends with the PQ self-endorsement
    // of the service which started it. An inconsistent PQ chain fails
    // fetching, as an inconsistent CLASSICAL chain does.
    // Set when the current service has a PQ identity
    std::optional<std::vector<uint8_t>> current_pq_key_der;
    // Whether the oldest PQ endorsement fetched so far has a predecessor
    bool pq_fetching{false};
    std::map<SeqNo, CoseEndorsement> pq_endorsements;
    // DER-encoded SubjectPublicKeyInfo of each PQ service key, from the start
    // of its epoch
    TrustedKeysDer pq_trusted_keys;

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

    [[nodiscard]] std::optional<CoseEndorsementsChain>
    get_cose_endorsements_chain(
      ccf::SeqNo seqno, IdentityType identity_type) const override
    {
      switch (identity_type)
      {
        case IdentityType::CLASSICAL:
        {
          return get_cose_endorsements_chain(seqno);
        }
        case IdentityType::PQ:
        {
          return get_pq_cose_endorsements_chain(seqno);
        }
      }
      return std::nullopt;
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

    [[nodiscard]] std::optional<std::vector<uint8_t>> get_trusted_key_der_for(
      ccf::SeqNo seqno, IdentityType identity_type) const override
    {
      switch (identity_type)
      {
        case IdentityType::CLASSICAL:
        {
          const auto key = get_trusted_identity_for(seqno);
          if (key == nullptr)
          {
            return std::nullopt;
          }
          return key->public_key_der();
        }
        case IdentityType::PQ:
        {
          const auto status = fetch_status.load();
          if (status != FetchStatus::Done && status != FetchStatus::Partial)
          {
            throw IdentityHistoryNotFetched(fmt::format(
              "Trusted PQ key requested for seqno {} but identity history "
              "fetching has not been completed yet",
              seqno));
          }
          auto it = pq_trusted_keys.upper_bound(seqno);
          if (it == pq_trusted_keys.begin())
          {
            return std::nullopt;
          }
          return std::prev(it)->second;
        }
      }
      return std::nullopt;
    }

    [[nodiscard]] TrustedKeysDer get_trusted_keys_der(
      IdentityType identity_type) const override
    {
      switch (identity_type)
      {
        case IdentityType::CLASSICAL:
        {
          TrustedKeysDer keys;
          for (const auto& [seqno, key] : get_trusted_keys())
          {
            keys.emplace(seqno, key->public_key_der());
          }
          return keys;
        }
        case IdentityType::PQ:
        {
          const auto status = fetch_status.load();
          if (status != FetchStatus::Done && status != FetchStatus::Partial)
          {
            throw IdentityHistoryNotFetched(
              "Trusted PQ keys requested but identity history fetching has "
              "not completed yet");
          }
          return pq_trusted_keys;
        }
      }
      return {};
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
    [[nodiscard]] std::optional<CoseEndorsementsChain>
    get_pq_cose_endorsements_chain(ccf::SeqNo seqno) const
    {
      const auto status = fetch_status.load();
      if (status != FetchStatus::Done && status != FetchStatus::Partial)
      {
        throw IdentityHistoryNotFetched(fmt::format(
          "PQ COSE endorsements chain requested for seqno {} but identity "
          "history fetching has not been completed yet",
          seqno));
      }

      if (!current_pq_key_der.has_value() || !current_service_from.has_value())
      {
        return std::nullopt;
      }

      if (seqno >= current_service_from->seqno)
      {
        return CoseEndorsementsChain{};
      }

      // Earlier seqnos are covered from the epoch of the service which started
      // the PQ chain, or in Partial from the earliest fetched PQ endorsement
      auto it = pq_endorsements.upper_bound(seqno);
      if (it == pq_endorsements.begin())
      {
        return std::nullopt;
      }

      CoseEndorsementsChain result;
      for (--it; it != pq_endorsements.end(); ++it)
      {
        result.push_back(it->second.endorsement);
      }
      std::reverse(result.begin(), result.end());
      return result;
    }

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

      complete_pq_chain(target_status, *current_service_from);

      log_status(target_status);
      fetch_status.store(target_status);
    }

    [[noreturn]] void fail_pq_chain(const std::exception& e)
    {
      fail_fetching(fmt::format("Invalid PQ endorsements chain: {}", e.what()));
    }

    // Starts the PQ chain at the PQ endorsement which the opening of the
    // current service, created at current_from, wrote with the CLASSICAL one
    void start_pq_chain(
      const std::optional<CoseEndorsement>& pq_endorsement,
      const CoseEndorsement& classical_endorsement,
      const ccf::TxID& current_from)
    {
      // A build without ML-DSA never holds a PQ identity
      if (!ccf::crypto::mldsa_supported())
      {
        return;
      }

      try
      {
        const auto pq_key = network_identity->get_pq_key_pair();
        if (pq_key == nullptr)
        {
          // Every node of a service with a PQ identity holds its PQ key
          if (pq_endorsement.has_value())
          {
            throw std::logic_error(
              "a PQ endorsement was written when the current service opened, "
              "but the network identity of this node has no PQ key");
          }
          return;
        }

        const auto& current_pq_key =
          current_pq_key_der.emplace(pq_key->public_key_der());

        if (!pq_endorsement.has_value())
        {
          throw std::logic_error(
            "the current service has a PQ identity, but no PQ endorsement was "
            "written when it opened");
        }

        if (pq_endorsement->endorsing_key != current_pq_key)
        {
          throw std::logic_error(fmt::format(
            "the PQ endorsement written when the current service opened is "
            "signed by public key {}, which is not the current PQ service "
            "public key {}",
            ccf::ds::to_hex(pq_endorsement->endorsing_key),
            ccf::ds::to_hex(current_pq_key)));
        }

        if (is_self_endorsement(pq_endorsement.value()))
        {
          if (pq_endorsement->endorsement_epoch_begin != current_from)
          {
            throw std::logic_error(fmt::format(
              "the current PQ self-endorsement at {} is different from "
              "current_service_create_txid {}",
              pq_endorsement->endorsement_epoch_begin.to_str(),
              current_from.to_str()));
          }
          LOG_INFO_FMT(
            "The PQ endorsements chain starts with the current service at {}",
            current_from.to_str());
          return;
        }

        process_pq_endorsement(pq_endorsement.value(), classical_endorsement);
      }
      catch (const std::exception& e)
      {
        fail_pq_chain(e);
      }
    }

    // Adds a PQ endorsement, written with the given CLASSICAL one, to the PQ
    // chain fetched so far, of which it is the oldest
    void process_pq_endorsement(
      const CoseEndorsement& endorsement,
      const CoseEndorsement& classical_endorsement)
    {
      const auto from = endorsement.endorsement_epoch_begin.seqno;
      if (is_self_endorsement(endorsement))
      {
        // As for CLASSICAL, the next PQ endorsement covers the epoch which
        // the self-endorsement started
        if (!pq_endorsements.contains(from))
        {
          throw std::logic_error(fmt::format(
            "fetched PQ self-endorsement at {} which has not been seen",
            endorsement.endorsement_epoch_begin.to_str()));
        }
        LOG_INFO_FMT("Got PQ self-endorsement at {}", from);
        pq_fetching = false;
        return;
      }

      if (
        endorsement.endorsement_epoch_begin !=
          classical_endorsement.endorsement_epoch_begin ||
        endorsement.endorsement_epoch_end !=
          classical_endorsement.endorsement_epoch_end ||
        endorsement.previous_version != classical_endorsement.previous_version)
      {
        throw std::logic_error(fmt::format(
          "PQ endorsement for {} - {} does not match the CLASSICAL "
          "endorsement for {} - {} written with it",
          endorsement.endorsement_epoch_begin.to_str(),
          format_epoch(endorsement.endorsement_epoch_end),
          classical_endorsement.endorsement_epoch_begin.to_str(),
          format_epoch(classical_endorsement.endorsement_epoch_end)));
      }

      pq_fetching = true;
      if (has_ill_formed_epoch_range(endorsement))
      {
        // Skipped, as the CLASSICAL endorsement with the same range is
        return;
      }

      if (!pq_endorsements.emplace(from, endorsement).second)
      {
        throw std::logic_error(fmt::format(
          "fetched PQ service endorsement at {} which already exists",
          endorsement.endorsement_epoch_begin.to_str()));
      }
    }

    // Extends the PQ chain with the endorsements written at seq, which the
    // oldest PQ endorsement fetched so far points to
    void fetch_pq_endorsement_at(
      ccf::SeqNo seq, const WrittenEndorsements& written)
    {
      if (!pq_fetching)
      {
        return;
      }

      try
      {
        if (!written.pq.has_value())
        {
          throw std::logic_error(fmt::format(
            "no PQ endorsement was written at {}, which the PQ endorsement "
            "after it points to",
            seq));
        }
        validate_fetched_endorsement(written.pq.value());
        process_pq_endorsement(written.pq.value(), written.classical);
      }
      catch (const std::exception& e)
      {
        fail_pq_chain(e);
      }
    }

    void complete_pq_chain(
      FetchStatus target_status, const ccf::TxID& current_from)
    {
      if (!current_pq_key_der.has_value())
      {
        return;
      }

      try
      {
        if (pq_fetching && target_status == FetchStatus::Done)
        {
          throw std::logic_error(
            "the CLASSICAL endorsements chain ends before the PQ one");
        }

        if (!pq_endorsements.empty())
        {
          auto next = pq_endorsements.begin();
          auto prev = next++;
          while (next != pq_endorsements.end())
          {
            verify_endorsements_connected(next->second, prev->second);
            ++prev;
            ++next;
          }
          validate_chain_front_connection(prev->second, current_from);
        }
        build_pq_trusted_key_chain(
          current_pq_key_der.value(), current_from.seqno);
      }
      catch (const std::exception& e)
      {
        fail_pq_chain(e);
      }

      LOG_INFO_FMT(
        "Fetched {} PQ service endorsement(s)", pq_endorsements.size());
    }

    void build_pq_trusted_key_chain(
      std::span<const uint8_t> current_pq_key, ccf::SeqNo current_from)
    {
      std::span<const uint8_t> previous_key_der{};
      for (const auto& [seqno, endorsement] : pq_endorsements)
      {
        std::vector<uint8_t> endorsed_key;
        try
        {
          endorsed_key = verify_cose_endorsement_signature(
            endorsement.endorsement, endorsement.endorsing_key);
        }
        catch (const std::logic_error&)
        {
          throw std::logic_error(fmt::format(
            "PQ endorsement from {} to {} failed signature verification",
            endorsement.endorsement_epoch_begin.to_str(),
            format_epoch(endorsement.endorsement_epoch_end)));
        }

        if (
          !previous_key_der.empty() &&
          !std::equal(
            previous_key_der.begin(),
            previous_key_der.end(),
            endorsed_key.begin(),
            endorsed_key.end()))
        {
          throw std::logic_error(fmt::format(
            "PQ endorsement from {} to {} over public key {} doesn't chain "
            "with the previous PQ endorsement with key {}",
            endorsement.endorsement_epoch_begin.to_str(),
            format_epoch(endorsement.endorsement_epoch_end),
            ccf::ds::to_hex(endorsed_key),
            ccf::ds::to_hex(previous_key_der)));
        }

        pq_trusted_keys.emplace(seqno, std::move(endorsed_key));
        previous_key_der = endorsement.endorsing_key;
      }

      if (
        !previous_key_der.empty() &&
        !std::equal(
          previous_key_der.begin(),
          previous_key_der.end(),
          current_pq_key.begin(),
          current_pq_key.end()))
      {
        throw std::logic_error(fmt::format(
          "Current PQ service public key {} does not match the last PQ "
          "endorsing key {}",
          ccf::ds::to_hex(current_pq_key),
          ccf::ds::to_hex(previous_key_der)));
      }

      pq_trusted_keys.emplace(
        current_from,
        std::vector<uint8_t>(current_pq_key.begin(), current_pq_key.end()));
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

      auto current = node_state_accessor->get_current_service_identity();
      if (!current.create_txid.has_value())
      {
        LOG_INFO_FMT(
          "Retrying fetching network identity as current service create "
          "txid is not yet available or service is not yet open");
        scheduler->add_delayed_task(
          [this]() { this->fetch_first(); },
          std::chrono::milliseconds(retry_interval_ms));
        return;
      }

      const auto& endorsement = current.endorsement;
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

      // The topmost endorsement's endorsing key should match the current
      // network identity public key. During join from a stale snapshot, the
      // live KV may initially expose an older endorsement until ledger replay
      // catches up.
      const auto& current_pkey =
        network_identity->get_key_pair()->public_key_der();
      if (endorsement->endorsing_key != current_pkey)
      {
        // Unbounded retry (like the other pre-bootstrap waits above), logging
        // the mismatching keys for diagnosis while the local store catches up.
        LOG_INFO_FMT(
          "Retrying fetching network identity: topmost endorsement at {} is "
          "signed by public key {}, which differs from the expected current "
          "network identity public key {}",
          endorsement->endorsement_epoch_begin.to_str(),
          ccf::ds::to_hex(endorsement->endorsing_key),
          ccf::ds::to_hex(current_pkey));
        scheduler->add_delayed_task(
          [this]() { this->fetch_first(); },
          std::chrono::milliseconds(retry_interval_ms));
        return;
      }

      current_service_from = current.create_txid;
      start_pq_chain(
        current.pq_endorsement,
        endorsement.value(),
        current.create_txid.value());

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
        std::vector<uint8_t> endorsed_key;
        try
        {
          endorsed_key = verify_cose_endorsement_signature(
            endorsement.endorsement, endorsement.endorsing_key);
        }
        catch (const std::logic_error&)
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
      std::optional<WrittenEndorsements> written;
      try
      {
        written = historical_state_accessor->get_endorsements_at(seq);
      }
      catch (const std::exception& e)
      {
        fail_fetching(e.what());
      }

      if (!written.has_value())
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
        validate_fetched_endorsement(written->classical);
      }
      catch (const std::exception& e)
      {
        fail_fetching(e.what());
      }

      fetch_pq_endorsement_at(seq, written.value());
      process_endorsement(written->classical);
    }
  };
}
