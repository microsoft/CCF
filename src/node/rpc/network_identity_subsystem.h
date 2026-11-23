// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/sha256_hash.h"
#include "ccf/network_identity_interface.h"
#include "ccf/node/configuration.h"
#include "crypto/cose.h"
#include "ds/internal_logger.h"
#include "node/identity.h"
#include "node/rpc/network_identity_accessors.h"
#include "node/rpc/network_identity_chain_helpers.h"
#include "service/tables/identity_types.h"

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
    // The CLASSICAL endorsement chain terminates here. It is not part of the
    // chain, but is checked for validity.
    std::optional<CoseEndorsement> self_endorsement;

    // PQ counterparts of some of the members above, with PQ-only additions.
    std::optional<std::vector<uint8_t>> current_pq_key_der;
    std::map<SeqNo, CoseEndorsement> pq_endorsements;
    TrustedKeysPQ pq_trusted_keys;

    // The PQ chain can stop earlier than the CLASSICAL one, so it needs its
    // own indication.
    bool pq_fetching{false};

    // The PQ endorsement chain terminates here. It is not part of the chain,
    // but is checked for validity.
    std::optional<CoseEndorsement> pq_self_endorsement;

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
      check_fetched(
        fmt::format("COSE endorsements chain requested for seqno {}", seqno));
      // Settled, so unchanged since the check
      const auto status = fetch_status.load();

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
      check_fetched(fmt::format("Trusted key requested for seqno {}", seqno));
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
      check_fetched("Trusted keys requested");
      return trusted_keys;
    }

    [[nodiscard]] std::optional<CoseEndorsementsChain>
    get_cose_endorsements_chain_pq(ccf::SeqNo seqno) const override
    {
      check_fetched(fmt::format(
        "PQ COSE endorsements chain requested for seqno {}", seqno));

      if (!current_pq_key_der.has_value() || !current_service_from.has_value())
      {
        return std::nullopt;
      }

      if (seqno >= current_service_from->seqno)
      {
        return CoseEndorsementsChain{};
      }

      // Earlier seqnos are covered from the service which introduced the PQ
      // identity, or in Partial from the earliest fetched PQ endorsement
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

    [[nodiscard]] ccf::crypto::MLDSAPublicKeyPtr get_trusted_identity_for_pq(
      ccf::SeqNo seqno) const override
    {
      check_fetched(
        fmt::format("Trusted PQ key requested for seqno {}", seqno));

      auto it = pq_trusted_keys.upper_bound(seqno);
      if (it == pq_trusted_keys.begin())
      {
        return nullptr;
      }
      return std::prev(it)->second;
    }

    [[nodiscard]] TrustedKeysPQ get_trusted_keys_pq() const override
    {
      check_fetched("Trusted PQ keys requested");
      return pq_trusted_keys;
    }

  protected:
    void check_fetched(const std::string& request) const
    {
      const auto status = fetch_status.load();
      if (status != FetchStatus::Done && status != FetchStatus::Partial)
      {
        throw IdentityHistoryNotFetched(fmt::format(
          "{} but identity history fetching has not been completed yet",
          request));
      }
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
        trusted_keys = build_trusted_key_chain<ccf::crypto::ECPublicKeyPtr>(
          IdentityType::CLASSICAL,
          endorsements,
          self_endorsement,
          network_identity->get_key_pair()->public_key_der(),
          *current_service_from,
          [](const std::vector<uint8_t>& der) {
            return ccf::crypto::make_ec_public_key(der);
          });
      }
      catch (const std::exception& e)
      {
        fail_fetching(e.what());
      }

      if (current_pq_key_der.has_value())
      {
        try
        {
          if (pq_fetching && target_status == FetchStatus::Done)
          {
            throw std::logic_error(
              "the classical endorsements chain ends before the PQ one");
          }
          pq_trusted_keys =
            build_trusted_key_chain<ccf::crypto::MLDSAPublicKeyPtr>(
              IdentityType::PQ,
              pq_endorsements,
              pq_self_endorsement,
              current_pq_key_der.value(),
              *current_service_from,
              [](const std::vector<uint8_t>& der) {
                return ccf::crypto::make_mldsa_public_key(der);
              });
        }
        catch (const std::exception& e)
        {
          fail_pq_fetching(e.what());
        }
      }

      log_status(target_status);
      fetch_status.store(target_status);
    }

    [[noreturn]] void fail_pq_fetching(const std::string& err)
    {
      fail_fetching(fmt::format("PQ endorsements chain: {}", err));
    }

    // Starts the PQ chain when the current service has a PQ identity. The
    // classical endorsement has already been matched to the current service,
    // and the PQ one was written with it.
    void start_pq_chain(const CurrentServiceIdentity& current)
    {
      // A build without ML-DSA never holds a PQ identity
      if (!ccf::crypto::mldsa_supported())
      {
        return;
      }

      const auto pq_key = network_identity->get_pq_key_pair();
      if (pq_key == nullptr)
      {
        // Every node of a service with a PQ identity holds its PQ key
        if (current.pq_endorsement.has_value())
        {
          fail_pq_fetching(
            "a PQ endorsement was written when the current service opened, "
            "but the network identity of this node has no PQ key");
        }
        return;
      }

      const auto& current_pq_key =
        current_pq_key_der.emplace(pq_key->public_key_der());
      if (
        current.pq_endorsement.has_value() &&
        current.pq_endorsement->endorsing_key != current_pq_key)
      {
        fail_pq_fetching(fmt::format(
          "the PQ endorsement written when the current service opened is "
          "signed by public key {}, which is not the current PQ service "
          "public key {}",
          key_for_error(
            IdentityType::PQ, current.pq_endorsement->endorsing_key),
          key_for_error(IdentityType::PQ, current_pq_key)));
      }

      pq_fetching = true;
    }

    // Adds the PQ endorsement written with the given classical one, which is
    // about to be processed, until the PQ chain stops at its self-endorsement
    void process_pq_endorsement(
      const std::optional<CoseEndorsement>& pq_endorsement,
      const CoseEndorsement& classical)
    {
      if (!pq_fetching)
      {
        return;
      }

      if (!pq_endorsement.has_value())
      {
        fail_pq_fetching(fmt::format(
          "no PQ endorsement was written with the classical endorsement for "
          "{} - {}",
          classical.endorsement_epoch_begin.to_str(),
          format_epoch(classical.endorsement_epoch_end)));
      }
      const auto& endorsement = pq_endorsement.value();

      try
      {
        validate_fetched_endorsement(endorsement);
      }
      catch (const std::exception& e)
      {
        fail_pq_fetching(e.what());
      }

      const auto from = endorsement.endorsement_epoch_begin.seqno;
      if (is_self_endorsement(endorsement))
      {
        // As for classical, the self-endorsement starts the oldest PQ epoch
        // fetched, which is the current one when no service endorsed it
        if (!current_service_from.has_value())
        {
          // Invariant: the PQ chain starts after current_service_from is set
          fail_pq_fetching(
            "Unset current_service_from when fetching a self-endorsement");
        }
        const auto oldest_from = pq_endorsements.empty() ?
          current_service_from->seqno :
          pq_endorsements.begin()->first;
        if (from != oldest_from)
        {
          fail_pq_fetching(fmt::format(
            "fetched self-endorsement at {} which has not been seen",
            endorsement.endorsement_epoch_begin.to_str()));
        }
        LOG_INFO_FMT("Got PQ self-endorsement at {}, stopping PQ chain", from);
        pq_self_endorsement = endorsement;
        pq_fetching = false;
        return;
      }

      if (
        endorsement.endorsement_epoch_begin !=
          classical.endorsement_epoch_begin ||
        endorsement.endorsement_epoch_end != classical.endorsement_epoch_end ||
        endorsement.previous_version != classical.previous_version)
      {
        fail_pq_fetching(fmt::format(
          "endorsement for {} - {} with previous version {} does not match "
          "the classical endorsement for {} - {} with previous version {} "
          "written with it",
          endorsement.endorsement_epoch_begin.to_str(),
          format_epoch(endorsement.endorsement_epoch_end),
          format_previous_version(endorsement.previous_version),
          classical.endorsement_epoch_begin.to_str(),
          format_epoch(classical.endorsement_epoch_end),
          format_previous_version(classical.previous_version)));
      }

      std::optional<std::vector<uint8_t>> previous_root;
      std::optional<std::vector<uint8_t>> classical_previous_root;
      try
      {
        previous_root = ccf::crypto::extract_cose_endorsement_previous_root(
          endorsement.endorsement);
        classical_previous_root =
          ccf::crypto::extract_cose_endorsement_previous_root(
            classical.endorsement);
      }
      catch (const std::exception& e)
      {
        fail_pq_fetching(e.what());
      }
      if (previous_root != classical_previous_root)
      {
        fail_pq_fetching(fmt::format(
          "endorsement for {} - {} is signed over another previous ledger "
          "root than the classical endorsement written with it",
          endorsement.endorsement_epoch_begin.to_str(),
          format_epoch(endorsement.endorsement_epoch_end)));
      }

      // The classical endorsement over the same epoch is skipped if ill-formed
      // and rejected if already fetched
      if (!has_ill_formed_epoch_range(endorsement))
      {
        pq_endorsements.emplace(from, endorsement);
      }
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

      try
      {
        validate_fetched_endorsement(endorsement.value());
      }
      catch (const std::exception& e)
      {
        fail_fetching(e.what());
      }

      current_service_from = current.create_txid;
      start_pq_chain(current);
      process_pq_endorsement(current.pq_endorsement, endorsement.value());

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
        self_endorsement = endorsement;
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
        if (!endorsements.contains(from))
        {
          fail_fetching(fmt::format(
            "Fetched self-endorsement at {} which has not been seen",
            from_str));
        }
        LOG_INFO_FMT("Got self-endorsement at {}, stopping fetching", from);
        self_endorsement = endorsement;
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
      if (endorsements.contains(from))
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

    static std::string format_previous_version(
      const std::optional<ccf::kv::Version>& previous_version)
    {
      return previous_version.has_value() ?
        std::to_string(previous_version.value()) :
        "null";
    }

    // ML-DSA public keys are several kilobytes, so they are identified by
    // their SHA-256
    static std::string key_digest(std::span<const uint8_t> key_der)
    {
      return fmt::format(
        "sha256:{}",
        ccf::crypto::Sha256Hash(key_der.data(), key_der.size()).hex_str());
    }

    static std::string key_for_log(
      IdentityType identity_type, const std::vector<uint8_t>& key_der)
    {
      return identity_type == IdentityType::PQ ? key_digest(key_der) :
                                                 ccf::ds::b64_from_raw(key_der);
    }

    static std::string key_for_error(
      IdentityType identity_type, std::span<const uint8_t> key_der)
    {
      return identity_type == IdentityType::PQ ? key_digest(key_der) :
                                                 ccf::ds::to_hex(key_der);
    }

    // Checks that the endorsements of a chain are connected up to the current
    // service, with valid signatures and linked keys, and returns the key
    // trusted from the start of each epoch. If fetching stopped at a
    // self-endorsement, checks that the oldest trusted key signed it.
    template <typename KeyPtr, typename MakeKey>
    static std::map<SeqNo, KeyPtr> build_trusted_key_chain(
      IdentityType identity_type,
      const std::map<SeqNo, CoseEndorsement>& chain,
      const std::optional<CoseEndorsement>& chain_self_endorsement,
      const std::vector<uint8_t>& current_pkey,
      const ccf::TxID& current_from,
      MakeKey make_key)
    {
      if (!chain.empty())
      {
        auto next = chain.begin();
        auto prev = next++;
        while (next != chain.end())
        {
          verify_endorsements_connected(next->second, prev->second);
          ++prev;
          ++next;
        }
        validate_chain_front_connection(prev->second, current_from);
      }

      std::map<SeqNo, KeyPtr> keys;
      std::span<const uint8_t> previous_key_der{};
      // Key trusted for the oldest epoch, which the current service has if
      // no endorsement covers an older one
      std::vector<uint8_t> oldest_key = current_pkey;
      auto oldest_from = current_from;
      for (const auto& [seqno, endorsement] : chain)
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

        if (previous_key_der.empty())
        {
          oldest_key = endorsed_key;
          oldest_from = endorsement.endorsement_epoch_begin;
        }

        LOG_INFO_FMT(
          "Adding trusted {} seq {} key {}",
          identity_type,
          endorsement.endorsement_epoch_begin.seqno,
          key_for_log(identity_type, endorsed_key));
        keys.insert(
          {endorsement.endorsement_epoch_begin.seqno, make_key(endorsed_key)});

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
            key_for_error(identity_type, endorsed_key),
            key_for_error(identity_type, previous_key_der)));
        }

        previous_key_der = endorsement.endorsing_key;
      }

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
          key_for_error(identity_type, current_pkey),
          key_for_error(identity_type, previous_key_der)));
      }

      if (chain_self_endorsement.has_value())
      {
        validate_self_endorsement(
          chain_self_endorsement.value(), oldest_from, oldest_key);
      }

      LOG_INFO_FMT(
        "Adding trusted {} seq {} key {}",
        identity_type,
        current_from.seqno,
        key_for_log(identity_type, current_pkey));
      keys.insert({current_from.seqno, make_key(current_pkey)});
      return keys;
    }

    void fetch_next_at(ccf::SeqNo seq)
    {
      std::optional<IdentityEndorsements> written;
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

      process_pq_endorsement(written->pq, written->classical);
      process_endorsement(written->classical);
    }
  };
}
