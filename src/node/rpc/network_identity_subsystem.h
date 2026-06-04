// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/ec_public_key.h"
#include "ccf/ds/hex.h"
#include "ccf/network_identity_interface.h"
#include "ccf/service/tables/service.h"
#include "node/cose_common.h"
#include "node/historical_queries.h"
#include "node/identity.h"
#include "node/rpc/network_identity_accessors.h"
#include "node/rpc/network_identity_accessors_impl.h"
#include "node/rpc/network_identity_chain_helpers.h"
#include "node/rpc/node_interface.h"
#include "service/internal_tables_access.h"

#include <algorithm>
#include <chrono>
#include <fmt/format.h>
#include <mutex>
#include <span>
#include <vector>

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
    // Threading: every method is either a lock-taking wrapper that
    // forwards to its `_unsafe` sibling, or an `_unsafe` method that
    // assumes chain_mutex is held and may only call other `_unsafe`
    // methods (calling a wrapper would re-enter the non-recursive
    // chain_mutex and deadlock).

  protected:
    static constexpr std::chrono::milliseconds RETRY_INTERVAL{100};
    static constexpr int MAX_FETCH_ATTEMPTS = 30;

    // Immutable after construction.
    std::shared_ptr<INodeStateAccessor> node_state_accessor;
    std::shared_ptr<IHistoricalStateAccessor> historical_state_accessor;
    const std::unique_ptr<NetworkIdentity>& network_identity;
    std::shared_ptr<TaskScheduler> scheduler;

    // All mutable state is guarded by chain_mutex.
    mutable std::mutex chain_mutex;

    std::map<SeqNo, CoseEndorsement> endorsements;
    std::map<SeqNo, ccf::crypto::ECPublicKeyPtr> trusted_keys;
    std::optional<TxID> current_service_from;
    SeqNo earliest_endorsed_seq{0};
    bool has_predecessors{false};
    int fetch_attempts{0};
    FetchStatus fetch_status{FetchStatus::Partial};
    // True while a fetch cycle is in flight; cleared by complete_unsafe /
    // fail_fetching_unsafe. Starts true because the constructor
    // synchronously claims the initial bootstrap cycle.
    bool fetch_active{true};

  public:
    NetworkIdentitySubsystem(
      AbstractNodeState& node_state_,
      const std::unique_ptr<NetworkIdentity>& network_identity_,
      std::shared_ptr<ccf::historical::StateCacheImpl> historical_cache_) :
      NetworkIdentitySubsystem(
        std::make_shared<NodeStateAccessor>(node_state_),
        std::make_shared<HistoricalStateAccessor>(std::move(historical_cache_)),
        network_identity_,
        std::make_shared<TaskSchedulerImpl>())
    {}

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
      fetch_first();
    }

    // --- Public wrappers ----------------------------------------------

    [[nodiscard]] FetchStatus endorsements_fetching_status() const override
    {
      std::lock_guard<std::mutex> g(chain_mutex);
      return endorsements_fetching_status_unsafe();
    }

    // Returns an immutable reference; no lock needed.
    const std::unique_ptr<NetworkIdentity>& get() override
    {
      return network_identity;
    }

    void trigger_extension() override
    {
      std::lock_guard<std::mutex> g(chain_mutex);
      trigger_extension_unsafe();
    }

    [[nodiscard]] std::optional<CoseEndorsementsChain>
    get_cose_endorsements_chain(ccf::SeqNo seqno) const override
    {
      std::lock_guard<std::mutex> g(chain_mutex);
      return get_cose_endorsements_chain_unsafe(seqno);
    }

    [[nodiscard]] ccf::crypto::ECPublicKeyPtr get_trusted_identity_for(
      ccf::SeqNo seqno) const override
    {
      std::lock_guard<std::mutex> g(chain_mutex);
      return get_trusted_identity_for_unsafe(seqno);
    }

    [[nodiscard]] TrustedKeys get_trusted_keys() const override
    {
      std::lock_guard<std::mutex> g(chain_mutex);
      return get_trusted_keys_unsafe();
    }

  private:
    // --- Private wrappers (scheduler-callback entry points) ----------

    void fetch_first()
    {
      std::lock_guard<std::mutex> g(chain_mutex);
      fetch_first_unsafe();
    }

    void fetch_next_at(ccf::SeqNo seq)
    {
      std::lock_guard<std::mutex> g(chain_mutex);
      fetch_next_at_unsafe(seq);
    }

    // --- `_unsafe` methods (chain_mutex held by caller) --------------

    [[nodiscard]] FetchStatus endorsements_fetching_status_unsafe() const
    {
      return fetch_status;
    }

    void trigger_extension_unsafe()
    {
      if (fetch_status != FetchStatus::Partial)
      {
        return;
      }
      if (fetch_active)
      {
        // A cycle is already in flight (initial bootstrap or a prior
        // extension); folding this trigger in is a no-op.
        return;
      }
      fetch_active = true;
      fetch_attempts = 0;

      // Resume from the earliest validated link, or re-run fetch_first
      // when nothing has been inserted yet (ill-formed or unfetched
      // topmost).
      std::optional<SeqNo> seq;
      if (!endorsements.empty())
      {
        seq = endorsements.begin()->second.previous_version;
      }

      if (seq.has_value())
      {
        scheduler->add_task([this, s = *seq]() { this->fetch_next_at(s); });
      }
      else
      {
        scheduler->add_task([this]() { this->fetch_first(); });
      }
    }

    [[nodiscard]] std::optional<CoseEndorsementsChain>
    get_cose_endorsements_chain_unsafe(ccf::SeqNo seqno) const
    {
      if (!current_service_from.has_value())
      {
        return std::nullopt;
      }

      if (seqno >= current_service_from->seqno)
      {
        return CoseEndorsementsChain{};
      }

      if (!has_predecessors)
      {
        // Done: confirmed self-only chain -> empty. Partial: topmost
        // not yet read -> nullopt so caller can trigger_extension.
        return fetch_status == FetchStatus::Done ?
          std::optional<CoseEndorsementsChain>(CoseEndorsementsChain{}) :
          std::nullopt;
      }

      auto it = endorsements.upper_bound(seqno);
      if (it == endorsements.begin())
      {
        // Below the earliest validated link. Done: pre-history -> empty.
        // Partial: caller may trigger_extension -> nullopt.
        if (fetch_status == FetchStatus::Done)
        {
          return CoseEndorsementsChain{};
        }
        return std::nullopt;
      }

      CoseEndorsementsChain result;
      for (--it; it != endorsements.end(); ++it)
      {
        result.push_back(it->second.endorsement);
      }
      std::reverse(result.begin(), result.end());
      return result;
    }

    [[nodiscard]] ccf::crypto::ECPublicKeyPtr get_trusted_identity_for_unsafe(
      ccf::SeqNo seqno) const
    {
      auto it = trusted_keys.upper_bound(seqno);
      if (it == trusted_keys.begin())
      {
        // Seqno predates the earliest known key (or trusted_keys is
        // still empty); caller may trigger_extension.
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

    [[nodiscard]] TrustedKeys get_trusted_keys_unsafe() const
    {
      return trusted_keys;
    }

    void retry_first_fetch_unsafe()
    {
      using namespace std::chrono_literals;
      static constexpr auto retry_after = 1s;

      ++fetch_attempts;
      if (fetch_attempts >= MAX_FETCH_ATTEMPTS)
      {
        LOG_FAIL_FMT(
          "Could not start fetching network identity after {} attempts at "
          "{}ms intervals. Cycle ends.",
          MAX_FETCH_ATTEMPTS,
          std::chrono::duration_cast<std::chrono::milliseconds>(retry_after)
            .count());
        complete_unsafe(FetchStatus::Partial);
        return;
      }

      scheduler->add_delayed_task(
        [this]() { this->fetch_first(); }, retry_after);
    }

    void fail_fetching_unsafe(const std::string& err = "")
    {
      if (!err.empty())
      {
        LOG_FAIL_FMT("Failed fetching network identity: {}", err);
      }
      fetch_status = FetchStatus::Failed;
      fetch_active = false;

      // By default this fails node startup early. The throw unwinds
      // out through the lock-taking wrapper, releasing chain_mutex
      // cleanly via the lock_guard destructor. Readers are unaffected:
      // they will observe FetchStatus::Failed on their next call and
      // return empty/nullopt rather than throwing.
      throw std::runtime_error("Failed fetching network identity: " + err);
    }

    void complete_unsafe(FetchStatus target_status)
    {
      fetch_attempts = 0;
      fetch_status = target_status;
      fetch_active = false;
    }

    void fetch_first_unsafe()
    {
      if (!node_state_accessor->is_part_of_network())
      {
        LOG_INFO_FMT(
          "Retry fetching network identity as node is not part of the network "
          "yet");
        retry_first_fetch_unsafe();
        return;
      }

      if (!current_service_from.has_value())
      {
        auto cs = node_state_accessor->read_current_service_from();
        if (!cs.has_value())
        {
          LOG_INFO_FMT(
            "Retrying fetching network identity as current service create "
            "txid is not yet available or service is not yet open");
          retry_first_fetch_unsafe();
          return;
        }
        current_service_from = cs;
      }

      // Seed trusted_keys with the current-service key (idempotent).
      if (trusted_keys.find(current_service_from->seqno) == trusted_keys.end())
      {
        trusted_keys.insert(
          {current_service_from->seqno,
           ccf::crypto::make_ec_public_key(
             network_identity->get_key_pair()->public_key_der())});
      }

      auto endorsement = node_state_accessor->read_topmost_endorsement();
      if (!endorsement.has_value())
      {
        LOG_INFO_FMT(
          "Retrying fetching network identity as there is no previous service "
          "identity endorsement yet");
        retry_first_fetch_unsafe();
        return;
      }

      // Reset the per-step counter for the chain walk: retries spent
      // waiting for the topmost entry must not eat into the per-chunk
      // budget consumed below.
      fetch_attempts = 0;

      if (is_self_endorsement(endorsement.value()))
      {
        if (
          current_service_from->seqno !=
          endorsement->endorsement_epoch_begin.seqno)
        {
          fail_fetching_unsafe(fmt::format(
            "The first fetched endorsement is a self-endorsement with seqno {} "
            "which is different from current_service_create_txid {}",
            endorsement->endorsement_epoch_begin.seqno,
            current_service_from->seqno));
        }

        LOG_INFO_FMT(
          "The very first service endorsement is self-signed at {}, no "
          "endorsement chain will be preloaded",
          current_service_from->seqno);

        has_predecessors = false;
        complete_unsafe(FetchStatus::Done);
        return;
      }

      has_predecessors = true;
      earliest_endorsed_seq = current_service_from->seqno;
      process_endorsement_unsafe(endorsement.value());
    }

    void process_endorsement_unsafe(const ccf::CoseEndorsement& endorsement)
    {
      try
      {
        validate_fetched_endorsement(endorsement);
      }
      catch (const std::exception& e)
      {
        fail_fetching_unsafe(e.what());
      }

      if (is_ill_formed(endorsement))
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
          fetch_next_at_unsafe(endorsement.previous_version.value());
          return;
        }
        fail_fetching_unsafe(fmt::format(
          "Found an ill-formed endorsement for {} - {} which has no "
          "predecessor",
          endorsement.endorsement_epoch_begin.to_str(),
          format_epoch(endorsement.endorsement_epoch_end)));
      }

      process_link_unsafe(endorsement);
    }

    // Verify and append a single endorsement to the chain. Used for
    // both the initial walk and extension cycles; the two cases differ
    // only in whether `endorsements` is empty when the link arrives.
    //
    // Chain-link predicate (oldest->newest):
    //   adjacent (older A, newer B): B.endorsed_key == A.endorsing_key
    //   newest entry N: N.endorsing_key == current_service_pkey
    // Extending backward with NEW becoming the new oldest:
    //   existing_earliest.endorsed_key == NEW.endorsing_key
    void process_link_unsafe(const ccf::CoseEndorsement& endorsement)
    {
      const auto from = endorsement.endorsement_epoch_begin.seqno;

      if (is_self_endorsement(endorsement))
      {
        if (endorsements.find(from) == endorsements.end())
        {
          fail_fetching_unsafe(fmt::format(
            "Fetched self-endorsement with seqno {} which has not been seen",
            from));
        }
        LOG_INFO_FMT(
          "COSE endorsement chain reached self-endorsement at {}", from);
        complete_unsafe(FetchStatus::Done);
        return;
      }

      if (!endorsement.endorsement_epoch_end.has_value())
      {
        fail_fetching_unsafe(
          fmt::format("Fetched endorsement at {} has no epoch end", from));
        return; // to silence clang-tidy unchecked optional
      }

      if (!current_service_from.has_value())
      {
        fail_fetching_unsafe("Unset current_service_from when extending chain");
        return; // to silence clang-tidy unchecked optional
      }
      if (from >= earliest_endorsed_seq)
      {
        fail_fetching_unsafe(fmt::format(
          "Fetched service endorsement with seqno {} which is not earlier "
          "than the current earliest known {}",
          from,
          earliest_endorsed_seq));
      }
      if (endorsements.find(from) != endorsements.end())
      {
        fail_fetching_unsafe(fmt::format(
          "Fetched service endorsement with seqno {} which already exists",
          from));
      }

      std::vector<uint8_t> expected_new_endorsing_key_der;
      if (!endorsements.empty())
      {
        const auto& existing_earliest = endorsements.begin()->second;
        auto trusted_it =
          trusted_keys.find(existing_earliest.endorsement_epoch_begin.seqno);
        if (trusted_it == trusted_keys.end())
        {
          fail_fetching_unsafe(fmt::format(
            "Missing trusted key entry for existing earliest endorsement "
            "at seqno {}",
            existing_earliest.endorsement_epoch_begin.seqno));
          return; // to silence clang-tidy unchecked iterator
        }
        expected_new_endorsing_key_der = trusted_it->second->public_key_der();

        try
        {
          verify_endorsements_connected(existing_earliest, endorsement);
        }
        catch (const std::exception& e)
        {
          fail_fetching_unsafe(e.what());
        }
      }
      else
      {
        expected_new_endorsing_key_der =
          network_identity->get_key_pair()->public_key_der();
        try
        {
          validate_chain_front_connection(endorsement, *current_service_from);
        }
        catch (const std::exception& e)
        {
          fail_fetching_unsafe(e.what());
        }
      }

      ccf::crypto::ECPublicKeyPtr new_trusted_key;
      try
      {
        auto verifier =
          ccf::crypto::make_cose_verifier_from_key(endorsement.endorsing_key);
        std::span<uint8_t> endorsed_key;
        if (!verifier->verify(endorsement.endorsement, endorsed_key))
        {
          throw std::logic_error(fmt::format(
            "Endorsement from {} to {} failed signature verification",
            endorsement.endorsement_epoch_begin.to_str(),
            format_epoch(endorsement.endorsement_epoch_end)));
        }
        if (
          endorsement.endorsing_key.size() !=
            expected_new_endorsing_key_der.size() ||
          !std::equal(
            endorsement.endorsing_key.begin(),
            endorsement.endorsing_key.end(),
            expected_new_endorsing_key_der.begin()))
        {
          throw std::logic_error(fmt::format(
            "Endorsement from {} to {} signed by key {} does not chain with "
            "the expected next key {}",
            endorsement.endorsement_epoch_begin.to_str(),
            format_epoch(endorsement.endorsement_epoch_end),
            ccf::ds::to_hex(endorsement.endorsing_key),
            ccf::ds::to_hex(expected_new_endorsing_key_der)));
        }
        new_trusted_key = ccf::crypto::make_ec_public_key(endorsed_key);
      }
      catch (const std::exception& e)
      {
        fail_fetching_unsafe(e.what());
      }

      LOG_INFO_FMT(
        "COSE endorsement chain extended to seqno {} (epoch {} - {})",
        from,
        endorsement.endorsement_epoch_begin.to_str(),
        endorsement.endorsement_epoch_end->to_str());

      endorsements.insert({from, endorsement});
      trusted_keys.insert({from, std::move(new_trusted_key)});
      earliest_endorsed_seq = from;

      if (!endorsement.previous_version.has_value())
      {
        fail_fetching_unsafe(fmt::format(
          "Non-self-endorsement at seqno {} unexpectedly has no "
          "previous_version",
          from));
        return; // to silence clang-tidy unchecked optional
      }
      fetch_next_at_unsafe(*endorsement.previous_version);
    }

    void fetch_next_at_unsafe(ccf::SeqNo seq)
    {
      // Bail out on stale callbacks from cycles that have already
      // ended. Belt-and-braces: under the monitor discipline a single
      // cycle has at most one outstanding scheduled task, so genuine
      // stale callbacks should not occur. Cheap to keep as a guard.
      if (!fetch_active)
      {
        return;
      }

      std::optional<CoseEndorsement> endorsement;
      try
      {
        endorsement = historical_state_accessor->get_endorsement_at(seq);
      }
      catch (const std::exception& e)
      {
        fail_fetching_unsafe(e.what());
      }
      if (!endorsement.has_value())
      {
        retry_fetch_next_unsafe(seq);
        return;
      }

      // Successful fetch: reset attempt counter.
      fetch_attempts = 0;
      process_endorsement_unsafe(endorsement.value());
    }

    void retry_fetch_next_unsafe(ccf::SeqNo seq)
    {
      ++fetch_attempts;
      if (fetch_attempts >= MAX_FETCH_ATTEMPTS)
      {
        LOG_FAIL_FMT(
          "Could not fetch previous service identity endorsement at seqno {} "
          "after {} attempts at {}ms intervals. Cycle ends; status is "
          "Partial. Callers may invoke trigger_extension to retry.",
          seq,
          MAX_FETCH_ATTEMPTS,
          RETRY_INTERVAL.count());
        complete_unsafe(FetchStatus::Partial);
        return;
      }

      scheduler->add_delayed_task(
        [this, seq]() { this->fetch_next_at(seq); }, RETRY_INTERVAL);
    }
  };
}
