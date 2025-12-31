// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/network_identity_interface.h"
#include "ccf/service/tables/service.h"
#include "node/historical_queries.h"
#include "node/identity.h"
#include "node/rpc/node_interface.h"
#include "service/internal_tables_access.h"

#include <atomic>

namespace ccf
{
  static std::string format_epoch(const std::optional<ccf::TxID>& epoch_end)
  {
    return epoch_end.has_value() ? epoch_end->to_str() : "null";
  }

  static bool is_self_endorsement(const ccf::CoseEndorsement& endorsement)
  {
    return !endorsement.previous_version.has_value();
  }

  static bool is_ill_formed(const ccf::CoseEndorsement& endorsement)
  {
    return endorsement.endorsement_epoch_end.has_value() &&
      endorsement.endorsement_epoch_end->seqno <
      endorsement.endorsement_epoch_begin.seqno;
  }

  static void validate_fetched_endorsement(
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
          ccf::crypto::COSE_PHEADER_KEY_RANGE_BEGIN));
      }

      const auto to_txid = ccf::TxID::from_str(to);
      if (!to_txid.has_value())
      {
        throw std::logic_error(fmt::format(
          "Cannot parse COSE endorsement header: {}",
          ccf::crypto::COSE_PHEADER_KEY_RANGE_END));
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

  static void validate_chain_integrity(
    const ccf::CoseEndorsement& newer, const ccf::CoseEndorsement& older)
  {
    if (!older.endorsement_epoch_end.has_value())
    {
      throw std::logic_error(fmt::format(
        "COSE endorsement chain integrity is violated, previous endorsement "
        "from {} does not have an epoch end",
        older.endorsement_epoch_begin.to_str()));
    }

    if (
      newer.endorsement_epoch_begin.view - aft::starting_view_change !=
        older.endorsement_epoch_end->view ||
      newer.endorsement_epoch_begin.seqno - 1 !=
        older.endorsement_epoch_end->seqno)
    {
      throw std::logic_error(fmt::format(
        "COSE endorsement chain integrity is violated, previous endorsement "
        "epoch end {} is not chained with newer endorsement epoch begin {}",
        older.endorsement_epoch_end->to_str(),
        newer.endorsement_epoch_begin.to_str()));
    }
  }

  class NetworkIdentitySubsystem : public NetworkIdentitySubsystemInterface
  {
  protected:
    AbstractNodeState& node_state;
    const std::unique_ptr<NetworkIdentity>& network_identity;
    std::shared_ptr<historical::StateCacheImpl> historical_cache;
    std::map<SeqNo, CoseEndorsement> endorsements;
    std::map<SeqNo, ccf::crypto::ECPublicKeyPtr> trusted_keys;
    std::optional<TxID> current_service_from;
    SeqNo earliest_endorsed_seq{0};
    std::atomic<FetchStatus> fetch_status{FetchStatus::Retry};
    bool has_predecessors{false};

  public:
    NetworkIdentitySubsystem(
      AbstractNodeState& node_state_,
      const std::unique_ptr<NetworkIdentity>& network_identity_,
      std::shared_ptr<ccf::historical::StateCacheImpl> historical_cache_) :
      node_state(node_state_),
      network_identity(network_identity_),
      historical_cache(std::move(historical_cache_))
    {
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
      // All other cases must be handled after recovery has been completed and
      // identities have been successfully fetched.
      if (fetch_status.load() != FetchStatus::Done)
      {
        return std::nullopt;
      }

      if (!current_service_from.has_value())
      {
        LOG_FAIL_FMT(
          "Unset current_service_from when fetching endorsements chain");
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
        return {};
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
      if (fetch_status.load() != FetchStatus::Done)
      {
        throw std::logic_error(fmt::format(
          "Trusted key requested for seqno {} but the fetching has "
          "not been completed yet",
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

  private:
    void retry_first_fetch()
    {
      using namespace std::chrono_literals;
      static constexpr auto retry_after = 1s;
      ccf::tasks::add_delayed_task(
        ccf::tasks::make_basic_task([this]() { this->fetch_first(); }),
        retry_after);
    }

    void fail_fetching(const std::string& err = "")
    {
      if (!err.empty())
      {
        LOG_FAIL_FMT("Failed fetching network identity: {}", err);
      }
      fetch_status.store(FetchStatus::Failed);

      // The caller may want to re-capture this, but by default it's supposed to
      // fail the node startup early. This is purely reading, so there's no risk
      // of corruption, but the endorsement chain is essential for the node to
      // produce receipts for the past epochs, which is a must-have
      // functionality.
      throw std::runtime_error("Failed fetching network identity: " + err);
    }

    void complete_fetching()
    {
      if (!current_service_from.has_value())
      {
        fail_fetching("Unset current_service_from when completing fetching");
        return; // to silence clang-tidy unchecked optional
      }

      if (!endorsements.empty())
      {
        auto next = endorsements.begin();
        auto prev = next++;
        try
        {
          while (next != endorsements.end())
          {
            validate_chain_integrity(next->second, prev->second);
            ++prev;
            ++next;
          }
        }
        catch (const std::exception& e)
        {
          fail_fetching(e.what());
        }

        const auto& last = prev->second;
        if (!last.endorsement_epoch_end.has_value())
        {
          fail_fetching(fmt::format(
            "The last fetched endorsement at {} has no epoch end",
            last.endorsement_epoch_begin.seqno));
          return; // to silence clang-tidy unchecked optional
        }

        if (
          current_service_from->view - aft::starting_view_change !=
            last.endorsement_epoch_end->view ||
          current_service_from->seqno - 1 != last.endorsement_epoch_end->seqno)
        {
          fail_fetching(fmt::format(
            "COSE endorsement chain integrity is violated, the current "
            "service start at {} is not chained with previous endorsement "
            "ending at {}",
            current_service_from->to_str(),
            last.endorsement_epoch_end->to_str()));
        }
      }

      try
      {
        build_trusted_key_chain();
      }
      catch (const std::exception& e)
      {
        fail_fetching(e.what());
      }

      fetch_status.store(FetchStatus::Done);
    }

    void fetch_first()
    {
      if (!node_state.is_part_of_network())
      {
        LOG_INFO_FMT(
          "Retry fetching network identity as node is not part of the network "
          "yet");
        retry_first_fetch();
        return;
      }

      auto store = node_state.get_store();
      auto tx = store->create_read_only_tx();

      if (!current_service_from.has_value())
      {
        auto* service_info_handle =
          tx.template ro<ccf::Service>(ccf::Tables::SERVICE);
        auto service_info = service_info_handle->get();
        if (
          !service_info ||
          !service_info->current_service_create_txid.has_value())
        {
          LOG_INFO_FMT(
            "Retrying fetching network identity as current service create txid "
            "is not yet available");
          retry_first_fetch();
          return;
        }

        if (service_info->status != ServiceStatus::OPEN)
        {
          // It can happen that node advances its internal state machine to
          // part-of-network, but the service opening tx has not been replicated
          // yet. This will cause the first fetched endorsement to be obsolete,
          // but waiting for ServiceStatus::OPEN is sufficient, as it's supposed
          // to arrive in the same TX that the previous identity endorsement.
          LOG_INFO_FMT(
            "Retrying fetching network identity as service is not yet open");
          retry_first_fetch();
          return;
        }

        current_service_from = service_info->current_service_create_txid;
      }

      auto* previous_identity_endorsement =
        tx.ro<ccf::PreviousServiceIdentityEndorsement>(
          ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT);

      auto endorsement = previous_identity_endorsement->get();
      if (!endorsement.has_value())
      {
        LOG_INFO_FMT(
          "Retrying fetching network identity as there is no previous service "
          "identity endorsement yet");
        retry_first_fetch();
        return;
      }

      if (is_self_endorsement(endorsement.value()))
      {
        if (
          current_service_from->seqno !=
          endorsement->endorsement_epoch_begin.seqno)
        {
          fail_fetching(fmt::format(
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
        complete_fetching();
        return;
      }

      has_predecessors = true;
      earliest_endorsed_seq = current_service_from->seqno;
      process_endorsement(endorsement.value());
    }

    void process_endorsement(const ccf::CoseEndorsement& endorsement)
    {
      if (is_ill_formed(endorsement))
      {
        // For double-sealed cases, which could have happened in the past. We
        // mark with failed logs, but skip intentionally if there are other
        // endorsements that follow. The overall chain integrity will be checked
        // at the end and will fail anyway if it's not intact.
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
      if (is_self_endorsement(endorsement))
      {
        if (endorsements.find(from) == endorsements.end())
        {
          fail_fetching(fmt::format(
            "Fetched self-endorsement with seqno {} which has not been seen",
            from));
        }
        LOG_INFO_FMT("Got self-endorsement at {}, stopping fetching", from);
        complete_fetching();
        return;
      }

      if (from >= earliest_endorsed_seq)
      {
        fail_fetching(fmt::format(
          "Fetched service endorsement with seqno {} which is greater than "
          "the earliest known in the chain {}",
          from,
          earliest_endorsed_seq));
      }

      if (!endorsement.endorsement_epoch_end.has_value())
      {
        fail_fetching(
          fmt::format("Fetched endorsement at {} has no epoch end", from));
        return; // to silence clang-tidy unchecked optional
      }

      earliest_endorsed_seq = from;
      if (endorsements.find(from) != endorsements.end())
      {
        fail_fetching(fmt::format(
          "Fetched service endorsement with seqno {} which already exists",
          from));
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

      complete_fetching();
    }

    void build_trusted_key_chain()
    {
      if (!current_service_from.has_value())
      {
        throw std::logic_error(
          "Attempting to build trusted key chain but no current service "
          "created seqno fetched");
      }

      std::span<const uint8_t> previous_key{};
      for (const auto& [seqno, endorsement] : endorsements)
      {
        auto verifier =
          ccf::crypto::make_cose_verifier_from_key(endorsement.endorsing_key);
        std::span<uint8_t> endorsed_key;
        if (!verifier->verify(endorsement.endorsement, endorsed_key))
        {
          throw std::logic_error(fmt::format(
            "COSE endorsement chain integrity is violated, endorsement from {} "
            "to {} failed signature verification",
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
          !previous_key.empty() &&
          !std::equal(
            previous_key.begin(),
            previous_key.end(),
            endorsed_key.begin(),
            endorsed_key.end()))
        {
          throw std::logic_error(fmt::format(
            "Endorsement from {} to {} over public key {} doesn't chain with "
            "the previous endorsement with key {}",
            endorsement.endorsement_epoch_begin.seqno,
            format_epoch(endorsement.endorsement_epoch_end),
            ccf::ds::to_hex(endorsed_key),
            ccf::ds::to_hex(previous_key)));
        }

        previous_key = endorsement.endorsing_key;
      }

      const auto& current_pkey =
        network_identity->get_key_pair()->public_key_der();
      if (
        !previous_key.empty() &&
        !std::equal(
          previous_key.begin(),
          previous_key.end(),
          current_pkey.begin(),
          current_pkey.end()))
      {
        throw std::logic_error(fmt::format(
          "Current service identity public key {} does not match the last "
          "endorsing key {}",
          ccf::ds::to_hex(previous_key),
          ccf::ds::to_hex(current_pkey)));
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
      auto state = historical_cache->get_state_at(
        ccf::historical::CompoundHandle{
          ccf::historical::RequestNamespace::System, seq},
        seq);
      if (!state)
      {
        retry_fetch_next(seq);
        return;
      }

      if (!state->store)
      {
        fail_fetching(fmt::format(
          "Fetched historical state with seqno {} with missing store", seq));
      }
      auto htx = state->store->create_read_only_tx();
      const auto endorsement =
        htx
          .template ro<ccf::PreviousServiceIdentityEndorsement>(
            ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
          ->get();

      if (!endorsement.has_value())
      {
        fail_fetching(
          fmt::format("Fetched COSE endorsement for {} is invalid", seq));
        return; // to silence clang-tidy unchecked optional
      }

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

    void retry_fetch_next(ccf::SeqNo seq)
    {
      using namespace std::chrono_literals;
      static constexpr auto retry_after = 100ms;
      ccf::tasks::add_delayed_task(
        ccf::tasks::make_basic_task(
          [this, seq]() { this->fetch_next_at(seq); }),
        retry_after);
    }
  };
}
