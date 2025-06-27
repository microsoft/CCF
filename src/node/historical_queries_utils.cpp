// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/historical_queries_utils.h"

#include "ccf/crypto/cose_verifier.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/service.h"
#include "consensus/aft/raft_types.h"
#include "kv/kv_types.h"
#include "node/identity.h"
#include "node/tx_receipt_impl.h"
#include "service/tables/previous_service_identity.h"

namespace
{
  using Endorsements = std::vector<std::vector<uint8_t>>;
  struct FetchResult
  {
    std::optional<Endorsements> endorsements{std::nullopt};
    bool retry{false};
  };

  std::vector<ccf::CoseEndorsement> cose_endorsements_cache = {};

  bool is_self_endorsement(const ccf::CoseEndorsement& endorsement)
  {
    return !endorsement.previous_version.has_value();
  }

  void validate_fetched_endorsement(
    const std::optional<ccf::CoseEndorsement>& endorsement)
  {
    if (!endorsement)
    {
      throw std::logic_error("Fetched COSE endorsement is invalid");
    }

    if (!is_self_endorsement(*endorsement))
    {
      const auto [from, to] = ccf::crypto::extract_cose_endorsement_validity(
        endorsement->endorsement);

      const auto from_txid = ccf::TxID::from_str(from);
      if (!from_txid)
      {
        throw std::logic_error(fmt::format(
          "Cannot parse COSE endorsement header: {}",
          ccf::crypto::COSE_PHEADER_KEY_RANGE_BEGIN));
      }

      const auto to_txid = ccf::TxID::from_str(to);
      if (!to_txid)
      {
        throw std::logic_error(fmt::format(
          "Cannot parse COSE endorsement header: {}",
          ccf::crypto::COSE_PHEADER_KEY_RANGE_END));
      }

      if (!endorsement->endorsement_epoch_end)
      {
        throw std::logic_error(
          "COSE endorsement doesn't contain epoch end in the table entry");
      }
      if (
        endorsement->endorsement_epoch_begin != *from_txid ||
        *endorsement->endorsement_epoch_end != *to_txid)
      {
        throw std::logic_error(fmt ::format(
          "COSE endorsement fetched but range is invalid, epoch begin {}, "
          "epoch end {}, header epoch begin: {}, header epoch end: {}",
          endorsement->endorsement_epoch_begin.to_str(),
          endorsement->endorsement_epoch_end->to_str(),
          from,
          to));
      }
    }
  }

  void validate_chain_integrity(
    const ccf::CoseEndorsement& newer, const ccf::CoseEndorsement& older)
  {
    if (
      !is_self_endorsement(older) && (
      older.endorsement_epoch_end.has_value() &&
      (newer.endorsement_epoch_begin.view - aft::starting_view_change !=
         older.endorsement_epoch_end->view ||
       newer.endorsement_epoch_begin.seqno - 1 !=
         older.endorsement_epoch_end->seqno)))
    {
      throw std::logic_error(fmt::format(
        "COSE endorsement chain integrity is violated, previous endorsement "
        "epoch end {} is not chained with newer endorsement epoch begin {}",
        older.endorsement_epoch_end->to_str(),
        newer.endorsement_epoch_begin.to_str()));
    }
  }

  void ensure_first_fetch(ccf::kv::ReadOnlyTx& tx)
  {
    if (cose_endorsements_cache.empty()) [[unlikely]]
    {
      const auto endorsement =
        tx.template ro<ccf::PreviousServiceIdentityEndorsement>(
            ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
          ->get();
      validate_fetched_endorsement(endorsement);
      // NOLINTBEGIN(bugprone-unchecked-optional-access)
      // Checked by the validate call above
      cose_endorsements_cache.push_back(*endorsement);
      // NOLINTEND(bugprone-unchecked-optional-access)
    }
  }

  bool keep_fetching(ccf::SeqNo target_seq)
  {
    return !is_self_endorsement(cose_endorsements_cache.back()) &&
      cose_endorsements_cache.back().endorsement_epoch_begin.seqno > target_seq;
  }

  FetchResult fetch_endorsements_for(
    ccf::kv::ReadOnlyTx& tx,
    ccf::historical::AbstractStateCache& state_cache,
    ccf::SeqNo target_seq)
  {
    ensure_first_fetch(tx);

    while (keep_fetching(target_seq))
    {
      const auto prev_endorsement_seqno =
        cose_endorsements_cache.back().previous_version.value();
      const auto hstate = state_cache.get_state_at(
        prev_endorsement_seqno, prev_endorsement_seqno);

      if (!hstate)
      {
        return {.endorsements = std::nullopt, .retry = true};
      }

      auto htx = hstate->store->create_read_only_tx();
      const auto endorsement =
        htx
          .template ro<ccf::PreviousServiceIdentityEndorsement>(
            ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
          ->get();

      validate_fetched_endorsement(endorsement);
      validate_chain_integrity(
        cose_endorsements_cache.back(), endorsement.value());
      cose_endorsements_cache.push_back(*endorsement);
    }

    if (cose_endorsements_cache.size() == 1)
    {
      LOG_TRACE_FMT(
        "Only current service self-endorsement was found, no historical TXs "
        "for previous epochs were COSE-endorsed.");
      return {.endorsements = std::nullopt, .retry = false};
    }

    auto last_valid_endorsement = cose_endorsements_cache.end() - 1;
    if (is_self_endorsement(*last_valid_endorsement))
    {
      --last_valid_endorsement;
    }

    const auto search_to = last_valid_endorsement + 1;

    if (last_valid_endorsement->endorsement_epoch_begin.seqno > target_seq)
    {
      LOG_TRACE_FMT(
        "COSE-endorsements are fetched for newer epochs, but target_seq {} is "
        "far behind and was never endorsed.",
        target_seq);

      return {.endorsements = std::nullopt, .retry = false};
    }

    const auto final_endorsement = std::upper_bound(
      cose_endorsements_cache.begin(),
      search_to,
      target_seq,
      [](const auto& seq, const auto& endorsement) {
        return endorsement.endorsement_epoch_begin.seqno <= seq;
      });

    if (final_endorsement == search_to)
    {
      throw std::logic_error(fmt::format(
        "Error during COSE endorsement chain reconstruction for seqno {}",
        target_seq));
    }

    Endorsements endorsements;

    std::transform(
      cose_endorsements_cache.begin(),
      final_endorsement + 1, // Inclusive
      std::back_inserter(endorsements),
      [](const auto& e) { return e.endorsement; });

    return {.endorsements = std::move(endorsements), .retry = false};
  }
}

namespace ccf
{
  static std::map<ccf::crypto::Pem, std::vector<ccf::crypto::Pem>>
    service_endorsement_cache;

  namespace historical
  {
    std::optional<ServiceInfo> find_previous_service_identity(
      ccf::kv::ReadOnlyTx& tx,
      ccf::historical::StatePtr& state,
      AbstractStateCache& state_cache)
    {
      SeqNo target_seqno = state->transaction_id.seqno;

      // We start at the previous write to the latest (current) service info.
      auto service = tx.template ro<Service>(Tables::SERVICE);

      // Iterate until we find the most recent write to the service info that
      // precedes the target seqno.
      std::optional<ServiceInfo> hservice_info = service->get();
      SeqNo i = -1;
      do
      {
        if (!hservice_info->previous_service_identity_version)
        {
          // Pre 2.0 we did not record the versions of previous identities in
          // the service table.
          throw std::runtime_error(
            "The service identity that signed the receipt cannot be found "
            "because it is in a pre-2.0 part of the ledger.");
        }
        i = hservice_info->previous_service_identity_version.value_or(i - 1);
        LOG_TRACE_FMT("historical service identity search at: {}", i);
        auto hstate = state_cache.get_state_at(i, i);
        if (!hstate)
        {
          return std::nullopt; // Not available yet - retry later.
        }
        auto htx = hstate->store->create_read_only_tx();
        auto * hservice = htx.ro<Service>(Tables::SERVICE);
        hservice_info = hservice->get();
      } while (i > target_seqno || (i > 1 && !hservice_info));

      if (!hservice_info)
      {
        throw std::runtime_error("Failed to locate previous service identity");
      }

      return hservice_info;
    }

    bool populate_service_endorsements(
      ccf::kv::ReadOnlyTx& tx,
      ccf::historical::StatePtr& state,
      AbstractStateCache& state_cache,
      std::shared_ptr<NetworkIdentitySubsystemInterface>
        network_identity_subsystem)
    {
      try
      {
        if (!network_identity_subsystem)
        {
          throw std::runtime_error(
            "The service identity endorsement for this receipt cannot be "
            "created "
            "because the current network identity is not available.");
        }

        const auto& network_identity = network_identity_subsystem->get();

        if (state && state->receipt && state->receipt->node_cert)
        {
          auto& receipt = *state->receipt;

          if (receipt.node_cert->empty())
          {
            // Pre 2.0 receipts did not contain node certs.
            throw std::runtime_error(
              "Node certificate in receipt is empty, likely because the "
              "transaction is in a pre-2.0 part of the ledger.");
          }

          auto v = ccf::crypto::make_unique_verifier(*receipt.node_cert);
          if (!v->verify_certificate(
                {&network_identity->cert}, {}, /* ignore_time */ true))
          {
            // The current service identity does not endorse the node
            // certificate in the receipt, so we search for the the most
            // recent write to the service info table before the historical
            // transaction ID to get the historical service identity.

            auto opt_psi =
              find_previous_service_identity(tx, state, state_cache);
            if (!opt_psi)
            {
              return false;
            }

            auto hpubkey = ccf::crypto::public_key_pem_from_cert(
              ccf::crypto::cert_pem_to_der(opt_psi->cert));

            auto eit = service_endorsement_cache.find(hpubkey);
            if (eit != service_endorsement_cache.end())
            {
              // Note: validity period of service certificate may have changed
              // since we created the cached endorsements.
              receipt.service_endorsements = eit->second;
            }
            else
            {
              auto ncv =
                ccf::crypto::make_unique_verifier(network_identity->cert);
              auto endorsement = create_endorsed_cert(
                hpubkey,
                ccf::crypto::get_subject_name(opt_psi->cert),
                {},
                ncv->validity_period(),
                network_identity->priv_key,
                network_identity->cert,
                true /* CA */);
              service_endorsement_cache[hpubkey] = {endorsement};
              receipt.service_endorsements = {endorsement};
            }
          }
        }
      }
      catch (std::exception& ex)
      {
        LOG_DEBUG_FMT(
          "Exception while extracting previous service identities: {}",
          ex.what());
        // (We keep the incomplete receipt, no further error reporting)
      }

      return true;
    }

    bool populate_cose_service_endorsements(
      ccf::kv::ReadOnlyTx& tx,
      ccf::historical::StatePtr& state,
      AbstractStateCache& state_cache)
    {
      const auto service_info = tx.template ro<Service>(Tables::SERVICE)->get();
      const auto service_start = service_info->current_service_create_txid;
      if (!service_start)
      {
        throw std::logic_error(
          "COSE endorsements fetch: current service create_txid not available");
      }

      const auto target_seq = state->transaction_id.seqno;
      if (service_start->seqno <= target_seq)
      {
        LOG_TRACE_FMT(
          "Target seqno {} belongs to current service started at {}",
          target_seq,
          service_start->seqno);
        return true;
      }

      const auto result =
        fetch_endorsements_for(tx, state_cache, state->transaction_id.seqno);
      if (!result.endorsements)
      {
        const bool final_result = !result.retry;
        return final_result;
      }

      state->receipt->cose_endorsements = result.endorsements.value();
      return true;
    }
  }
}