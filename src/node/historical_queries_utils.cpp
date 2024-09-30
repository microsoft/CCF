// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/historical_queries_utils.h"

#include "ccf/rpc_context.h"
#include "ccf/service/tables/service.h"
#include "kv/kv_types.h"
#include "node/identity.h"
#include "node/tx_receipt_impl.h"
#include "service/tables/previous_service_identity.h"

namespace ccf
{
  static std::map<ccf::crypto::Pem, std::vector<ccf::crypto::Pem>>
    service_endorsement_cache;

  // valid_from -> [valid_to, endorsement]
  static std::map<ccf::SeqNo, std::pair<ccf::SeqNo, std::vector<uint8_t>>>
    cose_endorsements;

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
        auto hservice = htx.ro<Service>(Tables::SERVICE);
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
            // certificate in the receipt, so we search for the the most recent
            // write to the service info table before the historical transaction
            // ID to get the historical service identity.

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
        // TO DO log err
        return true;
      }

      const auto target_seq = state->transaction_id.seqno;
      if (service_start->seqno <= target_seq)
      {
        return true;
      }

      const auto prev_id_seq = service_info->previous_service_identity_version;
      if (!prev_id_seq)
      {
        // TO DO log err
        return true;
      }

      if (cose_endorsements.empty())
      {
        const auto endorsement =
          tx.template ro<PreviousServiceIdentityEndorsement>(
              Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
            ->get();
        CCF_ASSERT(endorsement.has_value, "Endorsed identity not found");

        cose_endorsements.insert({*prev_id_seq, {target_seq, *endorsement}});
      }

      while (cose_endorsements.begin()->first > target_seq)
      {
        auto earlist_seqno = cose_endorsements.begin()->first;
        auto hstate = state_cache.get_state_at(earlist_seqno, earlist_seqno);
        if (!hstate)
        {
          return false; // retry later
        }
        auto htx = hstate->store->create_read_only_tx();
        const auto prev_service_info =
          htx.template ro<Service>(Tables::SERVICE)->get();

        if (!prev_service_info->previous_service_identity_version)
        {
          // TO DO log err
          return true;
        }
        const auto endorsement =
          htx
            .template ro<PreviousServiceIdentityEndorsement>(
              Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
            ->get();

        if (!endorsement)
        {
          // TO DO log err: cose endorsement not present there
          return true;
        }

        cose_endorsements.insert(
          {prev_service_info->previous_service_identity_version.value(),
           {earlist_seqno, *endorsement}});
      }

      auto it = cose_endorsements.find(target_seq);
      if (it->first != target_seq)
      {
        --it;
      }
      // TO DO check it

      std::vector<std::vector<uint8_t>> endorsements;
      for (it; it != cose_endorsements.end(); ++it)
      {
        endorsements.push_back(it->second.second);
      }

      state->receipt->cose_endorsements = endorsements;
      return true;
    }
  }
}