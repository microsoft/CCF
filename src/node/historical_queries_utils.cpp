// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/historical_queries_utils.h"

#include "ccf/crypto/cose_verifier.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/service.h"
#include "consensus/aft/raft_types.h"
#include "kv/kv_types.h"
#include "node/cose_common.h"
#include "node/historical_queries.h"
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

  ccf::historical::CompoundHandle make_system_handle(ccf::SeqNo seq)
  {
    return ccf::historical::CompoundHandle{
      ccf::historical::RequestNamespace::System, seq};
  }
}

namespace ccf
{
  namespace
  {
    std::map<ccf::crypto::Pem, std::vector<ccf::crypto::Pem>>
      service_endorsement_cache;
  }

  namespace historical
  {
    std::optional<ServiceInfo> find_previous_service_identity(
      ccf::kv::ReadOnlyTx& tx,
      ccf::historical::StatePtr& state,
      AbstractStateCache& state_cache)
    {
      SeqNo target_seqno = state->transaction_id.seqno;

      // We start at the previous write to the latest (current) service info.
      auto* service = tx.template ro<Service>(Tables::SERVICE);

      // Iterate until we find the most recent write to the service info that
      // precedes the target seqno.
      std::optional<ServiceInfo> hservice_info = service->get();
      SeqNo i = -1;

      do
      {
        if (!hservice_info)
        {
          throw std::runtime_error("Failed to locate service identity");
        }

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

        const auto system_handle = make_system_handle(i);
        auto* cache_impl =
          dynamic_cast<ccf::historical::StateCacheImpl*>(&state_cache);
        if (cache_impl == nullptr)
        {
          throw std::logic_error(
            "StateCacheImpl required to access cache as "
            "RequestNamespace::System");
        }

        auto hstate = cache_impl->get_state_at(system_handle, i);
        if (!hstate)
        {
          return std::nullopt; // Not available yet - retry later.
        }

        auto htx = hstate->store->create_read_only_tx();
        auto* hservice = htx.ro<Service>(Tables::SERVICE);
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

        if (state && state->receipt)
        {
          auto& receipt = state->receipt;
          auto& node_cert = receipt->node_cert;

          if (node_cert.has_value())
          {
            if (node_cert->empty())
            {
              // Pre 2.0 receipts did not contain node certs.
              throw std::runtime_error(
                "Node certificate in receipt is empty, likely because the "
                "transaction is in a pre-2.0 part of the ledger.");
            }

            auto v = ccf::crypto::make_unique_verifier(node_cert.value());
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
                receipt->service_endorsements = eit->second;
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
                receipt->service_endorsements = {endorsement};
              }
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
      std::shared_ptr<NetworkIdentitySubsystemInterface>
        network_identity_subsystem)
    {
      auto* service = tx.template ro<Service>(Tables::SERVICE);
      auto hservice_info = service->get();
      if (!hservice_info)
      {
        throw std::runtime_error("Failed to locate service identity");
      }
      if (!hservice_info->current_service_create_txid)
      {
        throw std::runtime_error(
          "The service identity is missing 'current_service_create_txid'");
      }

      if (
        state->transaction_id.seqno >=
        hservice_info->current_service_create_txid->seqno)
      {
        // This is handled by the network identity subsystem, but to test
        // mid-recovery receipts for the current service identity we set empty
        // chain as a valid chain early on.
        return true;
      }

      const auto fetching =
        network_identity_subsystem->endorsements_fetching_status();
      if (fetching == FetchStatus::Retry)
      {
        return false;
      }
      if (fetching == FetchStatus::Failed)
      {
        throw std::runtime_error(fmt::format(
          "The service identity endorsement for the receipt at seqno {} "
          "cannot be fetched",
          state->transaction_id.seqno));
      }
      if (fetching != FetchStatus::Done)
      {
        throw std::logic_error("Unexpected endorsements fetching status");
      }

      auto cose_endorsements =
        network_identity_subsystem->get_cose_endorsements_chain(
          state->transaction_id.seqno);
      state->receipt->cose_endorsements = cose_endorsements;
      return true;
    }

    void verify_self_issued_receipt(
      const std::vector<uint8_t>& cose_receipt,
      std::shared_ptr<NetworkIdentitySubsystemInterface>
        network_identity_subsystem)
    {
      auto receipt =
        cose::decode_ccf_receipt(cose_receipt, /* recompute_root */ true);

      const auto tx_id = ccf::TxID::from_str(receipt.phdr.ccf.txid);
      if (!tx_id.has_value())
      {
        throw std::logic_error(fmt::format(
          "Failed to convert txid {} to ccf::TxID", receipt.phdr.ccf.txid));
      }

      const auto trusted_key =
        network_identity_subsystem->get_trusted_identity_for(tx_id->seqno);
      if (!trusted_key)
      {
        throw std::logic_error(fmt::format(
          "Verifying receipt for seqno {} failed due to trusted key absence",
          tx_id->seqno));
      }

      const auto verifier =
        ccf::crypto::make_cose_verifier_from_key(trusted_key->public_key_pem());
      if (!verifier->verify_detached(cose_receipt, receipt.merkle_root))
      {
        throw ccf::cose::COSESignatureValidationError(
          "COSE receipt signature verification failed");
      }
    }
  }
}
