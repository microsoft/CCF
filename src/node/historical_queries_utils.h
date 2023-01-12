// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

//#include "ccf/historical_queries_adapter.h"

#include "ccf/rpc_context.h"
#include "ccf/service/tables/service.h"
#include "kv/kv_types.h"
#include "node/rpc/network_identity_subsystem.h"
#include "node/tx_receipt_impl.h"

namespace ccf
{
  static std::map<crypto::Pem, std::vector<crypto::Pem>>
    service_endorsement_cache;
}

namespace ccf::historical
{
  std::optional<ServiceInfo> find_previous_service_identity(
    auto& ctx,
    ccf::historical::StatePtr& state,
    AbstractStateCache& state_cache)
  {
    SeqNo target_seqno = state->transaction_id.seqno;

    // We start at the previous write to the latest (current) service info.
    auto service = ctx.tx.template ro<Service>(Tables::SERVICE);

    // Iterate until we find the most recent write to the service info that
    // precedes the target seqno.
    std::optional<ServiceInfo> hservice_info = service->get();
    SeqNo i = -1;
    do
    {
      if (!hservice_info->previous_service_identity_version)
      {
        // Pre 2.0 we did not record the versions of previous identities in the
        // service table.
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

  bool get_service_endorsements(
    auto& ctx,
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
          "The service identity endorsement for this receipt cannot be created "
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

        auto v = crypto::make_unique_verifier(*receipt.node_cert);
        if (!v->verify_certificate(
              {&network_identity->cert}, {}, /* ignore_time */ true))
        {
          // The current service identity does not endorse the node certificate
          // in the receipt, so we search for the the most recent write to the
          // service info table before the historical transaction ID to get the
          // historical service identity.

          auto opt_psi =
            find_previous_service_identity(ctx, state, state_cache);
          if (!opt_psi)
          {
            return false;
          }

          auto hpubkey = crypto::public_key_pem_from_cert(
            crypto::cert_pem_to_der(opt_psi->cert));

          auto eit = service_endorsement_cache.find(hpubkey);
          if (eit != service_endorsement_cache.end())
          {
            // Note: validity period of service certificate may have changed
            // since we created the cached endorsements.
            receipt.service_endorsements = eit->second;
          }
          else
          {
            auto ncv = crypto::make_unique_verifier(network_identity->cert);
            auto endorsement = create_endorsed_cert(
              hpubkey,
              ReplicatedNetworkIdentity::subject_name,
              {},
              ncv->validity_period(),
              network_identity->priv_key,
              network_identity->cert,
              true);
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
}