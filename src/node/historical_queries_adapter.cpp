// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/historical_queries_adapter.h"

#include "ccf/rpc_context.h"
#include "ccf/service/tables/service.h"
#include "kv/kv_types.h"
#include "node/rpc/network_identity_subsystem.h"
#include "node/tx_receipt_impl.h"

namespace ccf
{
  static std::map<crypto::Pem, std::vector<crypto::Pem>>
    service_endorsement_cache;

  nlohmann::json describe_receipt_v1(const TxReceiptImpl& receipt)
  {
    // Legacy JSON format, retained for compatibility
    nlohmann::json out = nlohmann::json::object();

    out["signature"] = crypto::b64_from_raw(receipt.signature);

    auto proof = nlohmann::json::array();
    if (receipt.path != nullptr)
    {
      for (const auto& node : *receipt.path)
      {
        auto n = nlohmann::json::object();
        if (node.direction == ccf::HistoryTree::Path::Direction::PATH_LEFT)
        {
          n["left"] = node.hash.to_string();
        }
        else
        {
          n["right"] = node.hash.to_string();
        }
        proof.emplace_back(std::move(n));
      }
    }
    out["proof"] = proof;

    out["node_id"] = receipt.node_id;

    if (receipt.node_cert.has_value())
    {
      out["cert"] = receipt.node_cert->str();
    }

    if (receipt.path == nullptr)
    {
      // Signature transaction
      out["leaf"] = receipt.root.to_string();
    }
    else if (!receipt.commit_evidence.has_value())
    {
      out["leaf"] = receipt.write_set_digest->hex_str();
    }
    else
    {
      auto leaf_components = nlohmann::json::object();
      if (receipt.write_set_digest.has_value())
      {
        leaf_components["write_set_digest"] =
          receipt.write_set_digest->hex_str();
      }

      if (receipt.commit_evidence.has_value())
      {
        leaf_components["commit_evidence"] = receipt.commit_evidence.value();
      }

      if (!receipt.claims_digest.empty())
      {
        leaf_components["claims_digest"] =
          receipt.claims_digest.value().hex_str();
      }
      out["leaf_components"] = leaf_components;
    }

    if (receipt.service_endorsements.has_value())
    {
      out["service_endorsements"] = receipt.service_endorsements;
    }

    return out;
  }

  ccf::ReceiptPtr describe_receipt_v2(const TxReceiptImpl& in)
  {
    ccf::ReceiptPtr receipt = nullptr;

    if (in.path != nullptr && in.commit_evidence.has_value())
    {
      auto proof_receipt = std::make_shared<ProofReceipt>();

      proof_receipt->proof.reserve(in.path->size());
      for (const auto& node : *in.path)
      {
        const auto direction =
          node.direction == ccf::HistoryTree::Path::Direction::PATH_LEFT ?
          ccf::ProofReceipt::ProofStep::Left :
          ccf::ProofReceipt::ProofStep::Right;
        const auto hash = crypto::Sha256Hash::from_span(
          std::span<const uint8_t, ccf::ClaimsDigest::Digest::SIZE>(
            node.hash.bytes, sizeof(node.hash.bytes)));
        proof_receipt->proof.push_back({direction, hash});
      }

      if (in.write_set_digest.has_value())
      {
        proof_receipt->leaf_components.write_set_digest =
          in.write_set_digest.value();
      }

      if (in.commit_evidence.has_value())
      {
        proof_receipt->leaf_components.commit_evidence =
          in.commit_evidence.value();
      }

      if (!in.claims_digest.empty())
      {
        proof_receipt->leaf_components.claims_digest = in.claims_digest;
      }

      receipt = proof_receipt;
    }
    else
    {
      // Signature transaction
      auto sig_receipt = std::make_shared<SignatureReceipt>();
      sig_receipt->signed_root = crypto::Sha256Hash::from_span(
        std::span<const uint8_t, ccf::ClaimsDigest::Digest::SIZE>(
          in.root.bytes, sizeof(in.root.bytes)));

      receipt = sig_receipt;
    }

    auto& out = *receipt;

    out.signature = in.signature;

    out.node_id = in.node_id;

    if (in.node_cert.has_value())
    {
      out.cert = in.node_cert.value();
    }

    if (in.service_endorsements.has_value())
    {
      out.service_endorsements = in.service_endorsements.value();
    }

    return receipt;
  }
}

namespace ccf::historical
{
  std::optional<ccf::TxID> txid_from_header(endpoints::EndpointContext& args)
  {
    const auto tx_id_header =
      args.rpc_ctx->get_request_header(http::headers::CCF_TX_ID);
    if (!tx_id_header.has_value())
    {
      args.rpc_ctx->set_error(
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::MissingRequiredHeader,
        fmt::format(
          "Historical query is missing '{}' header.",
          http::headers::CCF_TX_ID));
      return std::nullopt;
    }

    const auto tx_id_opt = ccf::TxID::from_str(tx_id_header.value());
    if (!tx_id_opt.has_value())
    {
      args.rpc_ctx->set_error(
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::InvalidHeaderValue,
        fmt::format(
          "The value '{}' in header '{}' could not be converted to a valid "
          "Tx ID.",
          tx_id_header.value(),
          http::headers::CCF_TX_ID));
      return std::nullopt;
    }

    return tx_id_opt;
  }

  bool is_tx_committed_v1(
    kv::Consensus* consensus,
    ccf::View view,
    ccf::SeqNo seqno,
    std::string& error_reason)
  {
    if (consensus == nullptr)
    {
      error_reason = "Node is not fully configured";
      return false;
    }

    const auto tx_view = consensus->get_view(seqno);
    const auto committed_seqno = consensus->get_committed_seqno();
    const auto committed_view = consensus->get_view(committed_seqno);

    const auto tx_status = ccf::evaluate_tx_status(
      view, seqno, tx_view, committed_view, committed_seqno);
    if (tx_status != ccf::TxStatus::Committed)
    {
      error_reason = fmt::format(
        "Only committed transactions can be queried. Transaction {}.{} "
        "is "
        "{}",
        view,
        seqno,
        ccf::tx_status_to_str(tx_status));
      return false;
    }

    return true;
  }

  HistoricalTxStatus is_tx_committed_v2(
    kv::Consensus* consensus,
    ccf::View view,
    ccf::SeqNo seqno,
    std::string& error_reason)
  {
    if (consensus == nullptr)
    {
      error_reason = "Node is not fully configured";
      return HistoricalTxStatus::Error;
    }

    const auto tx_view = consensus->get_view(seqno);
    const auto committed_seqno = consensus->get_committed_seqno();
    const auto committed_view = consensus->get_view(committed_seqno);

    const auto tx_status = ccf::evaluate_tx_status(
      view, seqno, tx_view, committed_view, committed_seqno);
    switch (tx_status)
    {
      case ccf::TxStatus::Unknown:
      case ccf::TxStatus::Pending:
        error_reason = fmt::format(
          "Only committed transactions can be queried. Transaction {}.{} "
          "is "
          "{}",
          view,
          seqno,
          ccf::tx_status_to_str(tx_status));
        return HistoricalTxStatus::PendingOrUnknown;
      case ccf::TxStatus::Invalid:
        error_reason = fmt::format(
          "Only committed transactions can be queried. Transaction {}.{} "
          "is "
          "{}",
          view,
          seqno,
          ccf::tx_status_to_str(tx_status));
        return HistoricalTxStatus::Invalid;
      case ccf::TxStatus::Committed:;
    }

    return HistoricalTxStatus::Valid;
  }

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

  ccf::endpoints::EndpointFunction adapter_v3(
    const HandleHistoricalQuery& f,
    ccfapp::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor)
  {
    auto& state_cache = node_context.get_historical_state();
    auto network_identity_subsystem =
      node_context.get_subsystem<NetworkIdentitySubsystemInterface>();

    return [f, &state_cache, network_identity_subsystem, available, extractor](
             endpoints::EndpointContext& args) {
      // Extract the requested transaction ID
      ccf::TxID target_tx_id;
      {
        const auto tx_id_opt = extractor(args);
        if (tx_id_opt.has_value())
        {
          target_tx_id = tx_id_opt.value();
        }
        else
        {
          return;
        }
      }

      // Check that the requested transaction ID is available
      {
        auto error_reason = fmt::format(
          "Transaction {} is not available.", target_tx_id.to_str());
        auto is_available =
          available(target_tx_id.view, target_tx_id.seqno, error_reason);
        switch (is_available)
        {
          case HistoricalTxStatus::Error:
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::TransactionPendingOrUnknown,
              std::move(error_reason));
            return;
          }
          case HistoricalTxStatus::PendingOrUnknown:
          {
            // Set header No-Cache
            args.rpc_ctx->set_response_header(
              http::headers::CACHE_CONTROL, "no-cache");
            args.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::TransactionPendingOrUnknown,
              std::move(error_reason));
            return;
          }
          case HistoricalTxStatus::Invalid:
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::TransactionInvalid,
              std::move(error_reason));
            return;
          }
          case HistoricalTxStatus::Valid:
          {
          }
        }
      }

      // We need a handle to determine whether this request is the 'same' as a
      // previous one. For simplicity we use target_tx_id.seqno. This means we
      // keep a lot of state around for old requests! It should be cleaned up
      // manually
      const auto historic_request_handle = target_tx_id.seqno;

      // Get a state at the target version from the cache, if it is present
      auto historical_state =
        state_cache.get_state_at(historic_request_handle, target_tx_id.seqno);
      if (
        historical_state == nullptr ||
        (!get_service_endorsements(
          args, historical_state, state_cache, network_identity_subsystem)))
      {
        args.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
        constexpr size_t retry_after_seconds = 3;
        args.rpc_ctx->set_response_header(
          http::headers::RETRY_AFTER, retry_after_seconds);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(fmt::format(
          "Historical transaction {} is not currently available.",
          target_tx_id.to_str()));
        return;
      }

      // Call the provided handler
      f(args, historical_state);
    };
  }

  ccf::endpoints::EndpointFunction adapter_v2(
    const HandleHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor)
  {
    return [f, &state_cache, available, extractor](
             endpoints::EndpointContext& args) {
      // Extract the requested transaction ID
      ccf::TxID target_tx_id;
      {
        const auto tx_id_opt = extractor(args);
        if (tx_id_opt.has_value())
        {
          target_tx_id = tx_id_opt.value();
        }
        else
        {
          return;
        }
      }

      // Check that the requested transaction ID is available
      {
        auto error_reason = fmt::format(
          "Transaction {} is not available.", target_tx_id.to_str());
        auto is_available =
          available(target_tx_id.view, target_tx_id.seqno, error_reason);
        switch (is_available)
        {
          case HistoricalTxStatus::Error:
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::TransactionPendingOrUnknown,
              std::move(error_reason));
            return;
          }
          case HistoricalTxStatus::PendingOrUnknown:
          {
            // Set header No-Cache
            args.rpc_ctx->set_response_header(
              http::headers::CACHE_CONTROL, "no-cache");
            args.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::TransactionPendingOrUnknown,
              std::move(error_reason));
            return;
          }
          case HistoricalTxStatus::Invalid:
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::TransactionInvalid,
              std::move(error_reason));
            return;
          }
          case HistoricalTxStatus::Valid:
          {
          }
        }
      }

      // We need a handle to determine whether this request is the 'same' as a
      // previous one. For simplicity we use target_tx_id.seqno. This means we
      // keep a lot of state around for old requests! It should be cleaned up
      // manually
      const auto historic_request_handle = target_tx_id.seqno;

      // Get a state at the target version from the cache, if it is present
      auto historical_state =
        state_cache.get_state_at(historic_request_handle, target_tx_id.seqno);
      if (historical_state == nullptr)
      {
        args.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
        constexpr size_t retry_after_seconds = 3;
        args.rpc_ctx->set_response_header(
          http::headers::RETRY_AFTER, retry_after_seconds);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(fmt::format(
          "Historical transaction {} is not currently available.",
          target_tx_id.to_str()));
        return;
      }

      // Call the provided handler
      f(args, historical_state);
    };
  }

  ccf::endpoints::EndpointFunction adapter_v1(
    const HandleHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckAvailability& available,
    const TxIDExtractor& extractor)
  {
    return [f, &state_cache, available, extractor](
             endpoints::EndpointContext& args) {
      // Extract the requested transaction ID
      ccf::TxID target_tx_id;
      {
        const auto tx_id_opt = extractor(args);
        if (tx_id_opt.has_value())
        {
          target_tx_id = tx_id_opt.value();
        }
        else
        {
          return;
        }
      }

      // Check that the requested transaction ID is available
      {
        auto error_reason = fmt::format(
          "Transaction {} is not available.", target_tx_id.to_str());
        if (!available(target_tx_id.view, target_tx_id.seqno, error_reason))
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::TransactionNotFound,
            std::move(error_reason));
          return;
        }
      }

      // We need a handle to determine whether this request is the 'same' as a
      // previous one. For simplicity we use target_tx_id.seqno. This means we
      // keep a lot of state around for old requests! It should be cleaned up
      // manually
      const auto historic_request_handle = target_tx_id.seqno;

      // Get a state at the target version from the cache, if it is present
      auto historical_state =
        state_cache.get_state_at(historic_request_handle, target_tx_id.seqno);
      if (historical_state == nullptr)
      {
        args.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
        constexpr size_t retry_after_seconds = 3;
        args.rpc_ctx->set_response_header(
          http::headers::RETRY_AFTER, retry_after_seconds);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(fmt::format(
          "Historical transaction {} is not currently available.",
          target_tx_id.to_str()));
        return;
      }

      // Call the provided handler
      f(args, historical_state);
    };
  }

  ccf::endpoints::EndpointFunction adapter(
    const HandleHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckAvailability& available,
    const TxIDExtractor& extractor)
  {
    return adapter_v1(f, state_cache, available, extractor);
  }

  bool is_tx_committed(
    kv::Consensus* consensus,
    ccf::View view,
    ccf::SeqNo seqno,
    std::string& error_reason)
  {
    return is_tx_committed_v1(consensus, view, seqno, error_reason);
  }
}