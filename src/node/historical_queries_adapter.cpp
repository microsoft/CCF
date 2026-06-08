// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/historical_queries_adapter.h"

#include "ccf/historical_queries_utils.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/service.h"
#include "kv/kv_types.h"
#include "node/rpc/network_identity_subsystem.h"
#include "node/tx_receipt_impl.h"

#include <t_cose/t_cose_sign1_sign.h>

namespace
{
  void encode_leaf_cbor(
    QCBOREncodeContext& ctx, const ccf::TxReceiptImpl& receipt)
  {
    QCBOREncode_OpenArrayInMapN(
      &ctx, ccf::MerkleProofLabel::MERKLE_PROOF_LEAF_LABEL);

    // 1 WSD
    if (!receipt.write_set_digest.has_value())
    {
      throw std::logic_error("Write set digest is required for COSE receipts");
    }
    const auto& wsd = receipt.write_set_digest->h;
    QCBOREncode_AddBytes(&ctx, {wsd.data(), wsd.size()});

    // 2. CE
    if (!receipt.commit_evidence.has_value())
    {
      throw std::logic_error("Commit evidence is required for COSE receipts");
    }
    const auto& ce = receipt.commit_evidence.value();
    QCBOREncode_AddSZString(&ctx, ce.data());

    // 3. CD
    const auto& cd = receipt.claims_digest.value().h;
    QCBOREncode_AddBytes(&ctx, {cd.data(), cd.size()});

    QCBOREncode_CloseArray(&ctx);
  }

  void encode_path_cbor(
    QCBOREncodeContext& ctx, const ccf::HistoryTree::Path& path)
  {
    QCBOREncode_OpenArrayInMapN(
      &ctx, ccf::MerkleProofLabel::MERKLE_PROOF_PATH_LABEL);
    for (const auto& node : path)
    {
      const bool dir =
        (node.direction == ccf::HistoryTree::Path::Direction::PATH_LEFT);
      std::vector<uint8_t> hash{node.hash};

      QCBOREncode_OpenArray(&ctx);
      QCBOREncode_AddBool(&ctx, dir);
      QCBOREncode_AddBytes(&ctx, {hash.data(), hash.size()});
      QCBOREncode_CloseArray(&ctx);
    }
    QCBOREncode_CloseArray(&ctx);
  }
}

namespace ccf
{
  nlohmann::json describe_receipt_v1(const TxReceiptImpl& receipt)
  {
    // Legacy JSON format, retained for compatibility
    nlohmann::json out = nlohmann::json::object();

    out["signature"] = ccf::crypto::b64_from_raw(receipt.signature);

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
      if (receipt.write_set_digest.has_value())
      {
        out["leaf"] = receipt.write_set_digest->hex_str();
      }
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
        const auto hash = ccf::crypto::Sha256Hash::from_span(
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
      sig_receipt->signed_root = ccf::crypto::Sha256Hash::from_span(
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

  std::optional<std::vector<uint8_t>> describe_merkle_proof_v1(
    const TxReceiptImpl& receipt)
  {
    constexpr size_t buf_size = 2048; // TBD: calculate why this is enough
    std::vector<uint8_t> underlying_buffer(buf_size);
    UsefulBuf buffer{underlying_buffer.data(), underlying_buffer.size()};
    assert(buffer.len == buf_size);

    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, buffer);

    QCBOREncode_OpenMap(&ctx);

    if (!receipt.commit_evidence)
    {
      LOG_DEBUG_FMT("Merkle proof is missing commit evidence");
      return std::nullopt;
    }
    if (!receipt.write_set_digest)
    {
      LOG_DEBUG_FMT("Merkle proof is missing write set digest");
      return std::nullopt;
    }
    encode_leaf_cbor(ctx, receipt);

    if (!receipt.path)
    {
      LOG_DEBUG_FMT("Merkle proof is missing path");
      return std::nullopt;
    }
    encode_path_cbor(ctx, *receipt.path);

    QCBOREncode_CloseMap(&ctx);

    UsefulBufC result;
    auto qerr = QCBOREncode_Finish(&ctx, &result);
    if (qerr != QCBOR_SUCCESS)
    {
      LOG_DEBUG_FMT("Failed to encode merkle proof: {}", qerr);
      return std::nullopt;
    }

    // Memory address is said to match:
    // github.com/laurencelundblade/QCBOR/blob/v1.4.1/inc/qcbor/qcbor_encode.h#L2190-L2191
    assert(result.ptr == underlying_buffer.data());

    underlying_buffer.resize(result.len);
    underlying_buffer.shrink_to_fit();
    return underlying_buffer;
  }

  std::optional<SerialisedCoseEndorsements> describe_cose_endorsements_v1(
    const TxReceiptImpl& receipt)
  {
    return receipt.cose_endorsements;
  }

  std::optional<SerialisedCoseSignature> describe_cose_signature_v1(
    const TxReceiptImpl& receipt)
  {
    return receipt.cose_signature;
  }
}

namespace ccf::historical
{
  std::optional<ccf::TxID> txid_from_header(
    endpoints::CommandEndpointContext& args)
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

  void default_error_handler(
    HistoricalQueryErrorCode err,
    std::string reason,
    endpoints::CommandEndpointContext& args)
  {
    switch (err)
    {
      case HistoricalQueryErrorCode::InternalError:
      {
        args.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::TransactionPendingOrUnknown,
          std::move(reason));
        break;
      }
      case HistoricalQueryErrorCode::TransactionPending:
      {
        args.rpc_ctx->set_response_header(
          http::headers::CACHE_CONTROL, "no-cache");
        args.rpc_ctx->set_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::TransactionPendingOrUnknown,
          std::move(reason));
        break;
      }
      case HistoricalQueryErrorCode::TransactionInvalid:
      case HistoricalQueryErrorCode::TransactionIdMissing:
      {
        args.rpc_ctx->set_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::TransactionInvalid,
          std::move(reason));
        break;
      }
      case HistoricalQueryErrorCode::TransactionPartiallyReady:
      {
        args.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
        constexpr size_t retry_after_seconds = 3;
        args.rpc_ctx->set_response_header(
          http::headers::RETRY_AFTER, retry_after_seconds);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(std::move(reason));
        break;
      }
      default:
      {
        LOG_FAIL_FMT("Unexpected historical query error {}", err);
      }
    }
  }

  HistoricalTxStatus is_tx_committed_v2(
    ccf::kv::Consensus* consensus,
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

  template <
    class TQueryHandler,
    class TEndpointFunction,
    class TEndpointContext,
    class TTxIDExtractor>
  TEndpointFunction _adapter_v3(
    const TQueryHandler& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const TTxIDExtractor& extractor)
  {
    return _adapter_v4<TQueryHandler, TEndpointFunction, TEndpointContext>(
      f, node_context, available, extractor, default_error_handler);
  }

  ccf::endpoints::EndpointFunction adapter_v3(
    const HandleHistoricalQuery& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor)
  {
    return _adapter_v3<
      HandleHistoricalQuery,
      ccf::endpoints::EndpointFunction,
      ccf::endpoints::EndpointContext>(f, node_context, available, extractor);
  }

  ccf::endpoints::ReadOnlyEndpointFunction read_only_adapter_v3(
    const HandleReadOnlyHistoricalQuery& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const ReadOnlyTxIDExtractor& extractor)
  {
    return _adapter_v3<
      HandleReadOnlyHistoricalQuery,
      ccf::endpoints::ReadOnlyEndpointFunction,
      ccf::endpoints::ReadOnlyEndpointContext>(
      f, node_context, available, extractor);
  }

  ccf::endpoints::EndpointFunction read_write_adapter_v3(
    const HandleReadWriteHistoricalQuery& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor)
  {
    return _adapter_v3<
      HandleReadWriteHistoricalQuery,
      ccf::endpoints::EndpointFunction,
      ccf::endpoints::EndpointContext>(f, node_context, available, extractor);
  }

  template <
    class TQueryHandler,
    class TEndpointFunction,
    class TEndpointContext,
    class TTxIDExtractor,
    class TErrorHandler>
  TEndpointFunction _adapter_v4(
    const TQueryHandler& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const TTxIDExtractor& extractor,
    const TErrorHandler& ehandler)
  {
    auto& state_cache = node_context.get_historical_state();
    auto network_identity_subsystem =
      node_context.get_subsystem<NetworkIdentitySubsystemInterface>();

    return [f,
            &state_cache,
            network_identity_subsystem,
            available,
            extractor,
            ehandler](TEndpointContext& args) {
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
          ehandler(
            HistoricalQueryErrorCode::TransactionIdMissing,
            "Could not extract Transaction Id",
            args);
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
            ehandler(
              HistoricalQueryErrorCode::InternalError,
              std::move(error_reason),
              args);
            return;
          case HistoricalTxStatus::PendingOrUnknown:
            ehandler(
              HistoricalQueryErrorCode::TransactionPending,
              std::move(error_reason),
              args);
            return;
          case HistoricalTxStatus::Invalid:
            ehandler(
              HistoricalQueryErrorCode::TransactionInvalid,
              std::move(error_reason),
              args);
            return;
          case HistoricalTxStatus::Valid:
            break;
        }
      }

      // If recovery in progress, prohibit any historical queries for previous
      // epochs, because the service does not yet have access to the
      // ledger secrets necessary to produce commit evidence.
      auto service = args.tx.template ro<ccf::Service>(Tables::SERVICE);
      auto active_service = service->get();
      if (active_service && active_service->status != ServiceStatus::OPEN)
      {
        if (
          active_service->current_service_create_txid &&
          target_tx_id.view < active_service->current_service_create_txid->view)
        {
          auto reason = fmt::format(
            "Historical transaction {} is not signed by the current service "
            "identity key and cannot be retrieved until recovery is complete.",
            target_tx_id.to_str());
          ehandler(
            HistoricalQueryErrorCode::TransactionInvalid,
            std::move(reason),
            args);
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
      try
      {
        if (
          historical_state == nullptr ||
          (!populate_service_endorsements(
            args.tx,
            historical_state,
            state_cache,
            network_identity_subsystem)) ||
          !populate_cose_service_endorsements(
            args.tx, historical_state, state_cache))
        {
          auto reason = fmt::format(
            "Historical transaction {} is not currently available.",
            target_tx_id.to_str());
          ehandler(
            HistoricalQueryErrorCode::TransactionPartiallyReady,
            std::move(reason),
            args);
          return;
        }
      }
      catch (const std::exception& e)
      {
        auto reason = fmt::format(
          "Historical transaction {} failed with error: {}",
          target_tx_id.to_str(),
          e.what());
        ehandler(
          HistoricalQueryErrorCode::InternalError, std::move(reason), args);
        return;
      }

      // Call the provided handler
      f(args, historical_state);
    };
  }

  ccf::endpoints::ReadOnlyEndpointFunction read_only_adapter_v4(
    const HandleReadOnlyHistoricalQuery& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const ReadOnlyTxIDExtractor& extractor,
    const ReadOnlyErrorHandler& ehandler)
  {
    return _adapter_v4<
      HandleReadOnlyHistoricalQuery,
      ccf::endpoints::ReadOnlyEndpointFunction,
      ccf::endpoints::ReadOnlyEndpointContext>(
      f, node_context, available, extractor, ehandler);
  }

  ccf::endpoints::EndpointFunction read_write_adapter_v4(
    const HandleReadWriteHistoricalQuery& f,
    ccf::AbstractNodeContext& node_context,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor,
    const ErrorHandler& ehandler)
  {
    return _adapter_v4<
      HandleReadWriteHistoricalQuery,
      ccf::endpoints::EndpointFunction,
      ccf::endpoints::EndpointContext>(
      f, node_context, available, extractor, ehandler);
  }
}
