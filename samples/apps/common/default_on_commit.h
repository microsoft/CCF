// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint_context.h"
#include "ccf/endpoint_registry.h"
#include "ccf/receipt.h"
#include "ccf/rpc_context.h"

namespace ccf::samples
{
  // A simple ConsensusCommittedEndpointFunction that returns the original
  // response once committed, or an error if the transaction was invalidated.
  inline void default_respond_on_commit(ccf::endpoints::CommittedTxInfo& info)
  {
    if (info.status == ccf::FinalTxStatus::Invalid)
    {
      info.rpc_ctx->set_error(
        HTTP_STATUS_INTERNAL_SERVER_ERROR,
        ccf::errors::TransactionInvalid,
        fmt::format(
          "While waiting for TxID {} to commit, it was invalidated",
          info.tx_id.to_str()));
    }

    // Else leave the original response untouched, and return it now
  }

  // Returns a ConsensusCommittedEndpointFunction that builds a COSE receipt
  // for the committed transaction and returns it as the response body.
  inline ccf::endpoints::ConsensusCommittedEndpointFunction
  make_respond_with_receipt_on_commit(ccf::AbstractNodeContext& context)
  {
    return [&context](ccf::endpoints::CommittedTxInfo& info) {
      if (info.status == ccf::FinalTxStatus::Invalid)
      {
        info.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::TransactionInvalid,
          fmt::format(
            "While waiting for TxID {} to commit, it was invalidated",
            info.tx_id.to_str()));
        return;
      }

      auto receipt =
        ccf::endpoints::build_receipt_for_committed_tx(context, info);
      if (receipt == nullptr)
      {
        return;
      }

      auto cose_receipt = ccf::describe_cose_receipt_v1(*receipt);
      if (!cose_receipt.has_value())
      {
        info.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "No COSE receipt produced for this transaction");
        return;
      }

      info.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      info.rpc_ctx->set_response_header(
        ccf::http::headers::CONTENT_TYPE,
        ccf::http::headervalues::contenttype::COSE);
      info.rpc_ctx->set_response_body(cose_receipt.value());
    };
  }
}
