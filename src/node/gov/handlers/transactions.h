// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "ccf/json_handler.h"
#include "ccf/tx_id.h"
#include "ccf/tx_status.h"
#include "node/gov/api_version.h"

namespace ccf::gov::endpoints
{
  inline void init_transactions_handlers(ccf::BaseEndpointRegistry& registry)
  {
    auto get_transaction_status = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
        {
          // Extract transaction ID from path parameter
          std::string tx_id_str;
          std::string error;
          if (!ccf::endpoints::get_path_param(
                ctx.rpc_ctx->get_request_path_params(),
                "transactionId",
                tx_id_str,
                error))
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              std::move(error));
            return;
          }

          // Parse transaction ID from string
          const auto tx_id = ccf::TxID::from_str(tx_id_str);
          if (!tx_id.has_value())
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidQueryParameterValue,
              fmt::format(
                "The value '{}' passed as parameter 'transactionId' could not "
                "be converted to a valid Transaction ID.",
                tx_id_str));
            return;
          }

          // Lookup status
          ccf::TxStatus status = ccf::TxStatus::Unknown;
          const auto result =
            registry.get_status_for_txid_v1(tx_id->view, tx_id->seqno, status);
          if (result != ccf::ApiResult::OK)
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "get_status_for_txid_v1 returned error: {}",
                ccf::api_result_to_str(result)));
            return;
          }

          // Build response
          auto body = nlohmann::json::object();

          body["status"] = status;
          body["transactionId"] = tx_id->to_str();

          ctx.rpc_ctx->set_response_json(body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_command_endpoint(
        "/service/transactions/{transactionId}",
        HTTP_GET,
        api_version_adapter(get_transaction_status),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto get_commit = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
        {
          // Lookup committed
          ccf::View view = 0;
          ccf::SeqNo seqno = 0;
          auto result = registry.get_last_committed_txid_v1(view, seqno);
          if (result != ccf::ApiResult::OK)
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "get_last_committed_txid_v1 returned error: {}",
                ccf::api_result_to_str(result)));
            return;
          }

          // Lookup status
          ccf::TxStatus status = ccf::TxStatus::Unknown;
          result = registry.get_status_for_txid_v1(view, seqno, status);
          if (result != ccf::ApiResult::OK)
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "get_status_for_txid_v1 returned error: {}",
                ccf::api_result_to_str(result)));
            return;
          }

          // Build response
          auto body = nlohmann::json::object();

          body["status"] = status;
          body["transactionId"] = ccf::TxID{view, seqno};

          ctx.rpc_ctx->set_response_json(body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_command_endpoint(
        "/service/transactions/commit",
        HTTP_GET,
        api_version_adapter(get_commit),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();
  }
}