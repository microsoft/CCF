// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "ccf/json_handler.h"
#include "ccf/tx_id.h"
#include "ccf/tx_status.h"

namespace ccf::gov::endpoints
{
  void init_transactions_handlers(ccf::BaseEndpointRegistry& registry)
  {
    auto get_transaction_status = [&](
                                    auto& ctx,
                                    nlohmann::json&& params,
                                    ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::v0_0_1_preview:
        default:
        {
          // Extract transaction ID from path parameter
          std::string tx_id_str, error;
          if (!ccf::endpoints::get_path_param(
                ctx.rpc_ctx->get_request_path_params(),
                "transactionId",
                tx_id_str,
                error))
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidResourceName, error);
          }

          // Parse transaction ID from string
          const auto tx_id = ccf::TxID::from_str(tx_id_str);
          if (!tx_id.has_value())
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidQueryParameterValue,
              fmt::format(
                "The value '{}' passed as parameter 'transactionId' could not "
                "be converted to a valid Transaction ID.",
                tx_id_str));
          }

          // Lookup status
          ccf::TxStatus status;
          const auto result =
            registry.get_status_for_txid_v1(tx_id->view, tx_id->seqno, status);
          if (result != ccf::ApiResult::OK)
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "get_status_for_txid_v1 returned error: {}",
                ccf::api_result_to_str(result)));
          }

          // Build response
          auto body = nlohmann::json::object();

          body["status"] = status;
          body["transactionId"] = tx_id->to_str();

          return make_success(body);
          break;
        }
      }
    };
    registry
      .make_command_endpoint(
        "/service/transactions/{transactionId}/status",
        HTTP_GET,
        json_command_adapter(api_version_adapter(get_transaction_status)),
        no_auth_required)
      .install();

    auto get_commit =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            // Lookup committed
            ccf::View view;
            ccf::SeqNo seqno;
            auto result = registry.get_last_committed_txid_v1(view, seqno);
            if (result != ccf::ApiResult::OK)
            {
              return make_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                fmt::format(
                  "get_last_committed_txid_v1 returned error: {}",
                  ccf::api_result_to_str(result)));
            }

            // Lookup status
            ccf::TxStatus status;
            result = registry.get_status_for_txid_v1(view, seqno, status);
            if (result != ccf::ApiResult::OK)
            {
              return make_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                fmt::format(
                  "get_status_for_txid_v1 returned error: {}",
                  ccf::api_result_to_str(result)));
            }

            // Build response
            auto body = nlohmann::json::object();

            body["status"] = status;
            body["transactionId"] = ccf::TxID{view, seqno};

            return make_success(body);
            break;
          }
        }
      };
    registry
      .make_command_endpoint(
        "/service/transactions/commit",
        HTTP_GET,
        json_command_adapter(api_version_adapter(get_commit)),
        no_auth_required)
      .install();
  }
}