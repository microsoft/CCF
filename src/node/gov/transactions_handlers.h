// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "ccf/endpoint_registry.h"
#include "ccf/json_handler.h"
#include "ccf/tx_id.h"
#include "ccf/tx_status.h"

namespace ccf::gov::endpoints
{
  void init_transactions_handlers(ccf::BaseEndpointRegistry& registry)
  {
    auto get_transaction_status = [&](auto& ctx, nlohmann::json&&) {
      std::string tx_id_str, error;
      if (!registry.get_path_param(
            ctx.rpc_ctx->get_request_path_params(),
            "transactionId",
            tx_id_str,
            error))
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidResourceName, error);
      }

      const auto tx_id = ccf::TxID::from_str(tx_id_str);
      if (!tx_id.has_value())
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidQueryParameterValue,
          fmt::format(
            "The value '{}' passed as parameter 'transactionId' could not be "
            "converted to a valid Transaction ID.",
            tx_id_str));
      }

      ccf::TxStatus status;
      const auto result =
        registry.get_status_for_txid_v1(tx_id->view, tx_id->seqno, status);
      if (result == ccf::ApiResult::OK)
      {
        auto body = nlohmann::json::object();

        body["status"] = status;
        body["transactionId"] = tx_id->to_str();

        return make_success(body);
      }
      else
      {
        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          fmt::format("Error code: {}", ccf::api_result_to_str(result)));
      }
    };
    registry
      .make_endpoint(
        "/service/transactions/{transactionId}/status",
        HTTP_GET,
        json_adapter(get_transaction_status),
        no_auth_required)
      .install();
  }
}