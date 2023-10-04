// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/common_endpoint_registry.h"

#include "ccf/common_auth_policies.h"
#include "ccf/ds/nonstd.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/http_consts.h"
#include "ccf/http_query.h"
#include "ccf/json_handler.h"
#include "ccf/node_context.h"
#include "ccf/service/tables/code_id.h"
#include "ccf/service/tables/host_data.h"
#include "ccf/service/tables/snp_measurements.h"
#include "node/rpc/call_types.h"
#include "node/rpc/serialization.h"

namespace ccf
{
  static constexpr auto tx_id_param_key = "transaction_id";
  static constexpr auto view_history_param_key = "view_history";
  static constexpr auto view_history_since_param_key = "view_history_since";

  namespace
  {
    std::optional<ccf::TxID> txid_from_query_string(
      ccf::endpoints::CommandEndpointContext& ctx)
    {
      const auto parsed_query =
        http::parse_query(ctx.rpc_ctx->get_request_query());

      const auto it = parsed_query.find(tx_id_param_key);
      if (it == parsed_query.end())
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidQueryParameterValue,
          fmt::format(
            "Query string must contain a '{}' parameter", tx_id_param_key));
        return std::nullopt;
      }

      const auto& txid_str = it->second;

      const auto tx_id_opt = ccf::TxID::from_str(txid_str);
      if (!tx_id_opt.has_value())
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidQueryParameterValue,
          fmt::format(
            "The value '{}' passed as '{}' could not be "
            "converted to a valid Tx ID.",
            txid_str,
            tx_id_param_key));
        return std::nullopt;
      }

      return tx_id_opt;
    }
  }

  CommonEndpointRegistry::CommonEndpointRegistry(
    const std::string& method_prefix_, ccfapp::AbstractNodeContext& context_) :
    BaseEndpointRegistry(method_prefix_, context_)
  {}

  void CommonEndpointRegistry::init_handlers()
  {
    BaseEndpointRegistry::init_handlers();

    auto get_commit = [this](auto& ctx, nlohmann::json&&) {
      ccf::View view;
      ccf::SeqNo seqno;
      auto result = get_last_committed_txid_v1(view, seqno);
      if (result != ccf::ApiResult::OK)
      {
        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          fmt::format("Error code: {}", ccf::api_result_to_str(result)));
      }

      GetCommit::Out out;
      out.transaction_id.view = view;
      out.transaction_id.seqno = seqno;

      // Parse arguments from query
      const auto parsed_query =
        http::parse_query(ctx.rpc_ctx->get_request_query());

      std::string error_reason; // ignored as this is optional
      auto view_history_since = http::get_query_value_opt<ccf::View>(
        parsed_query, view_history_since_param_key, error_reason);

      // if view_history_since was given then the value has already been
      // validated
      if (view_history_since.has_value())
      {
        if (error_reason != "")
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            error_reason);
        }
        std::vector<ccf::TxID> history;
        result = get_view_history_v1(history, view_history_since.value());
        if (result == ccf::ApiResult::InvalidArgs)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            fmt::format(
              "Invalid value for {}, must be in range [1, current_term]",
              view_history_since_param_key));
        }
        else if (result == ccf::ApiResult::NotFound)
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::InvalidQueryParameterValue,
            fmt::format(
              "Invalid value for {}, must be in range [1, current_term]",
              view_history_since_param_key));
        }
        else if (result != ccf::ApiResult::OK)
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Error code: {}", ccf::api_result_to_str(result)));
        }
        out.view_history = history;
      }

      error_reason.clear();
      auto view_history = http::get_query_value_opt<std::string>(
        parsed_query, view_history_param_key, error_reason);

      // if view_history was given then we can validate the value
      if (view_history.has_value())
      {
        if (error_reason != "")
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            error_reason);
        }
        if (view_history.value() == "true")
        {
          std::vector<ccf::TxID> history;
          result = get_view_history_v1(history);
          if (result != ccf::ApiResult::OK)
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format("Error code: {}", ccf::api_result_to_str(result)));
          }
          out.view_history = history;
        }
        else if (view_history.value() == "false")
        {
          out.view_history.clear();
        }
        else
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            fmt::format(
              "Invalid value for {}, must be one of [true, false] when present",
              view_history_param_key));
        }
      }

      return make_success(out);
    };
    make_command_endpoint(
      "/commit", HTTP_GET, json_command_adapter(get_commit), no_auth_required)
      .set_auto_schema<GetCommit>()
      .add_query_parameter<bool>(
        view_history_param_key, endpoints::OptionalParameter)
      .add_query_parameter<ccf::View>(
        view_history_since_param_key, endpoints::OptionalParameter)
      .set_openapi_summary("Current commit level")
      .set_openapi_description(
        "Latest transaction ID that has been committed on the service")
      .install();

    auto get_tx_status = [this](auto& ctx, nlohmann::json&&) {
      // Parse arguments from query
      const auto parsed_query =
        http::parse_query(ctx.rpc_ctx->get_request_query());

      std::string error_reason;
      std::string tx_id_str;
      if (!http::get_query_value(
            parsed_query, tx_id_param_key, tx_id_str, error_reason))
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidQueryParameterValue,
          std::move(error_reason));
      }

      const auto tx_id = ccf::TxID::from_str(tx_id_str);
      if (!tx_id.has_value())
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidQueryParameterValue,
          fmt::format(
            "The value '{}' passed as query parameter '{}' could not be "
            "converted to a valid Transaction ID.",
            tx_id_str,
            tx_id_param_key));
      }

      GetTxStatus::Out out;
      const auto result =
        get_status_for_txid_v1(tx_id->view, tx_id->seqno, out.status);
      if (result == ccf::ApiResult::OK)
      {
        out.transaction_id = tx_id.value();
        return make_success(out);
      }
      else
      {
        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          fmt::format("Error code: {}", ccf::api_result_to_str(result)));
      }
    };
    make_command_endpoint(
      "/tx", HTTP_GET, json_command_adapter(get_tx_status), no_auth_required)
      .set_auto_schema<void, GetTxStatus::Out>()
      .add_query_parameter<ccf::TxID>(tx_id_param_key)
      .set_openapi_summary("Current status of a transaction")
      .set_openapi_description(
        "Possible statuses returned are Unknown, Pending, Committed or "
        "Invalid.")
      .install();

    auto get_code = [](auto& ctx, nlohmann::json&&) {
      GetCode::Out out;

      auto codes_ids = ctx.tx.template ro<CodeIDs>(Tables::NODE_CODE_IDS);
      codes_ids->foreach(
        [&out](
          const ccf::pal::SgxAttestationMeasurement& measurement,
          const ccf::CodeStatus& status) {
          auto digest = measurement.hex_str();
          out.versions.push_back({digest, status});
          return true;
        });

      return make_success(out);
    };
    make_read_only_endpoint(
      "/code", HTTP_GET, json_read_only_adapter(get_code), no_auth_required)
      .set_auto_schema<void, GetCode::Out>()
      .set_openapi_summary(
        "This endpoint is deprecated. It is replaced by /gov/kv/nodes/code_ids "
        "endpoint")
      .set_openapi_deprecated(true)
      .set_openapi_description("Permitted SGX code identities")
      .install();

    auto openapi = [this](auto& ctx) { this->api_endpoint(ctx); };
    make_read_only_endpoint("/api", HTTP_GET, openapi, no_auth_required)
      .set_auto_schema<void, GetAPI::Out>()
      .set_openapi_summary("OpenAPI schema")
      .install();

    auto endpoint_metrics_fn = [this](auto&, nlohmann::json&&) {
      EndpointMetrics out;
      const auto result = get_metrics_v1(out);
      if (result == ccf::ApiResult::OK)
      {
        return make_success(out);
      }
      else
      {
        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          fmt::format("Error code: {}", ccf::api_result_to_str(result)));
      }
    };
    make_command_endpoint(
      "/api/metrics",
      HTTP_GET,
      json_command_adapter(endpoint_metrics_fn),
      no_auth_required)
      .set_auto_schema<void, EndpointMetrics>()
      .set_openapi_summary("Usage metrics for endpoints")
      .install();

    auto is_tx_committed =
      [this](ccf::View view, ccf::SeqNo seqno, std::string& error_reason) {
        return ccf::historical::is_tx_committed_v2(
          consensus, view, seqno, error_reason);
      };

    auto get_receipt =
      [](auto& ctx, ccf::historical::StatePtr historical_state) {
        const auto [pack, params] =
          ccf::jsonhandler::get_json_params(ctx.rpc_ctx);

        assert(historical_state->receipt);
        auto out = ccf::describe_receipt_v1(*historical_state->receipt);
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ccf::jsonhandler::set_response(out, ctx.rpc_ctx, pack);
      };

    make_read_only_endpoint(
      "/receipt",
      HTTP_GET,
      ccf::historical::read_only_adapter_v3(
        get_receipt, context, is_tx_committed, txid_from_query_string),
      no_auth_required)
      .set_auto_schema<void, nlohmann::json>()
      .add_query_parameter<ccf::TxID>(tx_id_param_key)
      .set_openapi_summary("Receipt for a transaction")
      .set_openapi_description(
        "A signed statement from the service over a transaction entry in the "
        "ledger")
      .install();
  }

  void CommonEndpointRegistry::api_endpoint(
    ccf::endpoints::ReadOnlyEndpointContext& ctx)
  {
    nlohmann::json document;
    const auto result = generate_openapi_document_v1(
      ctx.tx,
      openapi_info.title,
      openapi_info.description,
      openapi_info.document_version,
      document);

    if (result == ccf::ApiResult::OK)
    {
      ctx.rpc_ctx->set_response_json(document, HTTP_STATUS_OK);
    }
    else
    {
      ctx.rpc_ctx->set_error(
        HTTP_STATUS_INTERNAL_SERVER_ERROR,
        ccf::errors::InternalError,
        fmt::format("Error code: {}", ccf::api_result_to_str(result)));
    }
  }
}
