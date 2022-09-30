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
#include "ccf/service/tables/security_policies.h"
#include "node/rpc/call_types.h"
#include "node/rpc/serialization.h"

namespace ccf
{
  static constexpr auto tx_id_param_key = "transaction_id";

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

    auto get_commit = [this](auto&, nlohmann::json&&) {
      ccf::View view;
      ccf::SeqNo seqno;
      const auto result = get_last_committed_txid_v1(view, seqno);

      if (result == ccf::ApiResult::OK)
      {
        GetCommit::Out out;
        out.transaction_id.view = view;
        out.transaction_id.seqno = seqno;
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
      "/commit", HTTP_GET, json_command_adapter(get_commit), no_auth_required)
      .set_auto_schema<GetCommit>()
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
      .install();

    make_command_endpoint(
      "/local_tx",
      HTTP_GET,
      json_command_adapter(get_tx_status),
      no_auth_required)
      .set_auto_schema<void, GetTxStatus::Out>()
      .add_query_parameter<ccf::TxID>(tx_id_param_key)
      .install();

    auto get_code = [](auto& ctx, nlohmann::json&&) {
      GetCode::Out out;

      auto codes_ids = ctx.tx.template ro<CodeIDs>(Tables::NODE_CODE_IDS);
      codes_ids->foreach(
        [&out](const ccf::CodeDigest& cd, const ccf::CodeInfo& info) {
          auto digest = ds::to_hex(cd.data);
          out.versions.push_back({digest, info.status, info.platform});
          return true;
        });

      return make_success(out);
    };
    make_read_only_endpoint(
      "/code", HTTP_GET, json_read_only_adapter(get_code), no_auth_required)
      .set_auto_schema<void, GetCode::Out>()
      .install();

    auto get_security_policies = [](auto& ctx, nlohmann::json&&) {

      const auto parsed_query =
        http::parse_query(ctx.rpc_ctx->get_request_query());
      std::string error_string; // Ignored - params are optional
      const auto key = http::get_query_value_opt<std::string>(
        parsed_query, "key", error_string);

      GetSecurityPolicies::Out out;

      auto security_policies = ctx.tx.template ro<SecurityPolicies>(Tables::SECURITY_POLICIES);
      security_policies->foreach(
        [key, &out](const DigestedPolicy& digest, const RawPolicy& raw) {
          auto digest_str = ds::to_hex(digest);
          if (!key.has_value() || key.value() == digest_str)
            out.policies.push_back({raw, digest_str});
          return true;
        });

      return make_success(out);
    };
    make_read_only_endpoint(
      "/security_policy", HTTP_GET, json_read_only_adapter(get_security_policies), no_auth_required)
      .set_auto_schema<void, GetSecurityPolicies::Out>()
      .add_query_parameter<std::string>(
        "key", ccf::endpoints::OptionalParameter)
      .install();

    auto openapi = [this](auto& ctx, nlohmann::json&&) {
      nlohmann::json document;
      const auto result = generate_openapi_document_v1(
        ctx.tx,
        openapi_info.title,
        openapi_info.description,
        openapi_info.document_version,
        document);

      if (result == ccf::ApiResult::OK)
      {
        return make_success(document);
      }
      else
      {
        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          fmt::format("Error code: {}", ccf::api_result_to_str(result)));
      }
    };
    make_read_only_endpoint(
      "/api", HTTP_GET, json_read_only_adapter(openapi), no_auth_required)
      .set_auto_schema<void, GetAPI::Out>()
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
      .install();
  }
}
