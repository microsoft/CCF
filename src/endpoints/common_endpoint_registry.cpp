// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/common_auth_policies.h"
#include "ccf/common_endpoint_registry.h"
#include "ccf/historical_queries_adapter.h"
#include "ds/nonstd.h"
#include "enclave/node_context.h"
#include "http/http_consts.h"
#include "http/http_query.h"
#include "node/code_id.h"
#include "node/rpc/json_handler.h"

namespace ccf
{
  static constexpr auto tx_id_param_key = "transaction_id";

  namespace
  {
    std::optional<ccf::TxID> txid_from_query_string(
      ccf::endpoints::EndpointContext& args)
    {
      const auto parsed_query =
        http::parse_query(args.rpc_ctx->get_request_query());

      const auto it = parsed_query.find(tx_id_param_key);
      if (it == parsed_query.end())
      {
        args.rpc_ctx->set_error(
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
        args.rpc_ctx->set_error(
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
      kv::Consensus::View view;
      kv::Consensus::SeqNo seqno;
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
      "commit", HTTP_GET, json_command_adapter(get_commit), no_auth_required)
      .set_execute_outside_consensus(
        ccf::endpoints::ExecuteOutsideConsensus::Locally)
      .set_auto_schema<void, GetCommit::Out>()
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
      "tx", HTTP_GET, json_command_adapter(get_tx_status), no_auth_required)
      .set_auto_schema<void, GetTxStatus::Out>()
      .add_query_parameter<ccf::TxID>(tx_id_param_key)
      .install();

    make_command_endpoint(
      "local_tx",
      HTTP_GET,
      json_command_adapter(get_tx_status),
      no_auth_required)
      .set_auto_schema<void, GetTxStatus::Out>()
      .add_query_parameter<ccf::TxID>(tx_id_param_key)
      .set_execute_outside_consensus(
        ccf::endpoints::ExecuteOutsideConsensus::Locally)
      .install();

    auto get_code = [](auto& args, nlohmann::json&&) {
      GetCode::Out out;

      auto codes_ids = args.tx.template ro<CodeIDs>(Tables::NODE_CODE_IDS);
      codes_ids->foreach(
        [&out](const ccf::CodeDigest& cd, const ccf::CodeStatus& cs) {
          auto digest = ds::to_hex(cd.data);
          out.versions.push_back({digest, cs});
          return true;
        });

      return make_success(out);
    };
    make_read_only_endpoint(
      "code", HTTP_GET, json_read_only_adapter(get_code), no_auth_required)
      .set_auto_schema<void, GetCode::Out>()
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
    make_endpoint("api", HTTP_GET, json_adapter(openapi), no_auth_required)
      .set_auto_schema<void, GetAPI::Out>()
      .install();

    auto endpoint_metrics_fn = [this](auto&, nlohmann::json&&) {
      std::lock_guard<SpinLock> guard(metrics_lock);
      EndpointMetrics::Out out;
      for (const auto& [path, verb_metrics] : metrics)
      {
        for (const auto& [verb, metric] : verb_metrics)
        {
          out.metrics.push_back({path,
                                 verb,
                                 metric.calls,
                                 metric.errors,
                                 metric.failures,
                                 metric.retries});
        }
      }
      return make_success(out);
    };
    make_command_endpoint(
      "api/metrics",
      HTTP_GET,
      json_command_adapter(endpoint_metrics_fn),
      no_auth_required)
      .set_auto_schema<void, EndpointMetrics::Out>()
      .set_execute_outside_consensus(
        ccf::endpoints::ExecuteOutsideConsensus::Locally)
      .install();

    auto is_tx_committed = [this](
                             kv::Consensus::View view,
                             kv::Consensus::SeqNo seqno,
                             std::string& error_reason) {
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
          "Only committed transactions can be queried. Transaction {}.{} is "
          "{}",
          view,
          seqno,
          ccf::tx_status_to_str(tx_status));
        return false;
      }

      return true;
    };

    auto get_receipt =
      [](auto& args, ccf::historical::StatePtr historical_state) {
        const auto [pack, params] =
          ccf::jsonhandler::get_json_params(args.rpc_ctx);

        ccf::Receipt out;
        historical_state->receipt->describe(out);
        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ccf::jsonhandler::set_response(out, args.rpc_ctx, pack);
      };

    make_endpoint(
      "receipt",
      HTTP_GET,
      ccf::historical::adapter(
        get_receipt,
        context.get_historical_state(),
        is_tx_committed,
        txid_from_query_string),
      no_auth_required)
      .set_execute_outside_consensus(
        ccf::endpoints::ExecuteOutsideConsensus::Locally)
      .set_auto_schema<void, ccf::Receipt>()
      .add_query_parameter<ccf::TxID>(tx_id_param_key)
      .install();
  }
}
