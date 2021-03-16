// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "base_endpoint_registry.h"
#include "ds/nonstd.h"
#include "enclave/node_context.h"
#include "http/http_consts.h"
#include "http/http_query.h"
#include "http/ws_consts.h"
#include "json_handler.h"
#include "node/code_id.h"
#include "node/historical_queries_adapter.h"

namespace ccf
{
  static inline std::optional<ccf::TxID> txid_from_query_string(
    EndpointContext& args)
  {
    const auto parsed_query =
      http::parse_query(args.rpc_ctx->get_request_query());
    constexpr auto param_key = "transaction_id";

    const auto it = parsed_query.find(param_key);
    if (it == parsed_query.end())
    {
      args.rpc_ctx->set_error(
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::InvalidQueryParameterValue,
        fmt::format("Query string must contain a '{}' parameter", param_key));
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
          param_key));
      return std::nullopt;
    }

    return tx_id_opt;
  }

  /*
   * Extends the BaseEndpointRegistry by installing common endpoints we expect
   * to be available on most services. Override init_handlers or inherit from
   * BaseEndpointRegistry directly if you wish to wrap some of this
   * functionality in different Endpoints.
   */
  class CommonEndpointRegistry : public BaseEndpointRegistry
  {
  public:
    CommonEndpointRegistry(
      const std::string& method_prefix_,
      ccfapp::AbstractNodeContext& context_) :
      BaseEndpointRegistry(method_prefix_, context_)
    {}

    void init_handlers() override
    {
      BaseEndpointRegistry::init_handlers();

      auto get_commit = [this](auto&, nlohmann::json&&) {
        GetCommit::Out out;
        const auto result = get_last_committed_txid_v1(out.view, out.seqno);

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

        kv::Consensus::View view;
        kv::Consensus::SeqNo seqno;
        if (
          !http::get_query_value(parsed_query, "view", view, error_reason) ||
          !http::get_query_value(parsed_query, "seqno", seqno, error_reason))
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            std::move(error_reason));
        }

        GetTxStatus::Out out;
        const auto result = get_status_for_txid_v1(view, seqno, out.status);
        if (result == ccf::ApiResult::OK)
        {
          out.view = view;
          out.seqno = seqno;
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
        .add_query_parameter<kv::Consensus::View>("view")
        .add_query_parameter<kv::Consensus::SeqNo>("seqno")
        .install();

      make_command_endpoint(
        "local_tx",
        HTTP_GET,
        json_command_adapter(get_tx_status),
        no_auth_required)
        .set_auto_schema<void, GetTxStatus::Out>()
        .add_query_parameter<kv::Consensus::View>("view")
        .add_query_parameter<kv::Consensus::SeqNo>("seqno")
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto get_code = [](auto& args, nlohmann::json&&) {
        GetCode::Out out;

        auto codes_ids = args.tx.template ro<CodeIDs>(Tables::NODE_CODE_IDS);
        codes_ids->foreach(
          [&out](const ccf::CodeDigest& cd, const ccf::CodeStatus& cs) {
            auto digest = fmt::format("{:02x}", fmt::join(cd, ""));
            out.versions.push_back({digest, cs});
            return true;
          });

        return make_success(out);
      };
      make_read_only_endpoint(
        "code", HTTP_GET, json_read_only_adapter(get_code), no_auth_required)
        .set_auto_schema<void, GetCode::Out>()
        .install();

      auto openapi = [this](kv::Tx& tx, nlohmann::json&&) {
        nlohmann::json document;
        const auto result = generate_openapi_document_v1(
          tx,
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
        EndpointMetrics::Out out;
        endpoint_metrics(out);
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

      auto get_receipt = [](
                           ccf::EndpointContext& args,
                           ccf::historical::StatePtr historical_state) {
        const auto [pack, params] =
          ccf::jsonhandler::get_json_params(args.rpc_ctx);

        GetReceipt::Out out;
        out.from_receipt(historical_state->receipt);
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
        .set_auto_schema<void, GetReceipt::Out>()
        .add_query_parameter<ccf::TxID>("transaction_id")
        .install();
    }
  };
}
