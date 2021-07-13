// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/app_interface.h"
#include "ccf/base_endpoint_registry.h"
#include "ccf/common_auth_policies.h"
#include "ccf/json_handler.h"
#include "ds/json.h"
#include "enclave/node_context.h"
#include "node/network_tables.h"
#include "node/rpc/frontend.h"

#include <charconv>

namespace nobuiltins
{
  struct NodeQuote
  {
    ccf::QuoteFormat quote_format;
    std::vector<uint8_t> quote;
    std::vector<uint8_t> endorsements;
  };

  DECLARE_JSON_TYPE(NodeQuote)
  DECLARE_JSON_REQUIRED_FIELDS(NodeQuote, quote_format, quote, endorsements)

  struct NodeSummary : public NodeQuote
  {
    ccf::View committed_view;
    ccf::SeqNo committed_seqno;

    ccf::NodeId node_id;
  };

  DECLARE_JSON_TYPE_WITH_BASE(NodeSummary, NodeQuote)
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeSummary, committed_view, committed_seqno, node_id)

  struct AllNodesSummary
  {
    std::map<std::string, NodeQuote> nodes;
  };

  DECLARE_JSON_TYPE(AllNodesSummary)
  DECLARE_JSON_REQUIRED_FIELDS(AllNodesSummary, nodes)

  struct TransactionIDResponse
  {
    std::string transaction_id;
  };

  DECLARE_JSON_TYPE(TransactionIDResponse)
  DECLARE_JSON_REQUIRED_FIELDS(TransactionIDResponse, transaction_id)

  struct TimeResponse
  {
    std::string timestamp;
  };

  DECLARE_JSON_TYPE(TimeResponse)
  DECLARE_JSON_REQUIRED_FIELDS(TimeResponse, timestamp)

  // SNIPPET: registry_inheritance
  class NoBuiltinsRegistry : public ccf::BaseEndpointRegistry
  {
  public:
    NoBuiltinsRegistry(ccfapp::AbstractNodeContext& context) :
      ccf::BaseEndpointRegistry("app", context)
    {
      auto node_summary = [this](auto& ctx) {
        ccf::ApiResult result;

        NodeSummary summary;

        {
          // SNIPPET_START: get_quote_api_v1
          ccf::QuoteInfo quote_info;
          result = get_quote_for_this_node_v1(ctx.tx, quote_info);
          if (result != ccf::ApiResult::OK)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "Failed to get quote: {}", ccf::api_result_to_str(result)));
            return;
          }

          summary.quote_format = quote_info.format;
          summary.quote = quote_info.quote;
          summary.endorsements = quote_info.endorsements;
          // SNIPPET_END: get_quote_api_v1
        }

        {
          result = get_last_committed_txid_v1(
            summary.committed_view, summary.committed_seqno);
          if (result != ccf::ApiResult::OK)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "Failed to get committed transaction: {}",
                ccf::api_result_to_str(result)));
            return;
          }
        }

        {
          result = get_id_for_this_node_v1(summary.node_id);
          if (result != ccf::ApiResult::OK)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "Failed to get node ID: {}", ccf::api_result_to_str(result)));
            return;
          }
        }

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_body(nlohmann::json(summary).dump(2));
      };
      make_endpoint(
        "/node_summary", HTTP_GET, node_summary, ccf::no_auth_required)
        .set_auto_schema<void, NodeSummary>()
        .install();

      auto all_nodes = [this](auto& ctx) {
        ccf::ApiResult result;

        std::map<ccf::NodeId, ccf::QuoteInfo> node_id_to_quote_info;
        result =
          get_quotes_for_all_trusted_nodes_v1(ctx.tx, node_id_to_quote_info);
        if (result != ccf::ApiResult::OK)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to get quotes: {}", ccf::api_result_to_str(result)));
          return;
        }

        AllNodesSummary summary;
        for (const auto& [node_id, quote_info] : node_id_to_quote_info)
        {
          NodeQuote nq;
          nq.quote_format = quote_info.format;
          nq.quote = quote_info.quote;
          nq.endorsements = quote_info.endorsements;
          summary.nodes[node_id.value()] = std::move(nq);
        }
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_body(nlohmann::json(summary).dump(2));
      };
      make_endpoint("/all_nodes", HTTP_GET, all_nodes, ccf::no_auth_required)
        .set_auto_schema<void, AllNodesSummary>()
        .install();

      auto openapi = [this](auto& ctx, nlohmann::json&&) {
        nlohmann::json document;
        const auto result = generate_openapi_document_v1(
          ctx.tx,
          openapi_info.title,
          "A CCF sample demonstrating a minimal app, with no default endpoints",
          "0.0.1",
          document);

        if (result == ccf::ApiResult::OK)
        {
          return ccf::make_success(document);
        }
        else
        {
          return ccf::make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to generate OpenAPI: {}",
              ccf::api_result_to_str(result)));
        }
      };
      make_endpoint(
        "/api", HTTP_GET, ccf::json_adapter(openapi), ccf::no_auth_required)
        .set_auto_schema<void, ccf::GetAPI::Out>()
        .install();

      auto get_commit = [this](auto&, nlohmann::json&&) {
        ccf::View view;
        ccf::SeqNo seqno;
        const auto result = get_last_committed_txid_v1(view, seqno);

        if (result == ccf::ApiResult::OK)
        {
          ccf::GetCommit::Out out;
          out.transaction_id.view = view;
          out.transaction_id.seqno = seqno;
          return ccf::make_success(out);
        }
        else
        {
          return ccf::make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to get committed transaction: {}",
              ccf::api_result_to_str(result)));
        }
      };
      make_command_endpoint(
        "/commit",
        HTTP_GET,
        ccf::json_command_adapter(get_commit),
        ccf::no_auth_required)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .set_auto_schema<void, ccf::GetCommit::Out>()
        .install();

      auto get_txid = [this](auto& ctx, nlohmann::json&&) {
        const auto query_string = ctx.rpc_ctx->get_request_query();
        const auto query_params = nonstd::split(query_string, "&");
        for (const auto& query_param : query_params)
        {
          const auto& [query_key, query_value] =
            nonstd::split_1(query_param, "=");
          if (query_key == "seqno")
          {
            ccf::SeqNo seqno;
            const auto qv_begin = query_value.data();
            const auto qv_end = qv_begin + query_value.size();
            const auto [p, ec] = std::from_chars(qv_begin, qv_end, seqno);
            if (ec != std::errc() || p != qv_end)
            {
              return ccf::make_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidQueryParameterValue,
                fmt::format(
                  "Query parameter '{}' cannot be parsed as a seqno",
                  query_value));
            }

            ccf::View view;
            const auto result = get_view_for_seqno_v1(seqno, view);
            if (result == ccf::ApiResult::OK)
            {
              ccf::TxID tx_id;
              tx_id.view = view;
              tx_id.seqno = seqno;

              TransactionIDResponse resp;
              resp.transaction_id = tx_id.to_str();

              return ccf::make_success(resp);
            }
            else
            {
              return ccf::make_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                fmt::format(
                  "Unable to construct TxID: {}",
                  ccf::api_result_to_str(result)));
            }
          }
        }

        return ccf::make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidInput,
          fmt::format("Missing query parameter '{}'", "seqno"));
      };
      make_command_endpoint(
        "/tx_id",
        HTTP_GET,
        ccf::json_command_adapter(get_txid),
        ccf::no_auth_required)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .set_auto_schema<void, TransactionIDResponse>()
        .install();

      auto get_time = [this](auto& ctx, nlohmann::json&&) {
        ::timespec time;
        ccf::ApiResult result = get_untrusted_host_time_v1(time);
        if (result != ccf::ApiResult::OK)
        {
          return ccf::make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Unable to get time: {}", ccf::api_result_to_str(result)));
        }

        std::tm calendar_time;
        gmtime_r(&time.tv_sec, &calendar_time);

        // 20 characters for a (timezoneless) ISO 8601 datetime, plus a
        // terminating null
        constexpr size_t buf_size = 21;
        char buf[buf_size];
        if (strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%S", &calendar_time) == 0)
        {
          return ccf::make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Unable to format timestamp"));
        }

        // Build full time, with 6 decimals of sub-second precision, and a
        // Python-friendly +00:00 UTC offset
        TimeResponse response;
        response.timestamp =
          fmt::format("{}.{:06}+00:00", buf, time.tv_nsec / 1'000);
        return ccf::make_success(response);
      };
      make_command_endpoint(
        "/current_time",
        HTTP_GET,
        ccf::json_command_adapter(get_time),
        ccf::no_auth_required)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .set_auto_schema<void, TimeResponse>()
        .install();
    }
  };

  class NoBuiltinsFrontend : public ccf::RpcFrontend
  {
  private:
    NoBuiltinsRegistry nbr;

  public:
    NoBuiltinsFrontend(
      ccf::NetworkTables& network, ccfapp::AbstractNodeContext& context) :
      ccf::RpcFrontend(*network.tables, nbr),
      nbr(context)
    {}
  };
}

namespace ccfapp
{
  std::shared_ptr<ccf::RpcFrontend> get_rpc_handler(
    ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context)
  {
    return std::make_shared<nobuiltins::NoBuiltinsFrontend>(nwt, context);
  }
}
