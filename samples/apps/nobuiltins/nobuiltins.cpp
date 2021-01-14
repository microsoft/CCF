// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/json.h"
#include "enclave/app_interface.h"

namespace nobuiltins
{
  struct NodeSummary
  {
    ccf::QuoteFormat quote_format;
    std::string quote;

    kv::Consensus::View committed_view;
    kv::Consensus::SeqNo committed_seqno;
  };

  DECLARE_JSON_TYPE(NodeSummary)
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeSummary, quote_format, quote, committed_view, committed_seqno)

  // SNIPPET: registry_inheritance
  class NoBuiltinsRegistry : public ccf::BaseEndpointRegistry
  {
  public:
    NoBuiltinsRegistry(ccfapp::AbstractNodeContext& context) :
      ccf::BaseEndpointRegistry("app", context.get_node_state())
    {
      auto node_summary = [this](ccf::EndpointContext& ctx) {
        std::string error_reason;

        NodeSummary summary;

        {
          // SNIPPET_START: get_quote_api_v1
          std::vector<uint8_t> raw_quote;
          error_reason =
            get_quote_for_this_node_v1(ctx.tx, summary.quote_format, raw_quote);
          if (!error_reason.empty())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format("Failed to get quote: {}", error_reason));
            return;
          }

          summary.quote = fmt::format("{:02x}", fmt::join(raw_quote, ""));
          // SNIPPET_END: get_quote_api_v1
        }

        {
          error_reason = get_last_committed_txid_v1(
            summary.committed_view, summary.committed_seqno);
          if (!error_reason.empty())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "Failed to get committed transaction: {}", error_reason));
            return;
          }
        }

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_body(nlohmann::json(summary).dump(2));
      };
      make_endpoint(
        "node_summary", HTTP_GET, node_summary, ccf::no_auth_required)
        .set_auto_schema<void, NodeSummary>()
        .install();

      auto openapi = [this](kv::Tx& tx, nlohmann::json&&) {
        nlohmann::json document;
        const auto error_reason = generate_openapi_document_v1(
          tx,
          openapi_info.title,
          "A CCF sample demonstrating a minimal app, with no default endpoints",
          "0.0.1",
          document);

        if (error_reason.empty())
        {
          return ccf::make_success(document);
        }
        else
        {
          return ccf::make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            std::move(error_reason));
        }
      };
      make_endpoint(
        "api", HTTP_GET, ccf::json_adapter(openapi), ccf::no_auth_required)
        .set_auto_schema<void, ccf::GetAPI::Out>()
        .install();

      auto get_commit = [this](auto&, nlohmann::json&&) {
        ccf::GetCommit::Out out;
        const auto error_reason =
          get_last_committed_txid_v1(out.view, out.seqno);

        if (error_reason.empty())
        {
          return ccf::make_success(out);
        }
        else
        {
          return ccf::make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            std::move(error_reason));
        }
      };
      make_command_endpoint(
        "commit",
        HTTP_GET,
        ccf::json_command_adapter(get_commit),
        ccf::no_auth_required)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .set_auto_schema<void, ccf::GetCommit::Out>()
        .install();
    }
  };

  class NoBuiltinsFrontend : public ccf::UserRpcFrontend
  {
  private:
    NoBuiltinsRegistry nbr;

  public:
    NoBuiltinsFrontend(
      ccf::NetworkTables& network, ccfapp::AbstractNodeContext& context) :
      ccf::UserRpcFrontend(*network.tables, nbr),
      nbr(context)
    {}
  };
}

namespace ccfapp
{
  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context)
  {
    return std::make_shared<nobuiltins::NoBuiltinsFrontend>(nwt, context);
  }
}
