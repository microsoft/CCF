// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/ds/json.h"
#include "ccf/json_handler.h"

namespace localcommithandler
{
  struct Response
  {
    std::string tx_id;
    int64_t value;
  };

  DECLARE_JSON_TYPE(Response);
  DECLARE_JSON_REQUIRED_FIELDS(Response, tx_id, value);

  class LocalCommitHandlerRegistry : public ccf::UserEndpointRegistry
  {
  public:
    using CounterMap = kv::Map<std::string, int64_t>;

    LocalCommitHandlerRegistry(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      auto add_tx_id = [](auto& ctx, const auto txid) {
        ctx.rpc_ctx->set_response_header("mytxid", txid.to_str());

        const nlohmann::json body_j =
          nlohmann::json::parse(ctx.rpc_ctx->get_response_body());

        auto resp = body_j.get<Response>();
        resp.tx_id = txid.to_str();

        ctx.rpc_ctx->set_response_body(nlohmann::json(resp).dump());
      };

      auto add_tx_id_exception = [](auto& ctx, const auto txid) {
        ctx.rpc_ctx->set_response_header("mytxid", txid.to_str());

        const nlohmann::json body_j =
          nlohmann::json::parse(ctx.rpc_ctx->get_response_body());

        throw std::runtime_error("oops, might have failed serialization");

        auto resp = body_j.get<Response>();
        resp.tx_id = txid.to_str();

        ctx.rpc_ctx->set_response_body(nlohmann::json(resp).dump());
      };

      auto increment = [this](auto& ctx) {
        auto counter_handle = ctx.tx.template rw<CounterMap>("counters");

        auto current_value = counter_handle->get("counter").value_or(0);

        auto new_value = current_value + 1;
        counter_handle->put("counter", new_value);

        Response resp;
        resp.value = new_value;

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        ctx.rpc_ctx->set_response_body(nlohmann::json(resp).dump());
      };
      make_endpoint_with_commit_handler(
        "/increment", HTTP_POST, increment, add_tx_id, ccf::no_auth_required)
        .set_auto_schema<void, Response>()
        .install();

      make_endpoint_with_commit_handler(
        "/increment_exception",
        HTTP_POST,
        increment,
        add_tx_id_exception,
        ccf::no_auth_required)
        .set_auto_schema<void, Response>()
        .install();

      auto decrement = [this](auto& ctx) {
        auto counter_handle = ctx.tx.template rw<CounterMap>("counters");

        auto current_value = counter_handle->get("counter").value_or(0);

        auto new_value = current_value - 1;
        counter_handle->put("counter", new_value);

        Response resp;
        resp.value = new_value;

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        ctx.rpc_ctx->set_response_body(nlohmann::json(resp).dump());
      };
      make_endpoint_with_commit_handler(
        "/decrement", HTTP_POST, decrement, add_tx_id, ccf::no_auth_required)
        .set_auto_schema<void, Response>()
        .install();

      make_endpoint_with_commit_handler(
        "/decrement_exception",
        HTTP_POST,
        decrement,
        add_tx_id_exception,
        ccf::no_auth_required)
        .set_auto_schema<void, Response>()
        .install();

      auto value = [this](auto& ctx) {
        auto counter_handle = ctx.tx.template ro<CounterMap>("counters");

        auto current_value = counter_handle->get("counter").value_or(0);

        Response resp;
        resp.value = current_value;

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        ctx.rpc_ctx->set_response_body(nlohmann::json(resp).dump());
      };
      make_read_only_endpoint_with_commit_handler(
        "/value", HTTP_GET, value, add_tx_id, ccf::no_auth_required)
        .set_auto_schema<void, Response>()
        .install();

      make_read_only_endpoint_with_commit_handler(
        "/value_exception",
        HTTP_GET,
        value,
        add_tx_id_exception,
        ccf::no_auth_required)
        .set_auto_schema<void, Response>()
        .install();
    };
  };
};

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    return std::make_unique<localcommithandler::LocalCommitHandlerRegistry>(
      context);
  }
}
