// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// CCF
#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/ds/hash.h"
#include "ccf/http_query.h"
#include "ccf/json_handler.h"
#include "ccf/version.h"

#include <charconv>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

// Custom Endpoints
#include "custom_endpoints/registry.h"

using namespace nlohmann;

namespace basicapp
{
  using RecordsMap = kv::Map<std::string, std::vector<uint8_t>>;
  static constexpr auto PRIVATE_RECORDS = "records";

  // By subclassing CustomJSEndpointRegistry, this application gains the ability
  // to install and execute custom JavaScript endpoints.
  // CustomJSEndpointRegistry adds a single built-in C++ endpoint installed at a
  // parametrable path (second argument to the constructor) that enables a user
  // for which with user_data["isAdmin"] is true to install custom JavaScript
  // endpoints. The JavaScript code for these endpoints is stored in the
  // internal KV store under a namespace configured in the second argument to
  // the constructor. PUT /app/custom_endpoints (in this case) is logically
  // equivalent to passing a set_js_app proposal in governance, except the
  // application resides in the application space.
  //
  // Known limitations:
  //
  // No auditability yet, COSE Sign1 auth is mandated, but the signature is not
  // stored. No support for historical endpoints yet.
  //
  // Additional functionality compared to set_js_app:
  // The KV namespace can be private, to keep the application confidential if
  // desired.
  class BasicHandlers : public basicapp::CustomJSEndpointRegistry
  {
  public:
    BasicHandlers(ccfapp::AbstractNodeContext& context) :
      basicapp::CustomJSEndpointRegistry(
        context,
        "custom_endpoints", // Custom JS endpoints can be install with PUT
                            // /app/custom_endpoints
        "public:custom_endpoints" // Internal KV space will be under
                                  // public:custom_endpoints.*
      )
    {
      openapi_info.title = "CCF Basic App";
      openapi_info.description =
        "Lightweight application for benchmarking purposes";
      openapi_info.document_version = "0.0.1";

      auto put = [this](ccf::endpoints::EndpointContext& ctx) {
        std::string key;
        std::string error;
        if (!get_path_param(
              ctx.rpc_ctx->get_request_path_params(), "key", key, error))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NO_CONTENT,
            ccf::errors::InvalidResourceName,
            "Missing key");
          return;
        }

        auto records_handle = ctx.tx.template rw<RecordsMap>(PRIVATE_RECORDS);
        records_handle->put(key, ctx.rpc_ctx->get_request_body());
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
      };
      make_endpoint(
        "/records/{key}", HTTP_PUT, put, {ccf::user_cert_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto get = [this](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
        std::string key;
        std::string error;
        if (!get_path_param(
              ctx.rpc_ctx->get_request_path_params(), "key", key, error))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NO_CONTENT,
            ccf::errors::InvalidResourceName,
            "Missing key");
          return;
        }

        auto records_handle = ctx.tx.template ro<RecordsMap>(PRIVATE_RECORDS);
        auto record = records_handle->get(key);

        if (record.has_value())
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          ctx.rpc_ctx->set_response_body(record.value());
          return;
        }

        ctx.rpc_ctx->set_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::InvalidResourceName,
          "No such key");
      };
      make_read_only_endpoint(
        "/records/{key}", HTTP_GET, get, {ccf::user_cert_auth_policy})
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto post = [this](ccf::endpoints::EndpointContext& ctx) {
        const nlohmann::json body =
          nlohmann::json::parse(ctx.rpc_ctx->get_request_body());

        const auto records = body.get<std::map<std::string, std::string>>();

        auto records_handle = ctx.tx.template rw<RecordsMap>(PRIVATE_RECORDS);
        for (const auto& [key, value] : records)
        {
          const std::vector<uint8_t> value_vec(value.begin(), value.end());
          records_handle->put(key, value_vec);
        }
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
      };
      make_endpoint("/records", HTTP_POST, post, {ccf::user_cert_auth_policy})
        .install();
    }
  };
}

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    return std::make_unique<basicapp::BasicHandlers>(context);
  }
}
