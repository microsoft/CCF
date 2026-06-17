// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "enclave/rpc_handler.h"
#include "enclave/rpc_map.h"
#include "http/http_rpc_context.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

namespace
{
  std::shared_ptr<http::HttpRpcContext> make_test_context()
  {
    auto session = std::make_shared<ccf::SessionContext>(
      0, std::vector<uint8_t>{}, std::nullopt);
    return std::make_shared<http::HttpRpcContext>(
      session,
      ccf::HttpVersion::HTTP1,
      HTTP_GET,
      "/",
      ccf::http::HeaderMap{},
      std::vector<uint8_t>{});
  }
}

TEST_CASE("Deferred response completion is single use")
{
  auto ctx = make_test_context();
  ctx->set_deferred_response_allowed(true);
  auto deferred = ctx->defer_response();

  ccf::http::HeaderMap headers;
  headers[ccf::http::headers::CONTENT_TYPE] =
    ccf::http::headervalues::contenttype::TEXT;

  REQUIRE(
    deferred->complete(HTTP_STATUS_ACCEPTED, "accepted", std::move(headers)));
  REQUIRE(deferred->is_complete());
  REQUIRE_FALSE(deferred->complete(HTTP_STATUS_OK, "second"));

  REQUIRE(ctx->response_is_pending);
  REQUIRE(ctx->get_response_status() == HTTP_STATUS_ACCEPTED);
  const auto response_headers = ctx->get_response_headers();
  REQUIRE(
    response_headers.at(ccf::http::headers::CONTENT_TYPE) ==
    ccf::http::headervalues::contenttype::TEXT);
  const auto& body = ctx->get_response_body();
  REQUIRE(std::string(body.begin(), body.end()) == "accepted");
}

TEST_CASE("Deferred response cancellation sets an error response")
{
  auto ctx = make_test_context();
  ctx->set_deferred_response_allowed(true);
  auto deferred = ctx->defer_response();

  REQUIRE(deferred->cancel(ccf::ErrorDetails{
    HTTP_STATUS_GATEWAY_TIMEOUT,
    ccf::errors::InternalError,
    "external request timed out"}));
  REQUIRE(deferred->is_complete());
  REQUIRE_FALSE(deferred->cancel(ccf::ErrorDetails{
    HTTP_STATUS_INTERNAL_SERVER_ERROR, ccf::errors::InternalError, "second"}));

  REQUIRE(ctx->get_response_status() == HTTP_STATUS_GATEWAY_TIMEOUT);
  const auto& body = ctx->get_response_body();
  const std::string body_s(body.begin(), body.end());
  REQUIRE(body_s.find("external request timed out") != std::string::npos);
}

TEST_CASE("Deferred response is rejected unless explicitly allowed")
{
  auto ctx = make_test_context();

  REQUIRE_THROWS_WITH(
    ctx->defer_response(),
    "Deferred responses are only supported by command and read-only endpoints");
}
