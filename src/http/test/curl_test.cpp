// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/json.h"
#include "curl/curl.h"
#include "ds/internal_logger.h"
#include "http/curl.h"

#include <cstdlib>
#include <curl/header.h>
#include <fstream>
#include <iostream>
#include <llhttp/llhttp.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/x509_vfy.h>
#include <optional>
#include <random>
#include <span>
#include <uv.h>

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

static std::string server_address = "127.0.0.1:8080";

struct Data
{
  std::string foo;
  std::string bar;
  uint8_t iter = 0;
};

DECLARE_JSON_TYPE(Data);
DECLARE_JSON_REQUIRED_FIELDS(Data, foo, bar, iter);

TEST_CASE("is_transient_transport_error classifies curl errors")
{
  // Transport/protocol-layer failures that a retry loop (e.g. the node join
  // client) should retry rather than treat as fatal.
  const std::vector<CURLcode> transient = {
    CURLE_COULDNT_RESOLVE_PROXY,
    CURLE_COULDNT_RESOLVE_HOST,
    CURLE_COULDNT_CONNECT,
    CURLE_OPERATION_TIMEDOUT,
    CURLE_GOT_NOTHING,
    CURLE_RECV_ERROR,
    CURLE_SEND_ERROR,
    CURLE_PARTIAL_FILE,
    CURLE_WEIRD_SERVER_REPLY,
    CURLE_HTTP2,
    CURLE_HTTP2_STREAM,
  };
  for (const auto code : transient)
  {
    INFO("code = " << static_cast<int>(code));
    CHECK(ccf::curl::is_transient_transport_error(code));
  }

  // Errors that must be treated as fatal (never retried): TLS/certificate
  // failures, application-level errors, and our own response size-cap
  // rejection (CURLE_WRITE_ERROR). CURLE_OK and CURLE_ABORTED_BY_CALLBACK are
  // not transport errors either.
  const std::vector<CURLcode> fatal = {
    CURLE_OK,
    CURLE_PEER_FAILED_VERIFICATION,
    CURLE_SSL_CACERT_BADFILE,
    CURLE_SSL_CONNECT_ERROR,
    CURLE_SSL_CERTPROBLEM,
    CURLE_USE_SSL_FAILED,
    CURLE_WRITE_ERROR,
    CURLE_TOO_MANY_REDIRECTS,
    CURLE_UNSUPPORTED_PROTOCOL,
    CURLE_ABORTED_BY_CALLBACK,
  };
  for (const auto code : fatal)
  {
    INFO("code = " << static_cast<int>(code));
    CHECK_FALSE(ccf::curl::is_transient_transport_error(code));
  }
}

TEST_CASE("ResponseHeaders rejects oversized headers")
{
  ccf::curl::ResponseHeaders headers;
  std::string status = "HTTP/1.1 200 OK\r\n";
  REQUIRE(
    ccf::curl::ResponseHeaders::recv_header_line(
      status.data(), 1, status.size(), &headers) == status.size());

  std::string oversized_value(
    ccf::http::default_max_header_size.count_bytes() + 1, 'x');
  std::string header = fmt::format("X-Large: {}\r\n", oversized_value);
  REQUIRE(
    ccf::curl::ResponseHeaders::recv_header_line(
      header.data(), 1, header.size(), &headers) == 0);
}

TEST_CASE("ResponseHeaders rejects oversized header fields")
{
  ccf::curl::ResponseHeaders headers;
  std::string status = "HTTP/1.1 200 OK\r\n";
  REQUIRE(
    ccf::curl::ResponseHeaders::recv_header_line(
      status.data(), 1, status.size(), &headers) == status.size());

  std::string oversized_field(
    ccf::http::default_max_header_size.count_bytes() + 1, 'x');
  std::string header = fmt::format("{}: value\r\n", oversized_field);
  REQUIRE(
    ccf::curl::ResponseHeaders::recv_header_line(
      header.data(), 1, header.size(), &headers) == 0);
}

TEST_CASE("ResponseHeaders rejects too many headers")
{
  ccf::curl::ResponseHeaders headers;
  std::string status = "HTTP/1.1 200 OK\r\n";
  REQUIRE(
    ccf::curl::ResponseHeaders::recv_header_line(
      status.data(), 1, status.size(), &headers) == status.size());

  for (size_t i = 0; i < ccf::http::default_max_headers_count; ++i)
  {
    std::string header = fmt::format("X-Test-{}: value\r\n", i);
    REQUIRE(
      ccf::curl::ResponseHeaders::recv_header_line(
        header.data(), 1, header.size(), &headers) == header.size());
  }

  std::string header = "X-Too-Many: value\r\n";
  REQUIRE(
    ccf::curl::ResponseHeaders::recv_header_line(
      header.data(), 1, header.size(), &headers) == 0);
}

TEST_CASE("CurlmLibuvContext aborts queued requests on close")
{
  size_t response_count = 0;
  CURLcode observed_curl_response = CURLE_OK;
  long observed_status_code = -1;

  {
    ccf::curl::CurlmLibuvContextSingleton singleton(uv_default_loop());

    auto response_callback =
      [&response_count, &observed_curl_response, &observed_status_code](
        std::unique_ptr<ccf::curl::CurlRequest>&& request,
        CURLcode curl_response,
        long status_code) {
        REQUIRE(request != nullptr);
        response_count++;
        observed_curl_response = curl_response;
        observed_status_code = status_code;
      };

    auto request = std::make_unique<ccf::curl::CurlRequest>(
      ccf::curl::UniqueCURL(),
      HTTP_GET,
      "http://127.0.0.1:1/pending",
      ccf::curl::UniqueSlist(),
      nullptr,
      std::make_unique<ccf::curl::ResponseBody>(SIZE_MAX),
      std::move(response_callback));

    ccf::curl::CurlmLibuvContextSingleton::get_instance()->attach_request(
      std::move(request));
  }

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);

  REQUIRE(response_count == 1);
  REQUIRE(observed_curl_response == CURLE_ABORTED_BY_CALLBACK);
  REQUIRE(observed_status_code == 0);
}

TEST_CASE("Synchronous")
{
  Data data = {.foo = "alpha", .bar = "beta"};
  size_t response_count = 0;
  constexpr size_t sync_number_requests = 10;
  for (size_t i = 0; i < sync_number_requests; ++i)
  {
    data.iter = i;
    std::string url = fmt::format("http://{}/{}", server_address, i);
    auto body = std::make_unique<ccf::curl::RequestBody>(data);

    auto headers = ccf::curl::UniqueSlist();
    headers.append("Content-Type", "application/json");

    auto curl_handle = ccf::curl::UniqueCURL();

    CURLcode curl_code = CURLE_OK;
    long status_code = 0;

    auto response = [&curl_code, &status_code](
                      std::unique_ptr<ccf::curl::CurlRequest>&& /*request*/,
                      CURLcode curl_response,
                      long status) {
      curl_code = curl_response;
      status_code = status;
    };

    auto request = std::make_unique<ccf::curl::CurlRequest>(
      std::move(curl_handle),
      HTTP_PUT,
      std::move(url),
      std::move(headers),
      std::move(body),
      std::make_unique<ccf::curl::ResponseBody>(SIZE_MAX),
      response);

    ccf::curl::CurlRequest::synchronous_perform(std::move(request));

    constexpr size_t HTTP_SUCCESS = 200;
    if (curl_code == CURLE_OK && status_code == HTTP_SUCCESS)
    {
      response_count++;
    }
  }
  REQUIRE(response_count == sync_number_requests);
}

TEST_CASE("Synchronous POST echoes body")
{
  // Exercises POST-with-body support in the curl wrapper: the echo server
  // reflects the request method and body, so we can assert that both were
  // transmitted correctly.
  const std::string sent_body = R"({"message":"join","iter":42})";
  std::vector<uint8_t> body_bytes(sent_body.begin(), sent_body.end());
  auto body = std::make_unique<ccf::curl::RequestBody>(std::move(body_bytes));

  auto headers = ccf::curl::UniqueSlist();
  headers.append("Content-Type", "application/json");

  auto curl_handle = ccf::curl::UniqueCURL();
  std::string url = fmt::format("http://{}/join", server_address);

  CURLcode curl_code = CURLE_FAILED_INIT;
  long status_code = 0;
  std::string response_body;

  auto response = [&curl_code, &status_code, &response_body](
                    std::unique_ptr<ccf::curl::CurlRequest>&& request,
                    CURLcode curl_response,
                    long status) {
    curl_code = curl_response;
    status_code = status;
    auto* rb = request->get_response_body();
    response_body = std::string(rb->buffer.begin(), rb->buffer.end());
  };

  auto request = std::make_unique<ccf::curl::CurlRequest>(
    std::move(curl_handle),
    HTTP_POST,
    std::move(url),
    std::move(headers),
    std::move(body),
    std::make_unique<ccf::curl::ResponseBody>(SIZE_MAX),
    response);

  ccf::curl::CurlRequest::synchronous_perform(std::move(request));

  constexpr long HTTP_SUCCESS = 200;
  REQUIRE(curl_code == CURLE_OK);
  REQUIRE(status_code == HTTP_SUCCESS);

  const auto parsed = nlohmann::json::parse(response_body);
  REQUIRE(parsed.at("metadata").at("method") == "POST");
  REQUIRE(parsed.at("body") == sent_body);
}

TEST_CASE("VERIFYHOST rejects a certificate SAN mismatch")
{
  // Guards the TLS hostname-verification hardening the node join client relies
  // on: with the same pinned CA and the same connection,
  // CURLOPT_SSL_VERIFYHOST == 2 must reject a certificate whose SAN does not
  // cover the dialed host, and accept one that does. Requires the HTTPS test
  // server started by e2e_curl.py (self-signed cert with a single dNSName SAN,
  // served on the loopback IP).
  const char* tls_addr_env = std::getenv("TLS_SERVER_ADDR");
  const char* tls_san_env = std::getenv("TLS_SERVER_SAN");
  const char* tls_ca_env = std::getenv("TLS_SERVER_CA");
  if (
    tls_addr_env == nullptr || tls_san_env == nullptr || tls_ca_env == nullptr)
  {
    MESSAGE("Skipping: TLS_SERVER_* env not set (run via e2e_curl.py)");
    return;
  }

  const std::string tls_addr = tls_addr_env;
  const std::string tls_san = tls_san_env;

  std::string ca_pem;
  {
    std::ifstream ca_file(tls_ca_env, std::ios::binary);
    REQUIRE(ca_file.good());
    ca_pem.assign(
      std::istreambuf_iterator<char>(ca_file),
      std::istreambuf_iterator<char>());
  }
  REQUIRE(!ca_pem.empty());

  // TLS_SERVER_ADDR is "<host>:<port>".
  const auto colon = tls_addr.rfind(':');
  REQUIRE(colon != std::string::npos);
  const std::string tls_host = tls_addr.substr(0, colon);
  const std::string tls_port = tls_addr.substr(colon + 1);

  auto perform_get = [&](
                       const std::string& url,
                       long verifyhost,
                       const std::optional<std::string>& resolve_entry) {
    auto curl_handle = ccf::curl::UniqueCURL();
    curl_handle.set_opt(CURLOPT_SSL_VERIFYPEER, 1L);
    curl_handle.set_opt(CURLOPT_SSL_VERIFYHOST, verifyhost);
    curl_handle.set_opt(CURLOPT_PROTOCOLS_STR, "https");
    curl_handle.set_blob_opt(
      CURLOPT_CAINFO_BLOB,
      reinterpret_cast<const uint8_t*>(ca_pem.data()),
      ca_pem.size());
    curl_handle.set_opt(CURLOPT_CAPATH, nullptr);
    curl_handle.set_opt(CURLOPT_CONNECTTIMEOUT, 5L);
    curl_handle.set_opt(CURLOPT_TIMEOUT, 10L);

    auto resolve = ccf::curl::UniqueSlist();
    if (resolve_entry.has_value())
    {
      resolve.append(resolve_entry->c_str());
      curl_handle.set_opt(CURLOPT_RESOLVE, resolve.get());
    }

    CURLcode result = CURLE_FAILED_INIT;
    auto callback = [&result](
                      std::unique_ptr<ccf::curl::CurlRequest>&& /*request*/,
                      CURLcode curl_response,
                      long /*status*/) { result = curl_response; };

    ccf::curl::CurlRequest::synchronous_perform(
      std::make_unique<ccf::curl::CurlRequest>(
        std::move(curl_handle),
        HTTP_GET,
        url,
        ccf::curl::UniqueSlist(),
        nullptr,
        std::make_unique<ccf::curl::ResponseBody>(SIZE_MAX),
        callback));
    return result;
  };

  SUBCASE("VERIFYHOST=2 rejects a host absent from the certificate SAN")
  {
    // The certificate's only SAN is a dNSName, so dialing the loopback IP
    // directly must fail hostname verification.
    const auto result =
      perform_get(fmt::format("https://{}/", tls_addr), 2L, std::nullopt);
    REQUIRE(result == CURLE_PEER_FAILED_VERIFICATION);
  }

  SUBCASE("VERIFYHOST=2 accepts the certificate SAN host")
  {
    // Dial the SAN name, resolved to the server's loopback address.
    const auto result = perform_get(
      fmt::format("https://{}:{}/", tls_san, tls_port),
      2L,
      fmt::format("{}:{}:{}", tls_san, tls_port, tls_host));
    REQUIRE(result == CURLE_OK);
  }

  SUBCASE("VERIFYHOST=0 accepts the mismatched host (control)")
  {
    // With hostname verification disabled the same mismatched connection
    // succeeds, proving the CA/cert/connection are otherwise valid and that
    // the hostname check is the sole discriminator.
    const auto result =
      perform_get(fmt::format("https://{}/", tls_addr), 0L, std::nullopt);
    REQUIRE(result == CURLE_OK);
  }
}

TEST_CASE("CurlmLibuvContext")
{
  size_t response_count = 0;
  constexpr size_t number_requests = 1000;
  auto load_generator = [](uv_work_t* req) {
    thread_local std::random_device rd;
    thread_local std::mt19937 gen(rd());
    constexpr size_t max_delay_ms = 10;
    thread_local std::uniform_int_distribution<> uniform_dist(1, max_delay_ms);
    auto* response_count_ptr = reinterpret_cast<size_t*>(req->data);
    Data data = {.foo = "alpha", .bar = "beta"};
    for (size_t i = 0; i < number_requests; ++i)
    {
      auto delay = uniform_dist(gen);
      std::this_thread::sleep_for(std::chrono::milliseconds(delay));

      data.iter = i;
      std::string url = fmt::format("http://{}/{}", server_address, i);
      auto body = std::make_unique<ccf::curl::RequestBody>(data);

      auto headers = ccf::curl::UniqueSlist();
      headers.append("Content-Type", "application/json");

      auto curl_handle = ccf::curl::UniqueCURL();
      curl_handle.set_opt(CURLOPT_FORBID_REUSE, 1L);

      auto response_callback =
        [response_count_ptr](
          std::unique_ptr<ccf::curl::CurlRequest>&& request,
          CURLcode curl_response,
          long status_code) {
          (void)request;
          constexpr size_t HTTP_SUCCESS = 200;
          if (curl_response == CURLE_OK && status_code == HTTP_SUCCESS)
          {
            (*response_count_ptr)++;
          }
        };

      auto request = std::make_unique<ccf::curl::CurlRequest>(
        std::move(curl_handle),
        HTTP_PUT,
        std::move(url),
        std::move(headers),
        std::move(body),
        std::make_unique<ccf::curl::ResponseBody>(SIZE_MAX),
        std::move(response_callback));

      ccf::curl::CurlmLibuvContextSingleton::get_instance()->attach_request(
        std::move(request));
    }
  };

  {
    ccf::curl::CurlmLibuvContextSingleton singleton(uv_default_loop());

    uv_work_t work_req;
    work_req.data = &response_count;
    uv_queue_work(uv_default_loop(), &work_req, load_generator, nullptr);
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  }
  REQUIRE(response_count == number_requests);
}

TEST_CASE("CurlmLibuvContext slow")
{
  size_t response_count = 0;
  constexpr size_t slow_number_requests = 10;
  auto load_generator = [](uv_work_t* req) {
    thread_local std::random_device rd;
    thread_local std::mt19937 gen(rd());
    constexpr size_t max_delay_ms = 2000;
    thread_local std::uniform_int_distribution<> uniform_dist(1, max_delay_ms);
    auto* response_count_ptr = reinterpret_cast<size_t*>(req->data);
    (void)req;
    Data data = {.foo = "alpha", .bar = "beta"};
    for (size_t i = 0; i < slow_number_requests; ++i)
    {
      auto delay = uniform_dist(gen);
      std::this_thread::sleep_for(std::chrono::milliseconds(delay));

      data.iter = i;
      std::string url = fmt::format("http://{}/{}", server_address, i);
      auto body = std::make_unique<ccf::curl::RequestBody>(data);

      auto headers = ccf::curl::UniqueSlist();
      headers.append("Content-Type", "application/json");

      auto curl_handle = ccf::curl::UniqueCURL();
      curl_handle.set_opt(CURLOPT_FORBID_REUSE, 1L);

      auto response_callback =
        [response_count_ptr](
          std::unique_ptr<ccf::curl::CurlRequest>&& request,
          CURLcode curl_response,
          long status_code) {
          (void)request;
          constexpr size_t HTTP_SUCCESS = 200;
          if (curl_response == CURLE_OK && status_code == HTTP_SUCCESS)
          {
            (*response_count_ptr)++;
          }
        };

      auto request = std::make_unique<ccf::curl::CurlRequest>(
        std::move(curl_handle),
        HTTP_PUT,
        std::move(url),
        std::move(headers),
        std::move(body),
        std::make_unique<ccf::curl::ResponseBody>(SIZE_MAX),
        std::move(response_callback));

      ccf::curl::CurlmLibuvContextSingleton::get_instance()->attach_request(
        std::move(request));
    }
  };

  {
    ccf::curl::CurlmLibuvContextSingleton singleton(uv_default_loop());

    uv_work_t work_req;
    work_req.data = &response_count;
    uv_queue_work(uv_default_loop(), &work_req, load_generator, nullptr);
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  }
  REQUIRE(response_count == slow_number_requests);
}

TEST_CASE("CurlmLibuvContext timeouts")
{
  size_t response_count = 0;
  constexpr size_t number_requests = 1000;

  auto load_generator = [](uv_work_t* req) {
    thread_local std::random_device rd;
    thread_local std::mt19937 gen(rd());
    constexpr size_t max_delay_ms = 40;
    thread_local std::uniform_int_distribution<> uniform_dist(1, max_delay_ms);
    auto* response_count_ptr = reinterpret_cast<size_t*>(req->data);
    (void)req;

    Data data = {.foo = "alpha", .bar = "beta"};
    for (size_t i = 0; i < number_requests; ++i)
    {
      auto delay = uniform_dist(gen);
      std::this_thread::sleep_for(std::chrono::milliseconds(delay));

      data.iter = i;

      // 192.0.2.0/24 (TEST-NET-1) is reserved (RFC 5737) and should be
      // unroutable.
      const std::string unreachable_base = "http://192.0.2.1:65535";
      std::string url = fmt::format("{}/{}", unreachable_base, i);
      auto body = std::make_unique<ccf::curl::RequestBody>(data);

      auto headers = ccf::curl::UniqueSlist();
      headers.append("Content-Type", "application/json");

      auto curl_handle = ccf::curl::UniqueCURL();
      curl_handle.set_opt(CURLOPT_TIMEOUT_MS, max_delay_ms);
      curl_handle.set_opt(CURLOPT_FORBID_REUSE, 1L);

      auto response_callback =
        [response_count_ptr](
          std::unique_ptr<ccf::curl::CurlRequest>&& request,
          CURLcode curl_response,
          long status_code) {
          (void)request;
          // We expect all to fail to connect; count only unexpected successes.
          constexpr size_t HTTP_SUCCESS = 200;
          if (curl_response == CURLE_OK && status_code == HTTP_SUCCESS)
          {
            (*response_count_ptr)++;
          }
        };

      auto request = std::make_unique<ccf::curl::CurlRequest>(
        std::move(curl_handle),
        HTTP_PUT,
        std::move(url),
        std::move(headers),
        std::move(body),
        std::make_unique<ccf::curl::ResponseBody>(SIZE_MAX),
        std::move(response_callback));

      ccf::curl::CurlmLibuvContextSingleton::get_instance()->attach_request(
        std::move(request));
    }
  };

  {
    ccf::curl::CurlmLibuvContextSingleton singleton(uv_default_loop());

    uv_work_t work_req;
    work_req.data = &response_count;
    uv_queue_work(uv_default_loop(), &work_req, load_generator, nullptr);
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  }
  // All should fail to reach the unreachable host.
  REQUIRE(response_count == 0);
}

TEST_CASE("CurlmLibuvContext multiple init")
{
  size_t response_count = 0;
  constexpr size_t number_iterations = 10;
  constexpr size_t number_requests = 10;

  auto load_generator = [](uv_work_t* req) {
    thread_local std::random_device rd;
    thread_local std::mt19937 gen(rd());
    constexpr size_t max_delay_ms = 40;
    thread_local std::uniform_int_distribution<> uniform_dist(1, max_delay_ms);
    auto* response_count_ptr = reinterpret_cast<size_t*>(req->data);
    (void)req;

    Data data = {.foo = "alpha", .bar = "beta"};
    for (size_t i = 0; i < number_requests; ++i)
    {
      auto delay = uniform_dist(gen);
      std::this_thread::sleep_for(std::chrono::milliseconds(delay));

      data.iter = i;

      std::string url = fmt::format("http://{}/{}", server_address, i);
      auto body = std::make_unique<ccf::curl::RequestBody>(data);

      auto headers = ccf::curl::UniqueSlist();
      headers.append("Content-Type", "application/json");

      auto curl_handle = ccf::curl::UniqueCURL();
      curl_handle.set_opt(CURLOPT_TIMEOUT_MS, max_delay_ms);
      curl_handle.set_opt(CURLOPT_FORBID_REUSE, 1L);

      auto response_callback =
        [response_count_ptr](
          std::unique_ptr<ccf::curl::CurlRequest>&& request,
          CURLcode curl_response,
          long status_code) {
          //(void)request;
          LOG_INFO_FMT(
            "Request to {} completed: {} ({}) {}",
            request->get_url(),
            curl_easy_strerror(curl_response),
            curl_response,
            status_code);

          // We expect all to fail to connect; count only unexpected successes.
          constexpr size_t HTTP_SUCCESS = 200;
          if (curl_response == CURLE_OK && status_code == HTTP_SUCCESS)
          {
            (*response_count_ptr)++;
          }
        };

      auto request = std::make_unique<ccf::curl::CurlRequest>(
        std::move(curl_handle),
        HTTP_PUT,
        std::move(url),
        std::move(headers),
        std::move(body),
        std::make_unique<ccf::curl::ResponseBody>(SIZE_MAX),
        std::move(response_callback));

      ccf::curl::CurlmLibuvContextSingleton::get_instance()->attach_request(
        std::move(request));
    }
  };

  for (size_t i = 0; i < number_iterations; ++i)
  {
    ccf::curl::CurlmLibuvContextSingleton singleton(uv_default_loop());

    uv_work_t work_req;
    work_req.data = &response_count;
    uv_queue_work(uv_default_loop(), &work_req, load_generator, nullptr);
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  }
  // All should fail to reach the unreachable host.
  REQUIRE(response_count == number_iterations * number_requests);
}

int main(int argc, char** argv)
{
  // NOLINTNEXTLINE(concurrency-mt-unsafe)
  auto* addr_ptr = std::getenv("ECHO_SERVER_ADDR");
  if (addr_ptr != nullptr)
  {
    server_address = std::string(addr_ptr);
  }
  ccf::logger::config::default_init();
  curl_global_init(CURL_GLOBAL_DEFAULT);
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  curl_global_cleanup();
  return res;
}
