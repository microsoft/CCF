// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define CCF_LOGGER_NO_DEPRECATE

#include "ccf/ds/json.h"
#include "ccf/ds/logger.h"
#include "curl/curl.h"
#include "http/curl.h"

#include <cstdlib>
#include <curl/header.h>
#include <iostream>
#include <llhttp/llhttp.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/x509_vfy.h>
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

TEST_CASE("Synchronous")
{
  Data data = {.foo = "alpha", .bar = "beta"};
  size_t response_count = 0;
  constexpr size_t sync_number_requests = 100;
  for (int i = 0; i < sync_number_requests; ++i)
  {
    data.iter = i;
    std::string url = fmt::format("http://{}/{}", server_address, i);
    auto body = std::make_unique<ccf::curl::RequestBody>(data);

    auto headers = ccf::curl::UniqueSlist();
    headers.append("Content-Type", "application/json");

    auto curl_handle = ccf::curl::UniqueCURL();

    auto request = std::make_unique<ccf::curl::CurlRequest>(
      std::move(curl_handle),
      HTTP_PUT,
      std::move(url),
      std::move(headers),
      std::move(body),
      std::make_unique<ccf::curl::ResponseBody>(SIZE_MAX),
      std::nullopt);

    CURLcode curl_code = CURLE_OK;
    long status_code = 0;

    request->synchronous_perform(curl_code, status_code);
    constexpr size_t HTTP_SUCCESS = 200;
    if (curl_code == CURLE_OK && status_code == HTTP_SUCCESS)
    {
      response_count++;
    }
  }
  REQUIRE(response_count == sync_number_requests);
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
    for (int i = 0; i < number_requests; ++i)
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

      auto response_callback = [response_count_ptr](
                                 ccf::curl::CurlRequest& request,
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
    for (int i = 0; i < slow_number_requests; ++i)
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

      auto response_callback = [response_count_ptr](
                                 ccf::curl::CurlRequest& request,
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
    for (int i = 0; i < number_requests; ++i)
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

      auto response_callback = [response_count_ptr](
                                 ccf::curl::CurlRequest& request,
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
    for (int i = 0; i < number_requests; ++i)
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

      auto response_callback = [response_count_ptr](
                                 ccf::curl::CurlRequest& request,
                                 CURLcode curl_response,
                                 long status_code) {
        //(void)request;
        LOG_INFO_FMT(
          "Request to {} completed: {} ({}) {}",
          request.get_url(),
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

  for (int i = 0; i < number_iterations; ++i)
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
