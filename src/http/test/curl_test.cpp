// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define CCF_LOGGER_NO_DEPRECATE

#include "ccf/ds/json.h"
#include "ccf/ds/logger.h"
#include "curl/curl.h"
#include "http/curl.h"

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

struct Data
{
  std::string foo;
  std::string bar;
  uint8_t iter = 0;
};

DECLARE_JSON_TYPE(Data);
DECLARE_JSON_REQUIRED_FIELDS(Data, foo, bar, iter);

constexpr size_t number_requests = 1000;

TEST_CASE("Synchronous")
{
  Data data = {.foo = "alpha", .bar = "beta"};
  size_t response_count = 0;
  constexpr size_t sync_number_requests = number_requests / 10;
  for (int i = 0; i < sync_number_requests; ++i)
  {
    data.iter = i;
    std::string url = fmt::format("http://localhost:8080/{}", i);
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

static size_t response_count = 0;

TEST_CASE("CurlmLibuvContext")
{
  auto load_generator = [](uv_work_t* req) {
    thread_local std::random_device rd;
    thread_local std::mt19937 gen(rd());
    constexpr size_t max_delay_ms = 10;
    thread_local std::uniform_int_distribution<> uniform_dist(1, max_delay_ms);
    (void)req;
    Data data = {.foo = "alpha", .bar = "beta"};
    for (int i = 0; i < number_requests; ++i)
    {
      auto delay = uniform_dist(gen);
      std::this_thread::sleep_for(std::chrono::milliseconds(delay));

      data.iter = i;
      std::string url = fmt::format("http://localhost:8080/{}", i);
      auto body = std::make_unique<ccf::curl::RequestBody>(data);

      auto headers = ccf::curl::UniqueSlist();
      headers.append("Content-Type", "application/json");

      auto curl_handle = ccf::curl::UniqueCURL();

      auto response_callback = [](
                                 ccf::curl::CurlRequest& request,
                                 CURLcode curl_response,
                                 long status_code) {
        (void)request;
        constexpr size_t HTTP_SUCCESS = 200;
        if (curl_response == CURLE_OK && status_code == HTTP_SUCCESS)
        {
          response_count++;
        }
      };

      auto request = std::make_unique<ccf::curl::CurlRequest>(
        std::move(curl_handle),
        HTTP_PUT,
        std::move(url),
        std::move(headers),
        std::move(body),
        std::move(response_callback));

      ccf::curl::CurlmLibuvContextSingleton::get_instance().attach_request(
        request);
    }
  };

  ccf::curl::CurlmLibuvContext context(uv_default_loop());
  ccf::curl::CurlmLibuvContextSingleton::get_instance_unsafe() = &context;

  uv_work_t work_req;
  uv_queue_work(uv_default_loop(), &work_req, load_generator, nullptr);
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  REQUIRE(response_count == number_requests);
}

int main(int argc, char** argv)
{
  ccf::logger::config::default_init();
  curl_global_init(CURL_GLOBAL_DEFAULT);
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  curl_global_cleanup();
  return res;
}
