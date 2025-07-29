// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/ds/json.h"
#include "ccf/ds/quote_info.h"
#include "ccf/kv/version.h"
#include "ds/actors.h"
#include "http/curl.h"

#include <curl/curl.h>
#include <llhttp/llhttp.h>
#include <sys/types.h>

namespace ccf::self_healing_open
{
  struct RequestNodeInfo
  {
    QuoteInfo quote_info;
    std::string published_network_address;
    std::string intrinsic_id;
  };
  DECLARE_JSON_TYPE(RequestNodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    RequestNodeInfo, quote_info, published_network_address, intrinsic_id);

  struct GossipRequest
  {
    RequestNodeInfo info;
    ccf::kv::Version txid;
  };
  DECLARE_JSON_TYPE(GossipRequest);
  DECLARE_JSON_REQUIRED_FIELDS(GossipRequest, txid, info);

  struct VoteRequest
  {
    RequestNodeInfo info;
  };
  DECLARE_JSON_TYPE(VoteRequest);
  DECLARE_JSON_REQUIRED_FIELDS(VoteRequest, info);

  struct IAmOpenRequest
  {
    RequestNodeInfo info;
  };
  DECLARE_JSON_TYPE(IAmOpenRequest);
  DECLARE_JSON_REQUIRED_FIELDS(IAmOpenRequest, info);

  inline void dispatch_authenticated_message(
    nlohmann::json&& request,
    const std::string& target_address,
    const std::string& endpoint,
    const crypto::Pem& self_signed_node_cert,
    const crypto::Pem& privkey_pem)
  {
    curl::UniqueCURL curl_handle;

    // diable SSL verification as no private information is sent
    curl_handle.set_opt(CURLOPT_SSL_VERIFYHOST, 0L);
    curl_handle.set_opt(CURLOPT_SSL_VERIFYPEER, 0L);
    curl_handle.set_opt(CURLOPT_SSL_VERIFYSTATUS, 0L);

    curl_handle.set_blob_opt(
      CURLOPT_SSLCERT_BLOB,
      self_signed_node_cert.data(),
      self_signed_node_cert.size());
    curl_handle.set_opt(CURLOPT_SSLCERTTYPE, "PEM");

    curl_handle.set_blob_opt(
      CURLOPT_SSLKEY_BLOB, privkey_pem.data(), privkey_pem.size());
      curl_handle.set_opt(CURLOPT_SSLKEYTYPE, "PEM");

    auto url = fmt::format(
      "https://{}/{}/self_healing_open/{}",
      target_address,
      get_actor_prefix(ActorsType::nodes),
      endpoint);

    curl::UniqueSlist headers;
    headers.append("Content-Type", "application/json");

    auto body = std::make_unique<curl::RequestBody>(request);

    auto response_callback = [](
                               const ccf::curl::CurlRequest& request,
                               CURLcode curl_code,
                               long status_code) {
      LOG_TRACE_FMT(
        "Response received for {} to {}: curl_result {} ({}), status code {}",
        request.get_method().c_str(),
        request.get_url(),
        curl_easy_strerror(curl_code),
        curl_code,
        status_code);
    };

    auto curl_request = std::make_unique<curl::CurlRequest>(
      std::move(curl_handle),
      HTTP_PUT,
      std::move(url),
      std::move(headers),
      std::move(body),
      std::move(response_callback));

    LOG_TRACE_FMT(
      "Dispatching attested message for {} to {}: {}",
      curl_request->get_method().c_str(),
      curl_request->get_url(),
      request.dump());

    curl::CurlmLibuvContextSingleton::get_instance().attach_request(
      curl_request);
  }

}