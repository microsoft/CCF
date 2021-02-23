// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/serialized.h"
#include "enclave/rpc_context.h"
#include "http_parser.h"
#include "http_sig.h"
#include "node/rpc/error.h"
#include "node/rpc/tx_status.h"
#include "ws_builder.h"

namespace ws
{
  static std::vector<uint8_t> serialise(
    size_t code,
    const std::vector<uint8_t>& body,
    kv::Version seqno = kv::NoVersion,
    kv::Consensus::View view = ccf::VIEW_UNKNOWN)
  {
    return make_out_frame(code, seqno, view, body);
  };

  inline std::vector<uint8_t> error(ccf::ErrorDetails&& error)
  {
    nlohmann::json body = ccf::ODataErrorResponse{
      ccf::ODataError{std::move(error.code), std::move(error.msg)}};
    const auto s = body.dump();

    std::vector<uint8_t> data(s.begin(), s.end());
    return serialise(error.status, data);
  }

  inline std::vector<uint8_t> error(
    http_status status, const std::string& code, std::string&& msg)
  {
    return error({status, code, std::move(msg)});
  }

  class WsRpcContext : public enclave::RpcContext
  {
  private:
    size_t request_index;

    ccf::RESTVerb verb = ws::Verb::WEBSOCKET;

    std::string path = {};
    std::string method = {};

    http::HeaderMap request_headers = {};

    std::vector<uint8_t> request_body = {};
    enclave::PathParams path_params = {};

    std::vector<uint8_t> serialised_request = {};

    std::string query = {};

    std::vector<uint8_t> response_body = {};
    http_status response_status = HTTP_STATUS_OK;
    std::optional<bool> explicit_apply_writes = std::nullopt;

    size_t seqno = 0;
    size_t view = 0;

  public:
    WsRpcContext(
      size_t request_index_,
      std::shared_ptr<enclave::SessionContext> s,
      const std::string_view& path_,
      const std::vector<uint8_t>& body_,
      const std::vector<uint8_t>& raw_request_ = {},
      const std::vector<uint8_t>& raw_bft_ = {}) :
      RpcContext(s, raw_bft_),
      request_index(request_index_),
      path(path_),
      method(path_),
      request_body(body_),
      serialised_request(raw_request_)
    {}

    virtual enclave::FrameFormat frame_format() const override
    {
      return enclave::FrameFormat::ws;
    }

    virtual size_t get_request_index() const override
    {
      return request_index;
    }

    virtual const std::vector<uint8_t>& get_request_body() const override
    {
      return request_body;
    }

    virtual const std::string& get_request_query() const override
    {
      return query;
    }

    virtual enclave::PathParams& get_request_path_params() override
    {
      return path_params;
    }

    virtual const ccf::RESTVerb& get_request_verb() const override
    {
      return verb;
    }

    virtual std::string get_request_path() const override
    {
      return method;
    }

    virtual const std::vector<uint8_t>& get_serialised_request() override
    {
      if (serialised_request.empty())
      {
        auto sr = make_in_frame(path, request_body);
        serialised_request.swap(sr);
      }
      return serialised_request;
    }

    virtual std::string get_method() const override
    {
      return method;
    }

    virtual void set_method(const std::string_view& p) override
    {
      method = p;
    }

    virtual const http::HeaderMap& get_request_headers() const override
    {
      return request_headers;
    }

    virtual std::optional<std::string> get_request_header(
      const std::string_view&) override
    {
      return std::nullopt;
    }

    virtual void set_response_body(const std::vector<uint8_t>& body) override
    {
      response_body = body;
    }

    virtual void set_response_body(std::vector<uint8_t>&& body) override
    {
      response_body = std::move(body);
    }

    virtual void set_response_body(std::string&& body) override
    {
      response_body = std::vector<uint8_t>(body.begin(), body.end());
    }

    virtual void set_response_status(int status) override
    {
      response_status = (http_status)status;
    }

    virtual int get_response_status() const override
    {
      return response_status;
    }

    virtual void set_response_header(
      const std::string_view&, const std::string_view&) override
    {}

    virtual void set_seqno(kv::Version sn) override
    {
      seqno = sn;
    }

    virtual void set_view(kv::Consensus::View t) override
    {
      view = t;
    }

    virtual void set_apply_writes(bool apply) override
    {
      explicit_apply_writes = apply;
    }

    virtual bool should_apply_writes() const override
    {
      if (explicit_apply_writes.has_value())
      {
        return explicit_apply_writes.value();
      }

      // Default is to apply any 2xx status
      return http::status_success(response_status);
    }

    virtual std::vector<uint8_t> serialise_response() const override
    {
      return serialise(response_status, response_body, seqno, view);
    }
  };
}