// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/actors.h"
#include "ccf/http_responder.h"
#include "ccf/odata_error.h"
#include "ccf/rpc_context.h"
#include "http_parser.h"
#include "http_sig.h"
#include "node/rpc/rpc_context_impl.h"

namespace http
{
  class HttpRpcContext : public ccf::RpcContextImpl
  {
  private:
    ccf::RESTVerb verb;
    std::string url = {};

    std::string whole_path = {};
    std::string path = {};
    std::string query = {};
    std::string fragment = {};

    http::HeaderMap request_headers = {};

    std::vector<uint8_t> request_body = {};

    std::shared_ptr<HTTPResponder> responder = nullptr;

    std::vector<uint8_t> serialised_request = {};

    http::HeaderMap response_headers;
    http::HeaderMap response_trailers;
    std::vector<uint8_t> response_body = {};
    http_status response_status = HTTP_STATUS_OK;

    bool serialised = false;

    std::optional<bool> explicit_apply_writes = std::nullopt;

    void serialise()
    {
      if (!serialised)
      {
        const auto request_prefix = fmt::format(
          "{} {} HTTP/1.1\r\n"
          "{}"
          "\r\n",
          verb.c_str(),
          url,
          http::get_header_string(request_headers));

        serialised_request.resize(request_prefix.size() + request_body.size());
        ::memcpy(
          serialised_request.data(),
          request_prefix.data(),
          request_prefix.size());
        if (!request_body.empty())
        {
          ::memcpy(
            serialised_request.data() + request_prefix.size(),
            request_body.data(),
            request_body.size());
        }
      }

      serialised = true;
    }

  public:
    HttpRpcContext(
      std::shared_ptr<ccf::SessionContext> s,
      llhttp_method verb_,
      const std::string_view& url_,
      const http::HeaderMap& headers_,
      const std::vector<uint8_t>& body_,
      const std::shared_ptr<HTTPResponder>& responder_ = nullptr,
      const std::vector<uint8_t>& raw_request_ = {}) :
      RpcContextImpl(s),
      verb(verb_),
      url(url_),
      request_headers(headers_),
      request_body(body_),
      responder(responder_),
      serialised_request(raw_request_)
    {
      const auto [path_, query_, fragment_] = split_url_path(url);
      path = path_;
      whole_path = path_;
      query = url_decode(query_);
      fragment = url_decode(fragment_);

      if (!serialised_request.empty())
      {
        serialised = true;
      }
    }

    http::HeaderMap get_response_headers() const
    {
      return response_headers;
    }

    http::HeaderMap get_response_trailers() const
    {
      return response_trailers;
    }

    std::vector<uint8_t>& get_response_body()
    {
      return response_body;
    }

    http_status get_response_http_status() const
    {
      return response_status;
    }

    virtual ccf::FrameFormat frame_format() const override
    {
      return ccf::FrameFormat::http;
    }

    virtual void set_tx_id(const ccf::TxID& tx_id) override
    {
      set_response_header(http::headers::CCF_TX_ID, tx_id.to_str());
    }

    virtual const std::vector<uint8_t>& get_request_body() const override
    {
      return request_body;
    }

    virtual const std::string& get_request_query() const override
    {
      return query;
    }

    virtual const ccf::RESTVerb& get_request_verb() const override
    {
      return verb;
    }

    virtual std::string get_request_path() const override
    {
      return whole_path;
    }

    virtual const std::vector<uint8_t>& get_serialised_request() override
    {
      serialise();
      return serialised_request;
    }

    virtual std::string get_method() const override
    {
      return path;
    }

    void set_method(const std::string_view& p)
    {
      path = p;
    }

    virtual const http::HeaderMap& get_request_headers() const override
    {
      return request_headers;
    }

    virtual std::optional<std::string> get_request_header(
      const std::string_view& name) override
    {
      const auto it = request_headers.find(name);
      if (it != request_headers.end())
      {
        return it->second;
      }

      return std::nullopt;
    }

    virtual const std::string& get_request_url() const override
    {
      return url;
    }

    virtual std::shared_ptr<http::HTTPResponder> get_responder() const override
    {
      return responder;
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

    virtual const std::vector<uint8_t>& get_response_body() const override
    {
      return response_body;
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
      const std::string_view& name, const std::string_view& value) override
    {
      response_headers[std::string(name)] = value;
    }

    virtual void set_response_trailer(
      const std::string_view& name, const std::string_view& value) override
    {
      response_trailers[std::string(name)] = value;
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
      return status_success(response_status);
    }

    virtual void reset_response() override
    {
      response_headers.clear();
      response_body.clear();
      response_status = HTTP_STATUS_OK;
      explicit_apply_writes.reset();
    }

    virtual std::vector<uint8_t> serialise_response() const override
    {
      auto http_response = http::Response(response_status);

      for (const auto& [k, v] : response_headers)
      {
        http_response.set_header(k, v);
      }

      http_response.set_body(&response_body);
      return http_response.build_response();
    }
  };

  inline static std::optional<std::string> extract_actor(HttpRpcContext& ctx)
  {
    const auto path = ctx.get_method();
    const auto first_slash = path.find_first_of('/');
    const auto second_slash = path.find_first_of('/', first_slash + 1);

    if (first_slash != 0 || second_slash == std::string::npos)
    {
      return std::nullopt;
    }

    const auto actor = path.substr(first_slash + 1, second_slash - 1);
    const auto remaining_path = path.substr(second_slash);

    if (actor.empty() || remaining_path.empty())
    {
      return std::nullopt;
    }

    // if the extracted actor is a known type, set the remaining path
    if (ccf::is_valid_actor(actor))
    {
      ctx.set_method(remaining_path);
    }
    else
    {
      ctx.set_method(path);
    }
    return actor;
  }
}

namespace ccf
{
  inline std::shared_ptr<http::HttpRpcContext> make_rpc_context(
    std::shared_ptr<ccf::SessionContext> s, const std::vector<uint8_t>& packed)
  {
    http::SimpleRequestProcessor processor;
    http::RequestParser parser(processor);

    parser.execute(packed.data(), packed.size());

    if (processor.received.size() != 1)
    {
      throw std::logic_error(fmt::format(
        "Expected packed to contain a single complete HTTP message. Actually "
        "parsed {} messages",
        processor.received.size()));
    }

    const auto& msg = processor.received.front();

    return std::make_shared<http::HttpRpcContext>(
      s, msg.method, msg.url, msg.headers, msg.body, nullptr, packed);
  }

  inline std::shared_ptr<http::HttpRpcContext> make_fwd_rpc_context(
    std::shared_ptr<ccf::SessionContext> s,
    const std::vector<uint8_t>& packed,
    ccf::FrameFormat frame_format)
  {
    switch (frame_format)
    {
      case ccf::FrameFormat::http:
      {
        return make_rpc_context(s, packed);
      }
      default:
        throw std::logic_error("Unknown Frame Format");
    }
  }
}