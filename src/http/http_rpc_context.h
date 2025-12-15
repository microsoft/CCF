// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_responder.h"
#include "ccf/odata_error.h"
#include "ccf/rpc_context.h"
#include "ds/actors.h"
#include "http_parser.h"
#include "node/rpc_context_impl.h"

namespace http
{
  inline std::vector<uint8_t> error(ccf::ErrorDetails&& error)
  {
    nlohmann::json body = ccf::ODataErrorResponse{
      ccf::ODataError{std::move(error.code), std::move(error.msg), {}}};
    const auto s = body.dump();

    std::vector<uint8_t> data(s.begin(), s.end());
    auto response = ::http::Response(error.status);

    response.set_header(
      ccf::http::headers::CONTENT_TYPE,
      ccf::http::headervalues::contenttype::JSON);
    response.set_body(&data);

    return response.build_response();
  }

  inline std::vector<uint8_t> error(
    ccf::http_status status, const std::string& code, std::string&& msg)
  {
    return error({status, code, std::move(msg)});
  }

  class HttpRpcContext : public ccf::RpcContextImpl
  {
  private:
    ccf::RESTVerb verb;
    std::string url;

    std::string whole_path;
    std::string path;
    std::string query;
    std::string fragment;

    ccf::http::HeaderMap request_headers;

    std::vector<uint8_t> request_body;

    std::shared_ptr<ccf::http::HTTPResponder> responder = nullptr;

    std::vector<uint8_t> serialised_request;

    ccf::http::HeaderMap response_headers;
    ccf::http::HeaderMap response_trailers;
    std::vector<uint8_t> response_body;
    ccf::http_status response_status = HTTP_STATUS_OK;

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
          ::http::get_header_string(request_headers));

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
      ccf::HttpVersion http_version,
      llhttp_method verb_,
      const std::string_view& url_,
      ccf::http::HeaderMap headers_,
      const std::vector<uint8_t>& body_,
      const std::shared_ptr<ccf::http::HTTPResponder>& responder_ = nullptr,
      const std::vector<uint8_t>& raw_request_ = {}) :
      RpcContextImpl(s, http_version),
      verb(verb_),
      url(url_),
      request_headers(std::move(headers_)),
      request_body(body_),
      responder(responder_),
      serialised_request(raw_request_)
    {
      const auto [path_, query_, fragment_] = split_url_path(url);
      // NOLINTBEGIN(cppcoreguidelines-prefer-member-initializer)
      path = path_;
      whole_path = path_;
      query = url_decode(query_);
      fragment = url_decode(fragment_);

      if (!serialised_request.empty())
      {
        serialised = true;
      }
      // NOLINTEND(cppcoreguidelines-prefer-member-initializer)
    }

    [[nodiscard]] ccf::http::HeaderMap get_response_headers() const
    {
      return response_headers;
    }

    [[nodiscard]] ccf::http::HeaderMap get_response_trailers() const
    {
      return response_trailers;
    }

    [[nodiscard]] ccf::http_status get_response_http_status() const
    {
      return response_status;
    }

    [[nodiscard]] ccf::FrameFormat frame_format() const override
    {
      return ccf::FrameFormat::http;
    }

    [[nodiscard]] const std::vector<uint8_t>& get_request_body() const override
    {
      return request_body;
    }

    [[nodiscard]] const std::string& get_request_query() const override
    {
      return query;
    }

    [[nodiscard]] const ccf::RESTVerb& get_request_verb() const override
    {
      return verb;
    }

    [[nodiscard]] std::string get_request_path() const override
    {
      return whole_path;
    }

    const std::vector<uint8_t>& get_serialised_request() override
    {
      serialise();
      return serialised_request;
    }

    [[nodiscard]] std::string get_method() const override
    {
      return path;
    }

    void set_method(const std::string_view& p)
    {
      path = p;
    }

    [[nodiscard]] const ccf::http::HeaderMap& get_request_headers()
      const override
    {
      return request_headers;
    }

    [[nodiscard]] std::optional<std::string> get_request_header(
      const std::string_view& name) const override
    {
      const auto it = request_headers.find(name);
      if (it != request_headers.end())
      {
        return it->second;
      }

      return std::nullopt;
    }

    [[nodiscard]] const std::string& get_request_url() const override
    {
      return url;
    }

    [[nodiscard]] std::shared_ptr<ccf::http::HTTPResponder> get_responder()
      const override
    {
      return responder;
    }

    template <typename T>
    void _set_response_body(T&& body)
    {
      // HEAD responses must not contain a body - clients will ignore it
      if (verb != HTTP_HEAD)
      {
        if constexpr (std::is_same_v<T, std::string>)
        {
          response_body = std::vector<uint8_t>(body.begin(), body.end());
        }
        else
        {
          response_body = std::forward<T>(body);
        }
      }
    }

    void set_response_body(const std::vector<uint8_t>& body) override
    {
      _set_response_body(body);
    }

    void set_response_body(std::vector<uint8_t>&& body) override
    {
      _set_response_body(std::move(body));
    }

    void set_response_body(std::string&& body) override
    {
      _set_response_body(std::move(body));
    }

    [[nodiscard]] const std::vector<uint8_t>& get_response_body() const override
    {
      return response_body;
    }

    std::vector<uint8_t>&& take_response_body() override
    {
      return std::move(response_body);
    }

    void set_response_status(int status) override
    {
      response_status = (ccf::http_status)status;
    }

    [[nodiscard]] int get_response_status() const override
    {
      return response_status;
    }

    void set_response_header(
      const std::string_view& name, const std::string_view& value) override
    {
      response_headers[std::string(name)] = value;
    }

    void clear_response_headers() override
    {
      response_headers.clear();
    }

    void set_response_trailer(
      const std::string_view& name, const std::string_view& value) override
    {
      response_trailers[std::string(name)] = value;
    }

    void set_apply_writes(bool apply) override
    {
      explicit_apply_writes = apply;
    }

    [[nodiscard]] bool should_apply_writes() const override
    {
      if (explicit_apply_writes.has_value())
      {
        return explicit_apply_writes.value();
      }

      // Default is to apply any 2xx status
      return status_success(response_status);
    }

    void reset_response() override
    {
      response_headers.clear();
      response_body.clear();
      response_status = HTTP_STATUS_OK;
      explicit_apply_writes.reset();
    }

    [[nodiscard]] std::vector<uint8_t> serialise_response() const override
    {
      auto http_response = ::http::Response(response_status);

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

    auto actor = path.substr(first_slash + 1, second_slash - first_slash - 1);
    auto remaining_path = path.substr(second_slash);

    if (actor.empty() || remaining_path.empty())
    {
      return std::nullopt;
    }

    // if the extracted actor is a known type, set the remaining path
    if (ccf::is_valid_actor(actor))
    {
      ctx.set_method(remaining_path);
    }
    return actor;
  }

  inline static std::shared_ptr<ccf::RpcHandler> fetch_rpc_handler(
    std::shared_ptr<http::HttpRpcContext>& ctx,
    std::shared_ptr<ccf::RPCMap>& rpc_map)
  {
    const auto actor_opt = http::extract_actor(*ctx);
    std::optional<std::shared_ptr<ccf::RpcHandler>> search;
    ccf::ActorsType actor = ccf::ActorsType::unknown;

    if (actor_opt.has_value())
    {
      const auto& actor_s = actor_opt.value();
      actor = rpc_map->resolve(actor_s);
      search = rpc_map->find(actor);
    }
    if (
      !actor_opt.has_value() || actor == ccf::ActorsType::unknown ||
      !search.has_value())
    {
      // if there is no actor, proceed with the "app" as the ActorType and
      // process the request
      search = rpc_map->find(ccf::ActorsType::users);
    }
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    return *search;
  }
}

namespace ccf
{
  inline std::shared_ptr<::http::HttpRpcContext> make_rpc_context(
    std::shared_ptr<ccf::SessionContext> s, const std::vector<uint8_t>& packed)
  {
    ::http::SimpleRequestProcessor processor;
    ::http::RequestParser parser(processor, http::permissive_configuration());
    parser.execute(packed.data(), packed.size());

    if (processor.received.size() != 1)
    {
      throw std::logic_error(fmt::format(
        "Expected packed to contain a single complete HTTP message. Actually "
        "parsed {} messages",
        processor.received.size()));
    }

    const auto& msg = processor.received.front();

    return std::make_shared<::http::HttpRpcContext>(
      s,
      ccf::HttpVersion::HTTP1,
      msg.method,
      msg.url,
      msg.headers,
      msg.body,
      nullptr,
      packed);
  }

  inline std::shared_ptr<::http::HttpRpcContext> make_fwd_rpc_context(
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