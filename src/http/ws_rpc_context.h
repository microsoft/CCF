// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpc_context.h"
#include "http_parser.h"
#include "http_sig.h"

namespace ws
{
  static std::vector<uint8_t> error(size_t code, const std::string& msg)
  {
    return std::vector<uint8_t>(msg.begin(), msg.end());
  };

  class WsRpcContext : public enclave::RpcContext
  {
  private:
    size_t request_index;

    std::string whole_path = {};
    std::string path = {};

    std::vector<uint8_t> request_body = {};

    std::vector<uint8_t> serialised_request = {};
    std::optional<ccf::SignedReq> signed_request = std::nullopt;

    std::vector<uint8_t> response_body = {};
    http_status response_status = HTTP_STATUS_OK;

    bool canonicalised = false;

    std::optional<bool> explicit_apply_writes = std::nullopt;

    void canonicalise()
    {
      // A canonicalised WebSocket request is the concatenation of the
      // whole path and the body of the request
      if (!canonicalised)
      {
        serialised_request.resize(whole_path.size() + request_body.size());
        ::memcpy(
          serialised_request.data(), whole_path.data(), whole_path.size());
        if (!request_body.empty())
        {
          ::memcpy(
            serialised_request.data() + whole_path.size(),
            request_body.data(),
            request_body.size());
        }
      }

      canonicalised = true;
    }

  public:
    WsRpcContext(
      size_t request_index_,
      std::shared_ptr<enclave::SessionContext> s,
      const std::string_view& path_,
      const std::vector<uint8_t>& body_,
      const std::vector<uint8_t>& raw_request_ = {},
      const std::vector<uint8_t>& raw_pbft_ = {}) :
      RpcContext(s, raw_pbft_),
      request_index(request_index_),
      path(path_),
      request_body(body_),
      serialised_request(raw_request_)
    {
      whole_path = path;

      if (!serialised_request.empty())
      {
        canonicalised = true;
      }
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
      throw std::logic_error("get_request_query not implemented");
    }

    virtual size_t get_request_verb() const override
    {
      // Expedient for now
      return http_method::HTTP_POST;
    }

    virtual const std::vector<uint8_t>& get_serialised_request() override
    {
      canonicalise();
      return serialised_request;
    }

    virtual std::optional<ccf::SignedReq> get_signed_request() override
    {
      canonicalise();
      if (!signed_request.has_value())
      {
        return std::nullopt;
      }

      return signed_request;
    }

    virtual std::string get_method() const override
    {
      return path;
    }

    virtual void set_method(const std::string_view& p) override
    {
      path = p;
    }

    virtual std::optional<std::string> get_request_header(
      const std::string_view& name) override
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

    virtual void set_response_header(
      const std::string_view& name, const std::string_view& value) override
    {}

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
      size_t sz_size = 0;
      if (response_body.size() > 125)
      {
        sz_size =
          response_body.size() > std::numeric_limits<uint16_t>::max() ? 8 : 2;
      }
      std::vector<uint8_t> h(2 + sz_size);
      h[0] = 0x82;
      switch (sz_size)
      {
        case 0:
        {
          h[1] = response_body.size();
          break;
        }
        case 2:
        {
          h[1] = 0x7e;
          *((uint16_t*)&h[2]) = htons(response_body.size());
          break;
        }
        case 8:
        {
          h[1] = 0x7f;
          *((uint64_t*)&h[2]) = htobe64(response_body.size());
          break;
        }
        default:
          throw std::logic_error("Unreachable");
      }
      h.insert(h.end(), response_body.begin(), response_body.end());
      return h;
    }

    virtual std::vector<uint8_t> serialise_error(
      size_t code, const std::string& msg) const override
    {
      return error(code, msg);
    }
  };
}