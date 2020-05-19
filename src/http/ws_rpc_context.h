// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/serialized.h"
#include "enclave/rpc_context.h"
#include "http_parser.h"
#include "http_sig.h"

namespace ws
{
  static std::vector<uint8_t> serialise(
    size_t code,
    const std::vector<uint8_t>& body,
    kv::Version commit = 0,
    kv::Consensus::View term = 0,
    kv::Version global_commit = 0)
  {
    std::vector<uint8_t> header(26); // TODO: ws::Frame::size or something
    uint8_t* hd = header.data();
    size_t s = header.size();

    serialized::write<uint16_t>(hd, s, code);
    serialized::write<size_t>(hd, s, commit);
    serialized::write<size_t>(hd, s, term);
    serialized::write<size_t>(hd, s, global_commit);
    size_t frame_size = body.size() + header.size();

    size_t sz_size = 0;
    if (frame_size > 125)
    {
      sz_size = frame_size > std::numeric_limits<uint16_t>::max() ? 8 : 2;
    }
    std::vector<uint8_t> h(2 + sz_size);
    h[0] = 0x82;
    switch (sz_size)
    {
      case 0:
      {
        h[1] = frame_size;
        break;
      }
      case 2:
      {
        h[1] = 0x7e;
        *((uint16_t*)&h[2]) = htons(frame_size);
        break;
      }
      case 8:
      {
        h[1] = 0x7f;
        *((uint64_t*)&h[2]) = htobe64(frame_size);
        break;
      }
      default:
        throw std::logic_error("Unreachable");
    }

    // TODO: shouldn't need to do that, can preallocate
    h.insert(h.end(), header.begin(), header.end());
    h.insert(h.end(), body.begin(), body.end());
    return h;
  };

  static std::vector<uint8_t> error(size_t code, const std::string& msg)
  {
    return serialise(code, std::vector<uint8_t>(msg.begin(), msg.end()));
  };

  class WsRpcContext : public enclave::RpcContext
  {
  private:
    size_t request_index;

    std::string path = {};
    std::string method = {};

    std::vector<uint8_t> request_body = {};

    std::vector<uint8_t> serialised_request = {};
    std::optional<ccf::SignedReq> signed_request = std::nullopt;

    std::string query = {};

    std::vector<uint8_t> response_body = {};
    http_status response_status = HTTP_STATUS_OK;
    std::optional<bool> explicit_apply_writes = std::nullopt;

    size_t commit = 0;
    size_t term = 0;
    size_t global_commit = 0;

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
      method(path_),
      request_body(body_),
      serialised_request(raw_request_)
    {
      LOG_TRACE_FMT("PATH is: [{}]", path);
    }

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

    virtual size_t get_request_verb() const override
    {
      // Expedient for now
      return http_method::HTTP_POST;
    }

    virtual const std::vector<uint8_t>& get_serialised_request() override
    {
      if (serialised_request.empty())
      {
        std::vector<uint8_t> frame_header(path.size() + sizeof(uint16_t) * 2);
        uint8_t* f = frame_header.data();
        size_t fs = frame_header.size();

        serialized::write_lps(f, fs, path);
        serialized::write_lps(f, fs, ""); // Signature

        size_t frame_size = frame_header.size() + request_body.size();

        size_t sz_size = 0;
        if (frame_size > 125)
        {
          sz_size = frame_size > std::numeric_limits<uint16_t>::max() ? 8 : 2;
        }
        std::vector<uint8_t> h(2 + sz_size);
        h[0] = 0x82;
        switch (sz_size)
        {
          case 0:
          {
            h[1] = frame_size;
            break;
          }
          case 2:
          {
            h[1] = 0x7e;
            *((uint16_t*)&h[2]) = htons(frame_size);
            break;
          }
          case 8:
          {
            h[1] = 0x7f;
            *((uint64_t*)&h[2]) = htobe64(frame_size);
            break;
          }
          default:
            throw std::logic_error("Unreachable");
        }

        serialised_request.insert(serialised_request.end(), h.begin(), h.end());
        serialised_request.insert(
          serialised_request.end(), frame_header.begin(), frame_header.end());
        serialised_request.insert(
          serialised_request.end(), request_body.begin(), request_body.end());
      }
      return serialised_request;
    }

    virtual std::optional<ccf::SignedReq> get_signed_request() override
    {
      if (!signed_request.has_value())
      {
        return std::nullopt;
      }

      return signed_request;
    }

    virtual std::string get_method() const override
    {
      return method;
    }

    virtual void set_method(const std::string_view& p) override
    {
      method = p;
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

    virtual void set_commit(kv::Version cv) override
    {
      commit = cv;
    }

    virtual void set_term(kv::Consensus::View t) override
    {
      term = t;
    }

    virtual void set_global_commit(kv::Version gc) override
    {
      global_commit = gc;
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
      return serialise(
        response_status, response_body, commit, term, global_commit);
    }

    virtual std::vector<uint8_t> serialise_error(
      size_t code, const std::string& msg) const override
    {
      return error(code, msg);
    }
  };
}