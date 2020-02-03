// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/clientsignatures.h"
#include "node/entities.h"
#include "node/rpc/jsonrpc.h"

#include <variant>
#include <vector>

namespace enclave
{
  static constexpr size_t InvalidSessionId = std::numeric_limits<size_t>::max();

  struct SessionContext
  {
    size_t client_session_id = InvalidSessionId;
    std::vector<uint8_t> caller_cert = {};

    //
    // Only set in the case of a forwarded RPC
    //
    struct Forwarded
    {
      // Initialised when forwarded context is created
      const size_t client_session_id;
      const ccf::CallerId caller_id;

      Forwarded(size_t client_session_id_, ccf::CallerId caller_id_) :
        client_session_id(client_session_id_),
        caller_id(caller_id_)
      {}
    };
    std::optional<Forwarded> fwd = std::nullopt;

    // Constructor used for non-forwarded RPC
    SessionContext(
      size_t client_session_id_, const std::vector<uint8_t>& caller_cert_) :
      client_session_id(client_session_id_),
      caller_cert(caller_cert_)
    {}

    // Constructor used for forwarded and PBFT RPC
    SessionContext(
      size_t fwd_session_id_,
      ccf::CallerId caller_id_,
      const std::vector<uint8_t>& caller_cert_ = {}) :
      fwd(std::make_optional<Forwarded>(fwd_session_id_, caller_id_)),
      caller_cert(caller_cert_)
    {}
  };

  struct ErrorDetails
  {
    int code;
    std::string msg;
  };

  struct RpcResponse
  {
    std::variant<ErrorDetails, nlohmann::json> result;
  };

  class RpcContext
  {
  protected:
    size_t request_index = 0;

    std::unordered_map<std::string, nlohmann::json> headers;
    RpcResponse response;

  public:
    SessionContext session;

    // TODO: Avoid unnecessary copies
    std::vector<uint8_t> raw = {};

    // raw pbft Request
    std::vector<uint8_t> pbft_raw = {};

    nlohmann::json unpacked_rpc = {};

    std::optional<ccf::SignedReq> signed_request = std::nullopt;

    // Actor type to dispatch to appropriate frontend
    ccf::ActorsType actor = ccf::ActorsType::unknown;

    // Method indicates specific handler for this request
    std::string method = {};

    nlohmann::json params = {};

    bool is_create_request = false;

    RpcContext(const SessionContext& s) : session(s) {}

    RpcContext(
      const SessionContext& s,
      const std::vector<uint8_t>& raw_,
      const std::vector<uint8_t>& pbft_raw_) :
      session(s),
      raw(raw_),
      pbft_raw(pbft_raw_)
    {}

    virtual ~RpcContext() {}

    void set_request_index(size_t ri)
    {
      request_index = ri;
    }

    size_t get_request_index() const
    {
      return request_index;
    }

    void set_response_error(int code, const std::string& msg = "")
    {
      response.result = ErrorDetails{code, msg};
    }

    const ErrorDetails* get_response_error() const
    {
      return std::get_if<ErrorDetails>(&response.result);
    }

    ErrorDetails* get_response_error()
    {
      return std::get_if<ErrorDetails>(&response.result);
    }

    bool response_is_error() const
    {
      return get_response_error() != nullptr;
    }

    void set_response_result(nlohmann::json&& j)
    {
      response.result = std::move(j);
    }

    const nlohmann::json* get_response_result() const
    {
      return std::get_if<nlohmann::json>(&response.result);
    }

    nlohmann::json* get_response_result()
    {
      return std::get_if<nlohmann::json>(&response.result);
    }

    void set_response(RpcResponse&& r)
    {
      response = std::move(r);
    }

    virtual std::vector<uint8_t> serialise_response() const = 0;

    virtual std::vector<uint8_t> result_response(
      const nlohmann::json& result) const = 0;

    virtual std::vector<uint8_t> error_response(
      int error, const std::string& msg = "") const = 0;

    virtual void set_response_headers(
      const std::string& name, const nlohmann::json& value)
    {
      headers[name] = value;
    }
  };

  class JsonRpcContext : public RpcContext
  {
    uint64_t seq_no = {};

    void init(jsonrpc::Pack p, const nlohmann::json& rpc)
    {
      pack_format = p;

      const auto sig_it = rpc.find(jsonrpc::SIG);
      if (sig_it != rpc.end())
      {
        unpacked_rpc = rpc.at(jsonrpc::REQ);
        ccf::SignedReq signed_req;
        signed_req.sig = sig_it->get<decltype(signed_req.sig)>();
        signed_req.req = nlohmann::json::to_msgpack(unpacked_rpc);
        signed_request = signed_req;
      }
      else
      {
        unpacked_rpc = rpc;
        signed_request = std::nullopt;
      }

      const auto method_it = unpacked_rpc.find(jsonrpc::METHOD);
      if (method_it != unpacked_rpc.end())
      {
        method = method_it->get<std::string>();
      }

      const auto seq_it = unpacked_rpc.find(jsonrpc::ID);
      if (seq_it != unpacked_rpc.end())
      {
        seq_no = seq_it->get<uint64_t>();
      }

      const auto params_it = unpacked_rpc.find(jsonrpc::PARAMS);
      if (params_it != unpacked_rpc.end())
      {
        params = *params_it;
      }
    }

    std::vector<uint8_t> pack(const nlohmann::json& j) const
    {
      return jsonrpc::pack(j, pack_format.value());
    }

  public:
    // Packing format of original request, should be used to pack response
    std::optional<jsonrpc::Pack> pack_format = std::nullopt;

    JsonRpcContext(
      const SessionContext& s,
      const std::vector<uint8_t>& packed,
      const std::vector<uint8_t>& pbft_raw = {}) :
      RpcContext(s, packed, pbft_raw)
    {
      std::optional<jsonrpc::Pack> p;

      auto [success, rpc] = jsonrpc::unpack_rpc(packed, p);
      if (!success)
      {
        throw std::logic_error(fmt::format("Failed to unpack: {}", rpc.dump()));
      }

      init(p.value(), rpc);
    }

    JsonRpcContext(
      const SessionContext& s, jsonrpc::Pack p, const nlohmann::json& rpc) :
      RpcContext(s)
    {
      init(p, rpc);
    }

    virtual std::vector<uint8_t> serialise_response() const override
    {
      nlohmann::json full_response;

      if (response_is_error())
      {
        const auto error = get_response_error();
        full_response = jsonrpc::error_response(
          seq_no, jsonrpc::Error(error->code, error->msg));
      }
      else
      {
        const auto payload = get_response_result();
        full_response = jsonrpc::result_response(seq_no, *payload);
      }

      for (const auto& [k, v] : headers)
      {
        const auto it = full_response.find(k);
        if (it == full_response.end())
        {
          full_response[k] = v;
        }
        else
        {
          LOG_DEBUG_FMT(
            "Ignoring response headers with key '{}' - already present in "
            "response object",
            k);
        }
      }

      return pack(full_response);
    }

    virtual std::vector<uint8_t> result_response(
      const nlohmann::json& result) const override
    {
      return pack(jsonrpc::result_response(seq_no, result));
    }

    std::vector<uint8_t> error_response(
      int error, const std::string& msg) const override
    {
      nlohmann::json error_element = jsonrpc::Error(error, msg);
      return pack(jsonrpc::error_response(seq_no, error_element));
    }
  };

  inline std::shared_ptr<RpcContext> make_rpc_context(
    const SessionContext& s,
    const std::vector<uint8_t>& packed,
    const std::vector<uint8_t>& raw_pbft = {})
  {
    return std::make_shared<JsonRpcContext>(s, packed, raw_pbft);
  }
}
