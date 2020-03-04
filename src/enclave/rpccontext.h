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
    bool is_forwarded = false;

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

    std::unordered_map<std::string, nlohmann::json> response_headers;
    RpcResponse response;

  public:
    std::shared_ptr<SessionContext> session;

    // raw pbft Request
    std::vector<uint8_t> pbft_raw = {};

    bool is_create_request = false;

    bool read_only_hint = true;

    RpcContext(std::shared_ptr<SessionContext> s) : session(s) {}

    RpcContext(
      std::shared_ptr<SessionContext> s,
      const std::vector<uint8_t>& pbft_raw_) :
      session(s),
      pbft_raw(pbft_raw_)
    {}

    virtual ~RpcContext() {}

    /// Request details
    void set_request_index(size_t ri)
    {
      request_index = ri;
    }

    size_t get_request_index() const
    {
      return request_index;
    }

    virtual const std::vector<uint8_t>& get_request_body() const = 0;
    virtual nlohmann::json get_params() const = 0;

    virtual std::string get_method() const = 0;
    virtual void set_method(const std::string_view& method) = 0;

    virtual const std::vector<uint8_t>& get_serialised_request() = 0;
    virtual std::optional<ccf::SignedReq> get_signed_request() = 0;

    /// Response details
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
      response_headers[name] = value;
    }
  };
}
