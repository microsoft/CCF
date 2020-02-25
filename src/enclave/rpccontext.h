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

  class RpcContext
  {
  protected:
    size_t request_index = 0;

    std::unordered_map<std::string, nlohmann::json> response_headers;

  public:
    SessionContext session;

    // raw pbft Request
    std::vector<uint8_t> pbft_raw = {};

    bool is_create_request = false;

    bool read_only_hint = true;

    RpcContext(const SessionContext& s) : session(s) {}

    RpcContext(const SessionContext& s, const std::vector<uint8_t>& pbft_raw_) :
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
    virtual void set_response_body(const std::vector<uint8_t>& body) = 0;
    virtual void set_response_body(std::vector<uint8_t>&& body) = 0;
    virtual void set_response_body(std::string&& body) = 0;

    virtual void set_response_status(int status) = 0;

    virtual bool response_is_error() const = 0;

    virtual std::vector<uint8_t> serialise_response() const = 0;

    virtual void set_response_header(
      const std::string& name, const std::string& value)
    {
      response_headers[name] = value;
    }

    virtual void set_response_header(const std::string& name, size_t n)
    {
      set_response_header(name, fmt::format("{}", n));
    }
  };
}
