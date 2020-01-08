// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/clientsignatures.h"
#include "node/entities.h"
#include "node/rpc/jsonrpc.h"

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

  enum class RpcError
  {
  };

  class RpcContext
  {
  public:
    SessionContext session;

    // Packing format of original request, should be used to pack response
    std::optional<jsonrpc::Pack> pack = std::nullopt;

    // TODO: Avoid unnecessary copies
    std::vector<uint8_t> raw = {};

    nlohmann::json unpacked_rpc = {};

    std::optional<ccf::SignedReq> signed_request = std::nullopt;

    // Actor type to dispatch to appropriate frontend
    ccf::ActorsType actor = ccf::ActorsType::unknown;

    // Method indicates specific handler for this request
    std::string method = {};

    uint64_t seq_no = {};

    nlohmann::json params = {};

    bool is_create_request = false;

    RpcContext(const SessionContext& s) : session(s) {}
    virtual ~RpcContext() {}

    virtual std::vector<uint8_t> error_response(
      int error, const std::string& msg) const = 0;
  };

  class JsonRpcContext : public RpcContext
  {
    void init(jsonrpc::Pack p, const nlohmann::json& rpc)
    {
      pack = p;

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

  public:
    JsonRpcContext(
      const SessionContext& s, const std::vector<uint8_t>& packed) :
      RpcContext(s)
    {
      std::optional<jsonrpc::Pack> pack_format;

      auto [success, rpc] = jsonrpc::unpack_rpc(packed, pack_format);
      if (!success)
      {
        throw std::logic_error(fmt::format("Failed to unpack: {}", rpc.dump()));
      }

      init(pack_format.value(), rpc);
      raw = packed;
    }

    JsonRpcContext(
      const SessionContext& s, jsonrpc::Pack p, const nlohmann::json& rpc) :
      RpcContext(s)
    {
      init(p, rpc);
    }

    std::vector<uint8_t> error_response(
      int error, const std::string& msg) const override
    {
      return jsonrpc::pack(jsonrpc::error_response(seq_no, msg), pack.value());
    }
  };
}
