// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "execution_utilities.h"

#include "enclave/rpc_map.h"
#include "http/http_rpc_context.h"
#include "request_message.h"

namespace aft
{
  std::unique_ptr<RequestCtx> ExecutionUtilities::create_request_ctx(
    uint8_t* req_start,
    size_t req_size,
    std::shared_ptr<enclave::RPCMap>& rpc_map)
  {
    pbft::Request request;
    request.deserialise(req_start, req_size);
    return create_request_ctx(request, rpc_map);
  }

  std::unique_ptr<RequestCtx> ExecutionUtilities::create_request_ctx(
    pbft::Request& request,
    std::shared_ptr<enclave::RPCMap>& rpc_map)
  {
    auto r_ctx = std::make_unique<RequestCtx>();

    auto session = std::make_shared<enclave::SessionContext>(
      enclave::InvalidSessionId, request.caller_id, request.caller_cert);

    r_ctx->ctx = enclave::make_fwd_rpc_context(
      session, request.raw, (enclave::FrameFormat)request.frame_format);

    const auto actor_opt = http::extract_actor(*r_ctx->ctx);
    if (!actor_opt.has_value())
    {
      throw std::logic_error(fmt::format(
        "Failed to extract actor from PBFT request. Method is '{}'",
        r_ctx->ctx->get_method()));
    }

    const auto& actor_s = actor_opt.value();
    std::string preferred_actor_s;
    const auto actor = rpc_map->resolve(actor_s, preferred_actor_s);
    auto handler = rpc_map->find(actor);
    if (!handler.has_value())
      throw std::logic_error(
        fmt::format("No frontend associated with actor {}", actor_s));

    r_ctx->frontend = handler.value();
    return r_ctx;
  }

  kv::Version ExecutionUtilities::execute_request(
    std::unique_ptr<RequestMessage> request, bool is_create_request)
  {
    std::shared_ptr<enclave::RpcContext>& ctx = request->get_request_ctx().ctx;
    std::shared_ptr<enclave::RpcHandler>& frontend =
      request->get_request_ctx().frontend;

    ctx->pbft_raw.resize(request->size());
    request->serialize_message(ctx->pbft_raw.data(), ctx->pbft_raw.size());

    ctx->is_create_request = is_create_request;
    ctx->set_apply_writes(true);

    enclave::RpcHandler::ProcessPbftResp rep = frontend->process_pbft(ctx);

    frontend->update_merkle_tree();

    request->callback(rep.result);

    return rep.version;
  }
}