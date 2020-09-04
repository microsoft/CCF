// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "execution.h"

#include "consensus/aft/request.h"
#include "enclave/rpc_map.h"
#include "enclave/rpc_sessions.h"
#include "http/http_rpc_context.h"
#include "kv/tx.h"
#include "request_message.h"

namespace aft
{
  std::unique_ptr<RequestCtx> ExecutorImpl::create_request_ctx(
    uint8_t* req_start, size_t req_size)
  {
    pbft::Request request;
    request.deserialise(req_start, req_size);
    return create_request_ctx(request);
  }

  std::unique_ptr<RequestCtx> ExecutorImpl::create_request_ctx(
    pbft::Request& request)
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
    const auto actor = rpc_map->resolve(actor_s);
    auto handler = rpc_map->find(actor);
    if (!handler.has_value())
      throw std::logic_error(
        fmt::format("No frontend associated with actor {}", actor_s));

    r_ctx->frontend = handler.value();
    return r_ctx;
  }

  kv::Version ExecutorImpl::execute_request(
    std::unique_ptr<RequestMessage> request, bool is_create_request)
  {
    std::shared_ptr<enclave::RpcContext>& ctx = request->get_request_ctx().ctx;
    std::shared_ptr<enclave::RpcHandler>& frontend =
      request->get_request_ctx().frontend;

    ctx->pbft_raw.resize(request->size());
    request->serialize_message(
      NoNode, ctx->pbft_raw.data(), ctx->pbft_raw.size());

    ctx->is_create_request = is_create_request;
    ctx->set_apply_writes(true);

    enclave::RpcHandler::ProcessPbftResp rep = frontend->process_pbft(ctx);

    frontend->update_merkle_tree();

    request->callback(rep.result);

    return rep.version;
  }

  std::unique_ptr<aft::RequestMessage> ExecutorImpl::create_request_message(
    const kv::TxHistory::RequestCallbackArgs& args)
  {
    Request request = {
      args.caller_id, args.caller_cert, args.request, {}, args.frame_format};
    auto serialized_req = request.serialise();

    auto rep_cb = [=](
                    void*,
                    kv::TxHistory::RequestID caller_rid,
                    int status,
                    std::vector<uint8_t>& data) {
      LOG_DEBUG_FMT("AFT reply callback status {}", status);

      return rpc_sessions->reply_async(std::get<1>(caller_rid), data);
    };

    auto ctx = create_request_ctx(serialized_req.data(), serialized_req.size());

    return std::make_unique<RequestMessage>(
      std::move(serialized_req), args.rid, std::move(ctx), rep_cb);
  }

  kv::Version ExecutorImpl::commit_replayed_request(kv::Tx& tx)
  {
    auto tx_view = tx.get_view(pbft_requests_map);
    auto req_v = tx_view->get(0);
    CCF_ASSERT(
      req_v.has_value(),
      "Deserialised request but it was not found in the requests map");
    pbft::Request request = req_v.value();

    auto ctx = create_request_ctx(request);

    auto request_message = RequestMessage::deserialize(
      request.pbft_raw.data(),
      request.pbft_raw.size(),
      std::move(ctx),
      nullptr);

    return execute_request(std::move(request_message), state->commit_idx == 0);
  }
}
