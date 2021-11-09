// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "execution.h"

#include "consensus/aft/request.h"
#include "enclave/rpc_map.h"
#include "enclave/rpc_sessions.h"
#include "http/http_rpc_context.h"
#include "request_message.h"

namespace aft
{
  std::unique_ptr<RequestCtx> ExecutorImpl::create_request_ctx(
    uint8_t* req_start, size_t req_size)
  {
    Request request;
    request.apply(req_start, req_size);
    return create_request_ctx(request);
  }

  std::unique_ptr<RequestCtx> ExecutorImpl::create_request_ctx(Request& request)
  {
    auto r_ctx = std::make_unique<RequestCtx>();

    auto session = std::make_shared<enclave::SessionContext>(
      enclave::InvalidSessionId, request.caller_cert);

    r_ctx->ctx = enclave::make_fwd_rpc_context(
      session, request.raw, (enclave::FrameFormat)request.frame_format);

    const auto actor_opt = http::extract_actor(*r_ctx->ctx);
    if (!actor_opt.has_value())
    {
      throw std::logic_error(fmt::format(
        "Failed to extract actor from BFT request. Method is '{}'",
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
    std::unique_ptr<RequestMessage> request,
    bool is_create_request,
    ccf::SeqNo prescribed_commit_version,
    std::shared_ptr<aft::RequestTracker> request_tracker,
    ccf::View replicated_view)
  {
    std::shared_ptr<enclave::RpcContext>& ctx = request->get_request_ctx().ctx;
    std::shared_ptr<enclave::RpcHandler>& frontend =
      request->get_request_ctx().frontend;

    ctx->bft_raw.resize(request->size());
    request->serialize_message(ctx->bft_raw.data(), ctx->bft_raw.size());

    if (request_tracker != nullptr)
    {
      const auto& raw_request = ctx->get_serialised_request();
      auto data_ = raw_request.data();
      auto size_ = raw_request.size();

      crypto::Sha256Hash hash({data_, size_});

      if (!request_tracker->remove(hash))
      {
        request_tracker->insert_deleted(
          hash,
          threading::ThreadMessaging::thread_messaging
            .get_current_time_offset());
      }
    }

    ctx->is_create_request = is_create_request;
    ctx->execute_on_node = true;

    enclave::RpcHandler::ProcessBftResp rep = frontend->process_bft(
      ctx, prescribed_commit_version, replicated_view);

    request->callback(std::move(rep.result));

    return rep.version;
  }

  std::unique_ptr<aft::RequestMessage> ExecutorImpl::create_request_message(
    const kv::TxHistory::RequestCallbackArgs& args, ccf::SeqNo committed_seqno)
  {
    Request request = {
      args.rid, args.caller_cert, args.request, args.frame_format};
    auto serialized_req = request.serialise();

    auto rep_cb = [=](
                    void*,
                    kv::TxHistory::RequestID caller_rid,
                    int status,
                    std::vector<uint8_t>&& data) {
      LOG_DEBUG_FMT("AFT reply callback status {}", status);

      return rpc_sessions->reply_async(
        std::get<0>(caller_rid), std::move(data));
    };

    auto ctx = create_request_ctx(serialized_req.data(), serialized_req.size());

    return std::make_unique<RequestMessage>(
      std::move(serialized_req), args.rid, std::move(ctx), rep_cb);
  }

  kv::Version ExecutorImpl::execute_request(
    aft::Request& request,
    std::shared_ptr<aft::RequestTracker> request_tracker,
    ccf::SeqNo prescribed_commit_version,
    ccf::View replicated_view)
  {
    auto ctx = create_request_ctx(request);

    auto request_message = RequestMessage::deserialize(
      std::move(request.raw), request.rid, std::move(ctx), nullptr);

    return execute_request(
      std::move(request_message),
      state->commit_idx == 0,
      prescribed_commit_version,
      request_tracker,
      replicated_view);
  }

  void ExecutorImpl::mark_request_executed(
    aft::Request& request,
    std::shared_ptr<aft::RequestTracker>& request_tracker)
  {
    auto req_ctx = create_request_ctx(request);
    auto request_message = RequestMessage::deserialize(
      std::move(request.raw), request.rid, std::move(req_ctx), nullptr);

    std::shared_ptr<enclave::RpcContext>& ctx =
      request_message->get_request_ctx().ctx;
    ctx->bft_raw.resize(request_message->size());
    request_message->serialize_message(
      ctx->bft_raw.data(), ctx->bft_raw.size());

    if (request_tracker != nullptr)
    {
      std::shared_ptr<enclave::RpcContext>& ctx =
        request_message->get_request_ctx().ctx;
      const auto& raw_request = ctx->get_serialised_request();
      auto data_ = raw_request.data();
      auto size_ = raw_request.size();

      crypto::Sha256Hash hash({data_, size_});

      if (!request_tracker->remove(hash))
      {
        request_tracker->insert_deleted(
          hash,
          threading::ThreadMessaging::thread_messaging
            .get_current_time_offset());
      }
    }
  }
}
