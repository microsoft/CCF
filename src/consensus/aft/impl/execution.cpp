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
    Request request;
    request.deserialise(req_start, req_size);
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
    std::shared_ptr<aft::RequestTracker> request_tracker)
  {
    std::shared_ptr<enclave::RpcContext>& ctx = request->get_request_ctx().ctx;
    std::shared_ptr<enclave::RpcHandler>& frontend =
      request->get_request_ctx().frontend;

    ctx->bft_raw.resize(request->size());
    request->serialize_message(
      NoNode, ctx->bft_raw.data(), ctx->bft_raw.size());

    if (request_tracker != nullptr)
    {
      const auto& raw_request = ctx->get_serialised_request();
      auto data_ = raw_request.data();
      auto size_ = raw_request.size();

      crypto::Sha256Hash hash;
      tls::do_hash(data_, size_, hash.h, MBEDTLS_MD_SHA256);

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
    ctx->set_apply_writes(true);

    enclave::RpcHandler::ProcessBftResp rep = frontend->process_bft(ctx);

    frontend->update_merkle_tree();

    request->callback(std::move(rep.result));

    return rep.version;
  }

  std::unique_ptr<aft::RequestMessage> ExecutorImpl::create_request_message(
    const kv::TxHistory::RequestCallbackArgs& args,
    kv::Consensus::SeqNo committed_seqno)
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

    // Deprecated, this will be removed in future releases
    ctx->ctx->set_global_commit(committed_seqno);

    return std::make_unique<RequestMessage>(
      std::move(serialized_req), args.rid, std::move(ctx), rep_cb);
  }

  kv::Version ExecutorImpl::commit_replayed_request(
    kv::Tx& tx,
    std::shared_ptr<aft::RequestTracker> request_tracker,
    kv::Consensus::SeqNo committed_seqno)
  {
    auto tx_view = tx.get_view<aft::RequestsMap>(ccf::Tables::AFT_REQUESTS);
    auto req_v = tx_view->get(0);
    CCF_ASSERT(
      req_v.has_value(),
      "Deserialised request but it was not found in the requests map");
    Request request = req_v.value();

    auto ctx = create_request_ctx(request);

    // Deprecated, this will be removed in future releases
    ctx->ctx->set_global_commit(committed_seqno);

    auto request_message = RequestMessage::deserialize(
      std::move(request.raw), request.rid, std::move(ctx), nullptr);

    return execute_request(
      std::move(request_message), state->commit_idx == 0, request_tracker);
  }
}
