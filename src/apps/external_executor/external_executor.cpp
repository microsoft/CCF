// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/crypto/verifier.h"
#include "ccf/entity_id.h"
#include "ccf/http_consts.h"
#include "ccf/http_responder.h"
#include "ccf/json_handler.h"
#include "ccf/kv/map.h"
#include "ccf/pal/locking.h"
#include "ccf/service/tables/nodes.h"
#include "endpoints/grpc/grpc.h"
#include "executor_auth_policy.h"
#include "executor_code_id.h"
#include "executor_registration.pb.h"
#include "http/http2_session.h"
#include "http/http_builder.h"
#include "kv.pb.h"
#include "misc.pb.h"
#include "node/endpoint_context_impl.h"
#include "node/rpc/rpc_context_impl.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <queue>
#include <string>

namespace externalexecutor
{
  // This uses std::string to match protobuf's storage of raw bytes entries, and
  // directly stores those raw bytes. Note that these strings may contain nulls
  // and other unprintable characters, so may not be trivially displayable.
  using Map = kv::RawCopySerialisedMap<std::string, std::string>;

  using ExecutorId = ccf::EntityId<ccf::NodeIdFormatter>;

  class EndpointRegistry : public ccf::UserEndpointRegistry
  {
    struct PendingRequest
    {
      std::unique_ptr<kv::CommittableTx> tx = nullptr;
      externalexecutor::protobuf::RequestDescription request_description;
      std::shared_ptr<http::HTTPResponder> http_responder;
    };
    using PendingRequestPtr = std::shared_ptr<PendingRequest>;

    using ExecutorPendingRequests = std::queue<PendingRequestPtr>;

    const ccf::grpc::ErrorResponse out_of_order_error = ccf::grpc::make_error(
      GRPC_STATUS_FAILED_PRECONDITION,
      "Not managing an active transaction - this should be called after a "
      "successful call to StartTx and before EndTx");

    std::unordered_map<ExecutorId, PendingRequestPtr> active_requests;
    std::unordered_map<ExecutorId, ExecutorPendingRequests>
      pending_executor_requests;

    struct ExecutorIdList
    {
      std::list<ExecutorId> executor_ids;

      void insert(ExecutorId id)
      {
        executor_ids.push_back(id);
      }

      ExecutorId get_executor_id()
      {
        // return the first ExecutorID and then move it back to the end of the
        // list
        ExecutorId front = executor_ids.front();
        executor_ids.pop_front();
        executor_ids.push_back(front);
        return front;
      }

      int size()
      {
        return executor_ids.size();
      }
    };

    std::unordered_map<std::string, ExecutorIdList> supported_uris;

    ExecutorId get_caller_executor_id(
      ccf::endpoints::CommandEndpointContext& ctx)
    {
      auto executor_ident = ctx.try_get_caller<ExecutorIdentity>();
      if (executor_ident == nullptr)
      {
        throw std::logic_error(
          "find_active_request() should only be called for successfully "
          "Executor-authenticated endpoints");
      }

      return executor_ident->executor_id;
    }

    PendingRequestPtr find_active_request(ExecutorId id)
    {
      auto it = active_requests.find(id);
      if (it != active_requests.end())
      {
        return it->second;
      }

      return nullptr;
    }

    void install_registry_service()
    {
      // create an endpoint to get executor code id
      auto get_executor_code =
        [](ccf::endpoints::ReadOnlyEndpointContext& ctx, nlohmann::json&&) {
          GetExecutorCode::Out out;

          auto executor_code_ids =
            ctx.tx.template ro<ExecutorCodeIDs>(EXECUTOR_CODE_IDS);
          executor_code_ids->foreach(
            [&out](const ccf::CodeDigest& cd, const ExecutorCodeInfo& info) {
              auto digest = ds::to_hex(cd.data);
              out.versions.push_back({digest, info.status, info.platform});
              return true;
            });

          return ccf::make_success(out);
        };

      make_read_only_endpoint(
        "/executor_code",
        HTTP_GET,
        ccf::json_read_only_adapter(get_executor_code),
        ccf::no_auth_required)
        .set_auto_schema<void, GetExecutorCode::Out>()
        .install();

      // create an endpoint to register the executor
      auto register_executor =
        [this](auto& ctx, externalexecutor::protobuf::NewExecutor&& payload)
        -> ccf::grpc::GrpcAdapterResponse<
          externalexecutor::protobuf::RegistrationResult> {
        // verify quote
        ccf::CodeDigest code_digest;
        ccf::QuoteVerificationResult verify_result = verify_executor_quote(
          ctx.tx, payload.attestation(), payload.cert(), code_digest);

        if (verify_result != ccf::QuoteVerificationResult::Verified)
        {
          const auto [code, message] = verification_error(verify_result);
          return ccf::grpc::make_error(code, message);
        }

        // generate and store executor id locally
        crypto::Pem executor_x509_cert(payload.cert());
        auto cert_der = crypto::cert_pem_to_der(executor_x509_cert);
        auto pubk_der = crypto::public_key_der_from_cert(cert_der);

        ExecutorId executor_id = ccf::compute_node_id_from_pubk_der(pubk_der);
        std::vector<externalexecutor::protobuf::NewExecutor::EndpointKey>
          supported_endpoints(
            payload.supported_endpoints().begin(),
            payload.supported_endpoints().end());

        for (int i = 0; i < payload.supported_endpoints_size(); ++i)
        {
          std::string method = supported_endpoints[i].method();
          std::string uri = supported_endpoints[i].uri();
          supported_uris[method + uri].insert(executor_id);
        }

        ExecutorNodeInfo executor_info = {
          executor_x509_cert, payload.attestation(), supported_endpoints};

        executor_ids[executor_id] = executor_info;

        // Record the certs in the Executor certs map
        executor_certs[executor_id] = executor_x509_cert;

        externalexecutor::protobuf::RegistrationResult result;
        result.set_details("Executor registration is accepted.");
        result.set_executor_id(executor_id.value());

        return ccf::grpc::make_success(result);
      };

      make_endpoint(
        "/externalexecutor.protobuf.ExecutorRegistration/RegisterExecutor",
        HTTP_POST,
        ccf::grpc_adapter<
          externalexecutor::protobuf::NewExecutor,
          externalexecutor::protobuf::RegistrationResult>(register_executor),
        ccf::no_auth_required)
        .install();
    }

    // Only used for streaming demo

    ccf::pal::Mutex subscribed_events_lock;
    std::unordered_map<
      std::string, // Concatenation of temp::Event
      ccf::grpc::DetachedStreamPtr<temp::EventInfo>>
      subscribed_events;

    void install_kv_service()
    {
      auto executor_auth_policy = std::make_shared<ExecutorAuthPolicy>();
      ccf::AuthnPolicies executor_only{executor_auth_policy};

      auto start = [this](
                     ccf::endpoints::CommandEndpointContext& ctx,
                     google::protobuf::Empty&& payload)
        -> ccf::grpc::GrpcAdapterResponse<
          externalexecutor::protobuf::OptionalRequestDescription> {
        const auto executor_id = get_caller_executor_id(ctx);
        const auto it = active_requests.find(executor_id);
        if (it != active_requests.end())
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Already managing an active transaction");
        }

        externalexecutor::protobuf::OptionalRequestDescription
          optional_request_description;

        auto& executor_queue = pending_executor_requests[executor_id];
        if (!executor_queue.empty())
        {
          auto* request_description =
            optional_request_description.mutable_optional();
          auto pending_request = executor_queue.front();
          executor_queue.pop();
          LOG_TRACE_FMT(
            "Processing executor id:{}, uri: {}, method: {}",
            executor_id.value(),
            pending_request->request_description.uri(),
            pending_request->request_description.method());
          *request_description = pending_request->request_description;
          active_requests.emplace_hint(it, executor_id, pending_request);
        }

        return ccf::grpc::make_success(optional_request_description);
      };
      make_endpoint(
        "/externalexecutor.protobuf.KV/StartTx",
        HTTP_POST,
        ccf::grpc_command_adapter<
          google::protobuf::Empty,
          externalexecutor::protobuf::OptionalRequestDescription>(start),
        executor_only)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto end = [this](
                   ccf::endpoints::EndpointContext& ctx,
                   externalexecutor::protobuf::ResponseDescription&& payload)
        -> ccf::grpc::GrpcAdapterResponse<google::protobuf::Empty> {
        const auto executor_id = get_caller_executor_id(ctx);
        const auto it = active_requests.find(executor_id);
        if (it == active_requests.end())
        {
          return out_of_order_error;
        }

        // Get claims from payload
        ccf::ClaimsDigest claims = ccf::empty_claims();
        const std::string& payload_digest = payload.claims_digest();
        if (!payload_digest.empty())
        {
          if (payload_digest.size() != ccf::ClaimsDigest::Digest::SIZE)
          {
            return ccf::grpc::make_error(
              GRPC_STATUS_INVALID_ARGUMENT,
              fmt::format(
                "claims_digest is not a valid Sha256 hash. Must be {} bytes. "
                "Received {} bytes.",
                ccf::ClaimsDigest::Digest::SIZE,
                payload_digest.size()));
          }
          claims.set(crypto::Sha256Hash::from_span(
            {(uint8_t*)payload_digest.data(),
             ccf::ClaimsDigest::Digest::SIZE}));
        }

        auto& active_request = it->second;
        kv::CommitResult result = active_request->tx->commit(claims);
        switch (result)
        {
          case kv::CommitResult::SUCCESS:
          {
            LOG_TRACE_FMT("Preparing to send final response to user");

            http::HeaderMap headers;
            for (int i = 0; i < payload.headers_size(); ++i)
            {
              const externalexecutor::protobuf::Header& header =
                payload.headers(i);
              headers[header.field()] = header.value();
            }

            auto tx_id = active_request->tx->get_txid();
            if (tx_id.has_value())
            {
              LOG_DEBUG_FMT("Applied tx at {}", tx_id->str());
              headers[http::headers::CCF_TX_ID] = tx_id->str();
            }

            http::HeaderMap trailers;

            const std::string& body_s = payload.body();
            if (!active_request->http_responder->send_response(
                  (http_status)payload.status_code(),
                  std::move(headers),
                  std::move(trailers),
                  {(const uint8_t*)body_s.data(), body_s.size()}))
            {
              LOG_FAIL_FMT("Could not send response back to client");
            }
            break;
          }

          case kv::CommitResult::FAIL_CONFLICT:
          {
            LOG_FAIL_FMT("Tx failed due to conflict");
            break;
          }

          case kv::CommitResult::FAIL_NO_REPLICATE:
          {
            LOG_FAIL_FMT("Tx failed to replicate");
            break;
          }
        }

        active_requests.erase(it);

        return ccf::grpc::make_success();
      };

      make_endpoint(
        "/externalexecutor.protobuf.KV/EndTx",
        HTTP_POST,
        ccf::grpc_adapter<
          externalexecutor::protobuf::ResponseDescription,
          google::protobuf::Empty>(end),
        executor_only)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto put = [this](
                   ccf::endpoints::EndpointContext& ctx,
                   externalexecutor::protobuf::KVKeyValue&& payload)
        -> ccf::grpc::GrpcAdapterResponse<google::protobuf::Empty> {
        auto active_request = find_active_request(get_caller_executor_id(ctx));
        if (active_request == nullptr)
        {
          return out_of_order_error;
        }

        auto handle = active_request->tx->rw<Map>(payload.table());
        handle->put(payload.key(), payload.value());

        return ccf::grpc::make_success();
      };

      make_endpoint(
        "/externalexecutor.protobuf.KV/Put",
        HTTP_POST,
        ccf::grpc_adapter<
          externalexecutor::protobuf::KVKeyValue,
          google::protobuf::Empty>(put),
        executor_only)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto get = [this](
                   ccf::endpoints::ReadOnlyEndpointContext& ctx,
                   externalexecutor::protobuf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<
          externalexecutor::protobuf::OptionalKVValue> {
        auto active_request = find_active_request(get_caller_executor_id(ctx));
        if (active_request == nullptr)
        {
          return out_of_order_error;
        }

        auto handle = active_request->tx->ro<Map>(payload.table());
        auto result = handle->get(payload.key());

        externalexecutor::protobuf::OptionalKVValue response;
        if (result.has_value())
        {
          externalexecutor::protobuf::KVValue* response_value =
            response.mutable_optional();
          response_value->set_value(*result);
        }

        return ccf::grpc::make_success(response);
      };

      make_read_only_endpoint(
        "/externalexecutor.protobuf.KV/Get",
        HTTP_POST,
        ccf::grpc_read_only_adapter<
          externalexecutor::protobuf::KVKey,
          externalexecutor::protobuf::OptionalKVValue>(get),
        executor_only)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto has = [this](
                   ccf::endpoints::ReadOnlyEndpointContext& ctx,
                   externalexecutor::protobuf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<
          externalexecutor::protobuf::KVHasResult> {
        auto active_request = find_active_request(get_caller_executor_id(ctx));
        if (active_request == nullptr)
        {
          return out_of_order_error;
        }

        auto handle = active_request->tx->ro<Map>(payload.table());

        externalexecutor::protobuf::KVHasResult result;
        result.set_present(handle->has(payload.key()));

        return ccf::grpc::make_success(result);
      };

      make_read_only_endpoint(
        "/externalexecutor.protobuf.KV/Has",
        HTTP_POST,
        ccf::grpc_read_only_adapter<
          externalexecutor::protobuf::KVKey,
          externalexecutor::protobuf::KVHasResult>(has),
        executor_only)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto get_version = [this](
                           ccf::endpoints::ReadOnlyEndpointContext& ctx,
                           externalexecutor::protobuf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<
          externalexecutor::protobuf::OptionalKVVersion> {
        auto active_request = find_active_request(get_caller_executor_id(ctx));
        if (active_request == nullptr)
        {
          return out_of_order_error;
        }

        auto handle = active_request->tx->ro<Map>(payload.table());
        auto version = handle->get_version_of_previous_write(payload.key());

        externalexecutor::protobuf::OptionalKVVersion response;
        if (version.has_value())
        {
          externalexecutor::protobuf::KVVersion* response_version =
            response.mutable_optional();
          response_version->set_version(*version);
        }

        return ccf::grpc::make_success(response);
      };

      make_read_only_endpoint(
        "/externalexecutor.protobuf.KV/GetVersion",
        HTTP_POST,
        ccf::grpc_read_only_adapter<
          externalexecutor::protobuf::KVKey,
          externalexecutor::protobuf::OptionalKVVersion>(get_version),
        executor_only)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto get_all = [this](
                       ccf::endpoints::ReadOnlyEndpointContext& ctx,
                       externalexecutor::protobuf::KVTable&& payload)
        -> ccf::grpc::GrpcAdapterResponse<
          std::vector<externalexecutor::protobuf::KVKeyValue>> {
        auto active_request = find_active_request(get_caller_executor_id(ctx));
        if (active_request == nullptr)
        {
          return out_of_order_error;
        }

        auto handle = active_request->tx->ro<Map>(payload.table());
        std::vector<externalexecutor::protobuf::KVKeyValue> results;

        handle->foreach([&results](const auto& k, const auto& v) {
          externalexecutor::protobuf::KVKeyValue& result =
            results.emplace_back();
          result.set_key(k);
          result.set_value(v);

          return true;
        });

        return ccf::grpc::make_success(results);
      };

      make_read_only_endpoint(
        "/externalexecutor.protobuf.KV/GetAll",
        HTTP_POST,
        ccf::grpc_read_only_adapter<
          externalexecutor::protobuf::KVTable,
          std::vector<externalexecutor::protobuf::KVKeyValue>>(get_all),
        executor_only)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto kv_delete = [this](
                         ccf::endpoints::ReadOnlyEndpointContext& ctx,
                         externalexecutor::protobuf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<google::protobuf::Empty> {
        auto active_request = find_active_request(get_caller_executor_id(ctx));
        if (active_request == nullptr)
        {
          return out_of_order_error;
        }

        auto handle = active_request->tx->wo<Map>(payload.table());
        handle->remove(payload.key());

        return ccf::grpc::make_success();
      };

      make_read_only_endpoint(
        "/externalexecutor.protobuf.KV/Delete",
        HTTP_POST,
        ccf::grpc_read_only_adapter<
          externalexecutor::protobuf::KVKey,
          google::protobuf::Empty>(kv_delete),
        executor_only)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto kv_clear = [this](
                        ccf::endpoints::ReadOnlyEndpointContext& ctx,
                        externalexecutor::protobuf::KVTable&& payload)
        -> ccf::grpc::GrpcAdapterResponse<google::protobuf::Empty> {
        auto active_request = find_active_request(get_caller_executor_id(ctx));
        if (active_request == nullptr)
        {
          return out_of_order_error;
        }

        auto handle = active_request->tx->wo<Map>(payload.table());
        handle->clear();

        return ccf::grpc::make_success();
      };

      make_read_only_endpoint(
        "/externalexecutor.protobuf.KV/Clear",
        HTTP_POST,
        ccf::grpc_read_only_adapter<
          externalexecutor::protobuf::KVTable,
          google::protobuf::Empty>(kv_clear),
        executor_only)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();
    }

    void queue_request_for_external_execution(
      ccf::endpoints::EndpointContext& endpoint_ctx, ExecutorId executor_id)
    {
      auto pending_request = std::make_shared<PendingRequest>();

      // Take ownership of underlying tx
      {
        ccf::EndpointContextImpl* ctx_impl =
          dynamic_cast<ccf::EndpointContextImpl*>(&endpoint_ctx);
        if (ctx_impl == nullptr)
        {
          throw std::logic_error("Unexpected context type");
        }

        pending_request->tx = std::move(ctx_impl->owned_tx);
      }

      // Construct RequestDescription from EndpointContext
      {
        externalexecutor::protobuf::RequestDescription& request_description =
          pending_request->request_description;
        request_description.set_method(
          endpoint_ctx.rpc_ctx->get_request_verb().c_str());
        request_description.set_uri(endpoint_ctx.rpc_ctx->get_request_path());
        request_description.set_query(
          endpoint_ctx.rpc_ctx->get_request_query());
        for (const auto& [k, v] : endpoint_ctx.rpc_ctx->get_request_headers())
        {
          externalexecutor::protobuf::Header* header =
            request_description.add_headers();
          header->set_field(k);
          header->set_value(v);
        }
        const auto& body = endpoint_ctx.rpc_ctx->get_request_body();
        request_description.set_body(body.data(), body.size());
      }

      // Lookup originating session and store handle for responding later
      {
        auto http_responder = endpoint_ctx.rpc_ctx->get_responder();
        if (http_responder == nullptr)
        {
          throw std::logic_error(
            "Found no responder for current session/stream");
        }

        pending_request->http_responder = http_responder;
      }

      // Mark response as pending
      {
        auto rpc_ctx_impl =
          dynamic_cast<ccf::RpcContextImpl*>(endpoint_ctx.rpc_ctx.get());
        if (rpc_ctx_impl == nullptr)
        {
          throw std::logic_error("Unexpected type for RpcContext");
        }

        rpc_ctx_impl->response_is_pending = true;
      }
      pending_executor_requests[executor_id].push(pending_request);
    }

    struct ExternallyExecutedEndpoint
      : public ccf::endpoints::EndpointDefinition
    {};

  public:
    EndpointRegistry(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      install_registry_service();

      install_kv_service();

      auto run_string_ops = [this](
                              ccf::endpoints::CommandEndpointContext& ctx,
                              std::vector<temp::OpIn>&& payload,
                              ccf::grpc::StreamPtr<temp::OpOut>&& out_stream) {
        for (temp::OpIn& op : payload)
        {
          temp::OpOut result;
          switch (op.op_case())
          {
            case (temp::OpIn::OpCase::kEcho):
            {
              LOG_INFO_FMT("Got kEcho");
              auto* echo_op = op.mutable_echo();
              auto* echoed = result.mutable_echoed();
              echoed->set_allocated_body(echo_op->release_body());
              break;
            }

            case (temp::OpIn::OpCase::kReverse):
            {
              LOG_INFO_FMT("Got kReverse");
              auto* reverse_op = op.mutable_reverse();
              std::string* s = reverse_op->release_body();
              std::reverse(s->begin(), s->end());
              auto* reversed = result.mutable_reversed();
              reversed->set_allocated_body(s);
              break;
            }

            case (temp::OpIn::OpCase::kTruncate):
            {
              LOG_INFO_FMT("Got kTruncate");
              auto* truncate_op = op.mutable_truncate();
              std::string* s = truncate_op->release_body();
              *s = s->substr(
                truncate_op->start(),
                truncate_op->end() - truncate_op->start());
              auto* truncated = result.mutable_truncated();
              truncated->set_allocated_body(s);
              break;
            }

            case (temp::OpIn::OpCase::OP_NOT_SET):
            {
              LOG_INFO_FMT("Got OP_NOT_SET");
              // oneof may always be null. If the input OpIn was null, then
              // the resulting OpOut is also null
              break;
            }
          }

          out_stream->stream_msg(result);
        }

        return ccf::grpc::make_success();
      };

      make_command_endpoint(
        "/temp.Test/RunOps",
        HTTP_POST,
        ccf::grpc_command_unary_stream_adapter<
          std::vector<temp::OpIn>,
          temp::OpOut>(run_string_ops),
        ccf::no_auth_required)
        .install();

      auto sub = [this](
                   ccf::endpoints::CommandEndpointContext& ctx,
                   temp::Event&& payload,
                   ccf::grpc::StreamPtr<temp::EventInfo>&& out_stream) {
        std::unique_lock<ccf::pal::Mutex> guard(subscribed_events_lock);

        subscribed_events.emplace(std::make_pair(
          payload.SerializeAsString(),
          ccf::grpc::detach_stream(
            std::move(out_stream), [this, event = payload]() {
              std::unique_lock<ccf::pal::Mutex> guard(subscribed_events_lock);

              auto search = subscribed_events.find(event.SerializeAsString());
              if (search != subscribed_events.end())
              {
                LOG_INFO_FMT(
                  "Successfully cleaned up event: {}",
                  event.SerializeAsString());
                subscribed_events.erase(search);
              }
              else
              {
                LOG_FAIL_FMT(
                  "Nothing to cleanup for event: {}",
                  event.SerializeAsString());
              }
            })));
        LOG_INFO_FMT("Subscribed to event {}", payload.SerializeAsString());

        return ccf::grpc::make_pending();
      };
      make_endpoint(
        "/temp.Test/Sub",
        HTTP_POST,
        ccf::grpc_command_unary_stream_adapter<temp::Event, temp::EventInfo>(
          sub),
        {ccf::no_auth_required})
        .install();

      auto pub = [this](
                   ccf::endpoints::CommandEndpointContext& ctx,
                   temp::EventInfo&& payload)
        -> ccf::grpc::GrpcAdapterResponse<google::protobuf::Empty> {
        temp::Event event;
        event.set_name(payload.name());

        std::unique_lock<ccf::pal::Mutex> guard(subscribed_events_lock);

        auto search = subscribed_events.find(event.SerializeAsString());
        if (search != subscribed_events.end())
        {
          if (!search->second->stream_msg(payload))
          {
            // Subscriber streams should be automatically cleaned up from
            // subscribed_events when underlying stream is closed so failure to
            // stream a message to an existing subscriber is considered an
            // error
            throw std::logic_error(fmt::format(
              "Error sending update to subscriber for event {}",
              payload.name()));
          }
        }
        else
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_NOT_FOUND,
            fmt::format(
              "Updates for event {} has no subscriber", payload.name()));
        }

        return ccf::grpc::make_success();
      };

      make_endpoint(
        "/temp.Test/Pub",
        HTTP_POST,
        ccf::grpc_command_adapter<temp::EventInfo, google::protobuf::Empty>(
          pub),
        ccf::no_auth_required)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();
    }

    ccf::endpoints::EndpointDefinitionPtr find_endpoint(
      kv::Tx& tx, ccf::RpcContext& rpc_ctx) override
    {
      auto real_endpoint =
        ccf::endpoints::EndpointRegistry::find_endpoint(tx, rpc_ctx);
      if (real_endpoint)
      {
        return real_endpoint;
      }

      return std::make_shared<ExternallyExecutedEndpoint>();
    }

    std::optional<ExecutorId> validate_supported_endpoints(
      std::string method, std::string uri)
    {
      auto it = supported_uris.find(method + uri);

      if (it == supported_uris.end())
      {
        return std::nullopt;
      }
      auto executor_id = it->second.get_executor_id();

      return executor_id;
    }

    void execute_endpoint(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::EndpointContext& endpoint_ctx) override
    {
      auto endpoint = dynamic_cast<const ExternallyExecutedEndpoint*>(e.get());
      if (endpoint != nullptr)
      {
        std::string method = endpoint_ctx.rpc_ctx->get_request_verb().c_str();
        std::string uri = endpoint_ctx.rpc_ctx->get_request_path();
        std::optional<ExecutorId> executor_id =
          validate_supported_endpoints(method, uri);
        if (!executor_id.has_value())
        {
          auto rpc_ctx_impl =
            dynamic_cast<ccf::RpcContextImpl*>(endpoint_ctx.rpc_ctx.get());
          std::string error_msg =
            "Only registered endpoints are supported. No executor was found "
            "for " +
            method + " and " + uri;
          rpc_ctx_impl->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            std::move(error_msg));
          return;
        }
        queue_request_for_external_execution(endpoint_ctx, executor_id.value());
        return;
      }

      ccf::endpoints::EndpointRegistry::execute_endpoint(e, endpoint_ctx);
    }

    void execute_endpoint_locally_committed(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::CommandEndpointContext& endpoint_ctx,
      const ccf::TxID& tx_id) override
    {
      auto endpoint = dynamic_cast<const ExternallyExecutedEndpoint*>(e.get());
      if (endpoint != nullptr)
      {
        execute_request_locally_committed(e, endpoint_ctx, tx_id);
        return;
      }

      ccf::endpoints::EndpointRegistry::execute_endpoint_locally_committed(
        e, endpoint_ctx, tx_id);
    }

    void execute_request_locally_committed(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::CommandEndpointContext& endpoint_ctx,
      const ccf::TxID& tx_id)
    {
      ccf::endpoints::default_locally_committed_func(endpoint_ctx, tx_id);
    }
  };
} // namespace externalexecutor

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    return std::make_unique<externalexecutor::EndpointRegistry>(context);
  }
} // namespace ccfapp