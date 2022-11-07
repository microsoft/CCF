// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/crypto/verifier.h"
#include "ccf/entity_id.h"
#include "ccf/http_consts.h"
#include "ccf/json_handler.h"
#include "ccf/kv/map.h"
#include "ccf/service/tables/nodes.h"
#include "ds/thread_messaging.h" // TODO: Private include
#include "endpoints/grpc.h"
#include "executor_auth_policy.h"
#include "executor_code_id.h"
#include "executor_registration.pb.h"
#include "http/http_builder.h"
#include "kv.pb.h"
#include "node/endpoint_context_impl.h"
#include "stringops.pb.h"

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
  std::map<ExecutorId, ExecutorNodeInfo> ExecutorIDs;

  class EndpointRegistry : public ccf::UserEndpointRegistry
  {
    // Note: As a temporary solution for testing, this app stores a single Tx,
    // stolen from a StartTx RPC rather than a real client request
    std::unique_ptr<kv::CommittableTx> active_tx = nullptr;

    std::queue<ccf::RequestDescription> pending_requests;

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
      auto register_executor = [this](auto& ctx, ccf::NewExecutor&& payload)
        -> ccf::grpc::GrpcAdapterResponse<ccf::RegistrationResult> {
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
        std::vector<ccf::NewExecutor::EndpointKey> supported_endpoints(
          payload.supported_endpoints().begin(),
          payload.supported_endpoints().end());

        ExecutorNodeInfo executor_info = {
          executor_x509_cert, payload.attestation(), supported_endpoints};

        executor_ids[executor_id] = executor_info;

        // Record the certs in the Executor certs map
        executor_certs[executor_id] = executor_x509_cert;

        ccf::RegistrationResult result;
        result.set_details("Executor registration is accepted.");
        result.set_executor_id(executor_id.value());

        return ccf::grpc::make_success(result);
      };

      make_endpoint(
        "ccf.ExecutorRegistration/RegisterExecutor",
        HTTP_POST,
        ccf::grpc_adapter<ccf::NewExecutor, ccf::RegistrationResult>(
          register_executor),
        ccf::no_auth_required)
        .install();
    }

    struct DelayedStreamMsg
    {
      std::shared_ptr<ccf::RpcContext> rpc_ctx;
      DelayedStreamMsg(const std::shared_ptr<ccf::RpcContext>& rpc_ctx_) :
        rpc_ctx(rpc_ctx_)
      {}
    };

    static void send_stream_payload(
      const std::shared_ptr<ccf::RpcContext>& rpc_ctx, bool close_stream)
    {
      static size_t count = 0;
      ccf::KVKeyValue kv;
      kv.set_key("lala");
      kv.set_value(fmt::format("my_value: {}", std::pow(10, count)));
      count++;

      const auto message_length = kv.ByteSizeLong();
      size_t r_size = ccf::grpc::impl::message_frame_length + message_length;
      std::vector<uint8_t> data;
      data.resize(r_size);
      auto r_data = data.data();

      ccf::grpc::impl::write_message_frame(r_data, r_size, message_length);

      if (!kv.SerializeToArray(r_data, r_size))
      {
        throw std::logic_error(fmt::format(
          "Error serialising protobuf response of type {}, size {}",
          kv.GetTypeName(),
          message_length));
      }

      CCF_APP_FAIL("Stream some data: {}", data.size());

      // TODO: There should be an option to close the stream too
      rpc_ctx->stream(std::move(data), close_stream);
    }

    static void async_send_stream_data(
      const std::shared_ptr<ccf::RpcContext>& rpc_ctx)
    {
      auto msg = std::make_unique<threading::Tmsg<DelayedStreamMsg>>(
        [](std::unique_ptr<threading::Tmsg<DelayedStreamMsg>> msg) {
          static size_t call_count = 0;
          LOG_FAIL_FMT("Sending asynchronous streaming data: {}", call_count);
          call_count++;
          bool should_stop = call_count > 5;
          send_stream_payload(msg->data.rpc_ctx, should_stop);

          if (!should_stop)
          {
            async_send_stream_data(msg->data.rpc_ctx);
          }
        },
        rpc_ctx);

      threading::ThreadMessaging::thread_messaging.add_task_after(
        std::move(msg), std::chrono::milliseconds(1000));
    }

    void install_kv_service()
    {
      auto start = [this](
                     ccf::endpoints::EndpointContext& ctx,
                     google::protobuf::Empty&& payload)
        -> ccf::grpc::GrpcAdapterResponse<ccf::OptionalRequestDescription> {
        if (active_tx != nullptr)
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Already managing an active transaction");
        }

        ccf::EndpointContextImpl* ctx_impl =
          dynamic_cast<ccf::EndpointContextImpl*>(&ctx);
        if (ctx_impl == nullptr)
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_INTERNAL, "Unexpected context type");
        }

        active_tx = std::move(ctx_impl->owned_tx);
        ctx_impl->owned_tx = nullptr; // < This will be done by move, but adding
                                      // explicit call here for clarity

        // Note: Temporary hack to make sure the caller doesn't try to commit
        // this transaction
        ctx.rpc_ctx->set_apply_writes(false);

        ccf::OptionalRequestDescription opt_rd;

        if (!pending_requests.empty())
        {
          auto* rd = opt_rd.mutable_optional();
          *rd = pending_requests.front();
          pending_requests.pop();
        }

        return ccf::grpc::make_success(opt_rd);
      };

      auto executor_auth_policy = std::make_shared<ExecutorAuthPolicy>();
      make_endpoint(
        "/ccf.KV/StartTx",
        HTTP_POST,
        ccf::grpc_adapter<
          google::protobuf::Empty,
          ccf::OptionalRequestDescription>(start),
        ccf::no_auth_required)
        .install();

      auto end = [this](
                   ccf::endpoints::EndpointContext& ctx,
                   ccf::ResponseDescription&& payload)
        -> ccf::grpc::GrpcAdapterResponse<google::protobuf::Empty> {
        if (active_tx == nullptr)
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Not managing an active transaction - this should be called after "
            "a successful call to StartTx");
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

        kv::CommitResult result = active_tx->commit(claims);
        switch (result)
        {
          case kv::CommitResult::SUCCESS:
          {
            http::Response response((http_status)payload.status_code());
            response.set_body(payload.body());
            for (int i = 0; i < payload.headers_size(); ++i)
            {
              const ccf::Header& header = payload.headers(i);
              response.set_header(header.field(), header.value());
            }

            auto tx_id = active_tx->get_txid();
            if (tx_id.has_value())
            {
              LOG_INFO_FMT("Applied tx at {}", tx_id->str());
              response.set_header(http::headers::CCF_TX_ID, tx_id->str());
            }

            const auto response_v = response.build_response();
            const std::string response_s(response_v.begin(), response_v.end());
            LOG_INFO_FMT(
              "Preparing to send final response to user:\n{}", response_s);
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
        active_tx = nullptr;

        return ccf::grpc::make_success();
      };

      make_endpoint(
        "/ccf.KV/EndTx",
        HTTP_POST,
        ccf::grpc_adapter<ccf::ResponseDescription, google::protobuf::Empty>(
          end),
        ccf::no_auth_required)
        .install();

      auto put =
        [this](ccf::endpoints::EndpointContext& ctx, ccf::KVKeyValue&& payload)
        -> ccf::grpc::GrpcAdapterResponse<google::protobuf::Empty> {
        if (active_tx == nullptr)
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Not managing an active transaction - this should be called after "
            "a successful call to StartTx and before EndTx");
        }

        auto handle = active_tx->rw<Map>(payload.table());
        handle->put(payload.key(), payload.value());

        return ccf::grpc::make_success();
      };

      make_endpoint(
        "/ccf.KV/Put",
        HTTP_POST,
        ccf::grpc_adapter<ccf::KVKeyValue, google::protobuf::Empty>(put),
        {executor_auth_policy})
        .install();

      auto get = [this](
                   ccf::endpoints::ReadOnlyEndpointContext& ctx,
                   ccf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<ccf::OptionalKVValue> {
        if (active_tx == nullptr)
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Not managing an active transaction - this should be called after "
            "a successful call to StartTx and before EndTx");
        }

        auto handle = active_tx->ro<Map>(payload.table());
        auto result = handle->get(payload.key());

        ccf::OptionalKVValue response;
        if (result.has_value())
        {
          ccf::KVValue* response_value = response.mutable_optional();
          response_value->set_value(*result);
        }

        return ccf::grpc::make_success(response);
      };

      make_read_only_endpoint(
        "/ccf.KV/Get",
        HTTP_POST,
        ccf::grpc_read_only_adapter<ccf::KVKey, ccf::OptionalKVValue>(get),
        {executor_auth_policy})
        .install();

      auto has = [this](
                   ccf::endpoints::ReadOnlyEndpointContext& ctx,
                   ccf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<ccf::KVHasResult> {
        if (active_tx == nullptr)
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Not managing an active transaction - this should be called after "
            "a successful call to StartTx and before EndTx");
        }

        auto handle = active_tx->ro<Map>(payload.table());

        ccf::KVHasResult result;
        result.set_present(handle->has(payload.key()));

        return ccf::grpc::make_success(result);
      };

      make_read_only_endpoint(
        "/ccf.KV/Has",
        HTTP_POST,
        ccf::grpc_read_only_adapter<ccf::KVKey, ccf::KVHasResult>(has),
        {executor_auth_policy})
        .install();

      auto get_version = [this](
                           ccf::endpoints::ReadOnlyEndpointContext& ctx,
                           ccf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<ccf::OptionalKVVersion> {
        if (active_tx == nullptr)
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Not managing an active transaction - this should be called after "
            "a successful call to StartTx and before EndTx");
        }

        auto handle = active_tx->ro<Map>(payload.table());
        auto version = handle->get_version_of_previous_write(payload.key());

        ccf::OptionalKVVersion response;
        if (version.has_value())
        {
          ccf::KVVersion* response_version = response.mutable_optional();
          response_version->set_version(*version);
        }

        return ccf::grpc::make_success(response);
      };

      make_read_only_endpoint(
        "/ccf.KV/GetVersion",
        HTTP_POST,
        ccf::grpc_read_only_adapter<ccf::KVKey, ccf::OptionalKVVersion>(
          get_version),
        {executor_auth_policy})
        .install();

      auto kv_delete = [this](
                         ccf::endpoints::ReadOnlyEndpointContext& ctx,
                         ccf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<google::protobuf::Empty> {
        if (active_tx == nullptr)
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Not managing an active transaction - this should be called after "
            "a successful call to StartTx and before EndTx");
        }

        auto handle = active_tx->wo<Map>(payload.table());
        handle->remove(payload.key());

        return ccf::grpc::make_success();
      };

      make_read_only_endpoint(
        "/ccf.KV/Delete",
        HTTP_POST,
        ccf::grpc_read_only_adapter<ccf::KVKey, google::protobuf::Empty>(
          kv_delete),
        {executor_auth_policy})
        .install();

      auto get_all = [this](
                       ccf::endpoints::ReadOnlyEndpointContext& ctx,
                       ccf::KVTable&& payload)
        -> ccf::grpc::GrpcAdapterResponse<ccf::KVValue> {
        return ccf::grpc::make_error(
          GRPC_STATUS_UNIMPLEMENTED, "Unimplemented");
      };

      make_read_only_endpoint(
        "/ccf.KV/GetAll",
        HTTP_POST,
        ccf::grpc_read_only_adapter<ccf::KVTable, ccf::KVValue>(get_all),
        {executor_auth_policy})
        .install();

      auto stream = [this](
                      ccf::endpoints::EndpointContext& ctx,
                      google::protobuf::Empty&& payload) {
        // Dummy streaming endpoint
        ccf::KVValue kv;

        // TODO:
        // 1. Create gRPC server stream wrapper that sets stream as non-unary
        // 2. Add ability to close stream from rpc_ctx->stream(data, close=true)
        // or rpc_ctx->stream_close();
        // 3. Create stream object from rpc_ctx, and then
        // rpc_ctx->create_stream() (figure out ownership and lifetime)

        LOG_FAIL_FMT("Endpoint synchronous execution");

        async_send_stream_data(ctx.rpc_ctx);

        ctx.rpc_ctx->set_is_streaming(); // TODO: Add to wrapper

        return ccf::grpc::make_success();
      };

      make_endpoint(
        "/ccf.KV/Stream",
        HTTP_POST,
        ccf::grpc_adapter<google::protobuf::Empty, google::protobuf::Empty>(
          stream),
        {ccf::no_auth_required})
        .install();
    }

    void queue_request_for_external_execution(
      ccf::endpoints::EndpointContext& endpoint_ctx)
    {
      ccf::RequestDescription rd;
      {
        // Construct rd from request
        rd.set_method(endpoint_ctx.rpc_ctx->get_request_verb().c_str());
        rd.set_uri(endpoint_ctx.rpc_ctx->get_request_path());
        for (const auto& [k, v] : endpoint_ctx.rpc_ctx->get_request_headers())
        {
          ccf::Header* header = rd.add_headers();
          header->set_field(k);
          header->set_value(v);
        }
        const auto& body = endpoint_ctx.rpc_ctx->get_request_body();
        rd.set_body(body.data(), body.size());
      }
      pending_requests.push(rd);

      endpoint_ctx.rpc_ctx->set_response_status(200);
      endpoint_ctx.rpc_ctx->set_response_body(
        "Executing your request, but not responding to you about it (yet!)");
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
                              std::vector<temp::OpIn>&& payload)
        -> ccf::grpc::GrpcAdapterResponse<std::vector<temp::OpOut>> {
        std::vector<temp::OpOut> results;

        for (temp::OpIn& op : payload)
        {
          temp::OpOut& result = results.emplace_back();
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
        }

        return ccf::grpc::make_success(results);
      };

      make_command_endpoint(
        "/temp.Test/RunOps",
        HTTP_POST,
        ccf::grpc_command_adapter<
          std::vector<temp::OpIn>,
          std::vector<temp::OpOut>>(run_string_ops),
        ccf::no_auth_required)
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

    void execute_endpoint(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::EndpointContext& endpoint_ctx) override
    {
      auto endpoint = dynamic_cast<const ExternallyExecutedEndpoint*>(e.get());
      if (endpoint != nullptr)
      {
        queue_request_for_external_execution(endpoint_ctx);
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