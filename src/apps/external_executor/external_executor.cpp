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
#include "endpoints/grpc.h"
#include "executor_auth_policy.h"
#include "executor_code_id.h"
#include "executor_registration.pb.h"
#include "http/http2_session.h"
#include "http/http_builder.h"
#include "http/http_responder.h"
#include "kv.pb.h"
#include "node/endpoint_context_impl.h"
#include "node/rpc/rpc_context_impl.h"
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
    struct PendingRequest
    {
      std::unique_ptr<kv::CommittableTx> tx = nullptr;
      externalexecutor::protobuf::RequestDescription request_description;
      std::shared_ptr<http::HTTPResponder> http_responder;
    };
    std::queue<PendingRequest> pending_requests;

    std::optional<PendingRequest> active_request;

    std::shared_ptr<http::AbstractResponderLookup> responder_lookup = nullptr;

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

    void install_kv_service()
    {
      auto executor_auth_policy = std::make_shared<ExecutorAuthPolicy>();
      ccf::AuthnPolicies executor_only{executor_auth_policy};

      auto start = [this](
                     ccf::endpoints::CommandEndpointContext& ctx,
                     google::protobuf::Empty&& payload)
        -> ccf::grpc::GrpcAdapterResponse<
          externalexecutor::protobuf::OptionalRequestDescription> {
        if (active_request.has_value())
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Already managing an active transaction");
        }

        externalexecutor::protobuf::OptionalRequestDescription
          optional_request_description;

        if (!pending_requests.empty())
        {
          auto* request_description =
            optional_request_description.mutable_optional();
          auto& pending_request = pending_requests.front();
          *request_description = pending_request.request_description;
          // NB: Move for unique_ptr
          active_request = std::move(pending_request);
          pending_requests.pop();
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
        .install();

      auto end = [this](
                   ccf::endpoints::EndpointContext& ctx,
                   externalexecutor::protobuf::ResponseDescription&& payload)
        -> ccf::grpc::GrpcAdapterResponse<google::protobuf::Empty> {
        if (!active_request.has_value())
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
            active_request->http_responder->send_response(
              (http_status)payload.status_code(),
              std::move(headers),
              std::move(trailers),
              {(const uint8_t*)body_s.data(), body_s.size()});
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

        active_request.reset();

        return ccf::grpc::make_success();
      };

      make_endpoint(
        "/externalexecutor.protobuf.KV/EndTx",
        HTTP_POST,
        ccf::grpc_adapter<
          externalexecutor::protobuf::ResponseDescription,
          google::protobuf::Empty>(end),
        executor_only)
        .install();

      auto put = [this](
                   ccf::endpoints::EndpointContext& ctx,
                   externalexecutor::protobuf::KVKeyValue&& payload)
        -> ccf::grpc::GrpcAdapterResponse<google::protobuf::Empty> {
        if (!active_request.has_value())
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Not managing an active transaction - this should be called "
            "after "
            "a successful call to StartTx and before EndTx");
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
        .install();

      auto get = [this](
                   ccf::endpoints::ReadOnlyEndpointContext& ctx,
                   externalexecutor::protobuf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<
          externalexecutor::protobuf::OptionalKVValue> {
        if (!active_request.has_value())
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Not managing an active transaction - this should be called "
            "after "
            "a successful call to StartTx and before EndTx");
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
        .install();

      auto has = [this](
                   ccf::endpoints::ReadOnlyEndpointContext& ctx,
                   externalexecutor::protobuf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<
          externalexecutor::protobuf::KVHasResult> {
        if (!active_request.has_value())
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Not managing an active transaction - this should be called "
            "after "
            "a successful call to StartTx and before EndTx");
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
        .install();

      auto get_version = [this](
                           ccf::endpoints::ReadOnlyEndpointContext& ctx,
                           externalexecutor::protobuf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<
          externalexecutor::protobuf::OptionalKVVersion> {
        if (!active_request.has_value())
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Not managing an active transaction - this should be called "
            "after "
            "a successful call to StartTx and before EndTx");
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
        .install();

      auto kv_delete = [this](
                         ccf::endpoints::ReadOnlyEndpointContext& ctx,
                         externalexecutor::protobuf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<google::protobuf::Empty> {
        if (!active_request.has_value())
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Not managing an active transaction - this should be called "
            "after "
            "a successful call to StartTx and before EndTx");
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
        .install();

      auto get_all = [this](
                       ccf::endpoints::ReadOnlyEndpointContext& ctx,
                       externalexecutor::protobuf::KVTable&& payload)
        -> ccf::grpc::GrpcAdapterResponse<externalexecutor::protobuf::KVValue> {
        return ccf::grpc::make_error(
          GRPC_STATUS_UNIMPLEMENTED, "Unimplemented");
      };

      make_read_only_endpoint(
        "/externalexecutor.protobuf.KV/GetAll",
        HTTP_POST,
        ccf::grpc_read_only_adapter<
          externalexecutor::protobuf::KVTable,
          externalexecutor::protobuf::KVValue>(get_all),
        executor_only)
        .install();
    }

    void queue_request_for_external_execution(
      ccf::endpoints::EndpointContext& endpoint_ctx)
    {
      PendingRequest pending_request;

      // Take ownership of underlying tx
      {
        ccf::EndpointContextImpl* ctx_impl =
          dynamic_cast<ccf::EndpointContextImpl*>(&endpoint_ctx);
        if (ctx_impl == nullptr)
        {
          throw std::logic_error("Unexpected context type");
        }

        pending_request.tx = std::move(ctx_impl->owned_tx);
      }

      // Construct RequestDescription from EndpointContext
      {
        externalexecutor::protobuf::RequestDescription& request_description =
          pending_request.request_description;
        request_description.set_method(
          endpoint_ctx.rpc_ctx->get_request_verb().c_str());
        request_description.set_uri(endpoint_ctx.rpc_ctx->get_request_path());
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
        auto http2_session_context =
          std::dynamic_pointer_cast<http::HTTP2SessionContext>(
            endpoint_ctx.rpc_ctx->get_session_context());
        if (http2_session_context == nullptr)
        {
          throw std::logic_error("Unexpected session context type");
        }

        const auto session_id = http2_session_context->client_session_id;
        const auto stream_id = http2_session_context->stream_id;

        auto http_responder =
          responder_lookup->lookup_responder(session_id, stream_id);
        if (http_responder == nullptr)
        {
          throw std::logic_error(fmt::format(
            "Found no responder for session {}, stream {}",
            session_id,
            stream_id));
        }

        pending_request.http_responder = http_responder;
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

      pending_requests.push(std::move(pending_request));
    }

    struct ExternallyExecutedEndpoint
      : public ccf::endpoints::EndpointDefinition
    {};

  public:
    EndpointRegistry(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      responder_lookup = context.get_subsystem<http::AbstractResponderLookup>();
      if (responder_lookup == nullptr)
      {
        throw std::runtime_error(fmt::format(
          "App cannot be constructed without ResponderLookup subsystem"));
      }

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