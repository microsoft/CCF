// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/http_consts.h"
#include "ccf/json_handler.h"
#include "ccf/kv/map.h"
#include "endpoints/grpc.h"
#include "executor_code_id.h"
#include "http/http_builder.h"
#include "kv.pb.h"
#include "node/endpoint_context_impl.h"

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

  class EndpointRegistry : public ccf::UserEndpointRegistry
  {
    // Note: As a temporary solution for testing, this app stores a single Tx,
    // stolen from a StartTx RPC rather than a real client request
    std::unique_ptr<kv::CommittableTx> active_tx = nullptr;

    std::queue<ccf::RequestDescription> pending_requests;

    void install_registry_service()
    {
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
        ccf::no_auth_required)
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
        ccf::no_auth_required)
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
        ccf::no_auth_required)
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
        ccf::no_auth_required)
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
        ccf::no_auth_required)
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
        ccf::no_auth_required)
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