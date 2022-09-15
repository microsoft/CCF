// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/http_consts.h"
#include "ccf/json_handler.h"
#include "ccf/kv/map.h"
#include "endpoints/grpc.h"
#include "executor_code_id.h"
#include "kv.pb.h"
#include "node/endpoint_context_impl.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <string>

namespace externalexecutor
{
  using Map = kv::Map<std::string, std::string>;

  class EndpointRegistry : public ccf::UserEndpointRegistry
  {
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

    // Note: As a temporary solution for testing, this app stores a single Tx,
    // stolen from a StartTx RPC rather than a real client request
    std::unique_ptr<kv::CommittableTx> active_tx = nullptr;

    void install_kv_service()
    {
      auto start = [this](
                     ccf::endpoints::EndpointContext& ctx,
                     google::protobuf::Empty&& payload)
        -> ccf::grpc::GrpcAdapterResponse<ccf::RequestDescription> {
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

        ccf::RequestDescription rd;
        rd.set_method("POST");
        rd.set_uri("/foo/bar");
        return ccf::grpc::make_success(rd);
      };

      make_endpoint(
        "ccf.KV/StartTx",
        HTTP_POST,
        ccf::grpc_adapter<google::protobuf::Empty, ccf::RequestDescription>(
          start),
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

        ccf::EndpointContextImpl* ctx_impl =
          dynamic_cast<ccf::EndpointContextImpl*>(&ctx);
        if (ctx_impl == nullptr)
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_INTERNAL, "Unexpected context type");
        }

        ctx_impl->owned_tx = std::move(active_tx);
        active_tx = nullptr;

        return ccf::grpc::make_success();
      };

      make_endpoint(
        "ccf.KV/EndTx",
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
        "ccf.KV/Put",
        HTTP_POST,
        ccf::grpc_adapter<ccf::KVKeyValue, google::protobuf::Empty>(put),
        ccf::no_auth_required)
        .install();

      auto get = [this](
                   ccf::endpoints::ReadOnlyEndpointContext& ctx,
                   ccf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<ccf::KVValue> {
        if (active_tx == nullptr)
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Not managing an active transaction - this should be called after "
            "a successful call to StartTx and before EndTx");
        }

        auto handle = active_tx->ro<Map>(payload.table());
        auto result = handle->get(payload.key());

        ccf::KVValue response;
        if (result.has_value())
        {
          response.set_value(*result);
        }

        return ccf::grpc::make_success(response);
      };

      make_read_only_endpoint(
        "ccf.KV/Get",
        HTTP_POST,
        ccf::grpc_read_only_adapter<ccf::KVKey, ccf::KVValue>(get),
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
        "ccf.KV/Has",
        HTTP_POST,
        ccf::grpc_read_only_adapter<ccf::KVKey, ccf::KVHasResult>(has),
        ccf::no_auth_required)
        .install();

      auto get_version = [this](
                           ccf::endpoints::ReadOnlyEndpointContext& ctx,
                           ccf::KVKey&& payload)
        -> ccf::grpc::GrpcAdapterResponse<ccf::KVVersion> {
        if (active_tx == nullptr)
        {
          return ccf::grpc::make_error(
            GRPC_STATUS_FAILED_PRECONDITION,
            "Not managing an active transaction - this should be called after "
            "a successful call to StartTx and before EndTx");
        }

        auto handle = active_tx->ro<Map>(payload.table());
        auto version = handle->get_version_of_previous_write(payload.key());

        ccf::KVVersion response;
        if (version.has_value())
        {
          response.set_version(*version);
        }

        return ccf::grpc::make_success(response);
      };

      make_read_only_endpoint(
        "ccf.KV/GetVersion",
        HTTP_POST,
        ccf::grpc_read_only_adapter<ccf::KVKey, ccf::KVVersion>(get_version),
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
        "ccf.KV/Delete",
        HTTP_POST,
        ccf::grpc_read_only_adapter<ccf::KVKey, google::protobuf::Empty>(
          kv_delete),
        ccf::no_auth_required)
        .install();

      // TODO: Stream return type
      // auto get_all = [this](
      //              ccf::endpoints::ReadOnlyEndpointContext& ctx,
      //              ccf::KVKey&& payload)
      //   -> ccf::grpc::GrpcAdapterResponse<ccf::KVValue> {
      //   if (active_tx == nullptr)
      //   {
      //     return ccf::grpc::make_error(
      //       GRPC_STATUS_FAILED_PRECONDITION,
      //       "Not managing an active transaction - this should be called after
      //       " "a successful call to StartTx and before EndTx");
      //   }

      //   auto handle = active_tx->ro<Map>(payload.table());
      //   auto value = handle->get(payload.key());
      //   if (!value.has_value())
      //   {
      //     // Note: no need to specify `make_error<ccf::KVValue>` here as
      //     lambda
      //     // returns `-> ccf::grpc::GrpcAdapterResponse<ccf::KVValue>`
      //     return ccf::grpc::make_error(
      //       GRPC_STATUS_NOT_FOUND,
      //       fmt::format("Key {} does not exist", payload.key()));
      //   }

      //   ccf::KVValue r;
      //   r.set_value(value.value());

      //   return ccf::grpc::make_success(r);
      // };

      // make_read_only_endpoint(
      //   "ccf.KV/GetAll",
      //   HTTP_POST,
      //   ccf::grpc_read_only_adapter<ccf::KVKey, ccf::KVValue>(get_version),
      //   ccf::no_auth_required)
      //   .install();
    }

  public:
    EndpointRegistry(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context)
    {
      install_registry_service();

      install_kv_service();
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