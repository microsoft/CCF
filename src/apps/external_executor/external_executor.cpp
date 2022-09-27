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
#include "executor_code_id.h"
#include "executor_registration.pb.h"
#include "kv.pb.h"
#include "node/endpoint_context_impl.h"
#include "stringops.pb.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <string>

namespace externalexecutor
{
  using Map = kv::Map<std::string, std::string>;
  using ExecutorId = ccf::EntityId<ccf::NodeIdFormatter>;
  std::map<ExecutorId, ExecutorNodeInfo> ExecutorIDs;

  class EndpointRegistry : public ccf::UserEndpointRegistry
  {
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
        crypto::Pem executor_public_key(payload.cert());
        auto pubk_der = crypto::cert_pem_to_der(executor_public_key);
        ExecutorId executor_id = ccf::compute_node_id_from_pubk_der(pubk_der);
        std::vector<ccf::NewExecutor::EndpointKey> supported_endpoints(
          payload.supported_endpoints().begin(),
          payload.supported_endpoints().end());

        ExecutorNodeInfo executor_info = {
          executor_public_key, payload.attestation(), supported_endpoints};

        ExecutorIDs[executor_id] = executor_info;

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

        auto records_handle = active_tx->rw<Map>(payload.table());
        records_handle->put(payload.key(), payload.value());

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

        auto records_handle = active_tx->ro<Map>(payload.table());
        auto value = records_handle->get(payload.key());
        if (!value.has_value())
        {
          // Note: no need to specify `make_error<ccf::KVValue>` here as lambda
          // returns `-> ccf::grpc::GrpcAdapterResponse<ccf::KVValue>`
          return ccf::grpc::make_error(
            GRPC_STATUS_NOT_FOUND,
            fmt::format("Key {} does not exist", payload.key()));
        }

        ccf::KVValue r;
        r.set_value(value.value());

        return ccf::grpc::make_success(r);
      };

      make_read_only_endpoint(
        "ccf.KV/Get",
        HTTP_POST,
        ccf::grpc_read_only_adapter<ccf::KVKey, ccf::KVValue>(get),
        ccf::no_auth_required)
        .install();
    }

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
              // oneof may always be null. If the input OpIn was null, then the
              // resulting OpOut is also null
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