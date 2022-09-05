// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/http_consts.h"
#include "ccf/kv/map.h"
#include "grpc.h"
#include "kv.pb.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <string>

namespace externalexecutor
{
  using Map = kv::Map<std::string, std::string>;

  class EndpointRegistry : public ccf::UserEndpointRegistry
  {
    void install_registry_service() {}

    void install_kv_service()
    {
      auto put = [this](
                   ccf::endpoints::EndpointContext& ctx,
                   ccf::KVKeyValue&& payload) {
        auto records_handle = ctx.tx.template rw<Map>(payload.table());
        records_handle->put(payload.key(), payload.value());

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      };

      make_endpoint(
        "ccf.KV/Put",
        HTTP_POST,
        ccf::grpc_adapter<ccf::KVKeyValue, void>(put),
        ccf::no_auth_required)
        .install();

      auto get = [this](
                   ccf::endpoints::ReadOnlyEndpointContext& ctx,
                   ccf::KVKey&& payload) {
        auto records_handle = ctx.tx.template ro<Map>(payload.table());
        auto value = records_handle->get(payload.key());
        if (!value.has_value())
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_NOT_FOUND);
          return ccf::KVValue(); // Handle errors
        }

        ccf::KVValue r;
        r.set_value(value.value());

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        return r;
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