// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "executor_code_id.h"

struct ExecutorIdentity : public ccf::AuthnIdentity
{
  ExecutorId executor_id;
};

class ExecutorAuthPolicy : public ccf::AuthnPolicy
{
  const ExecutorCertsMap& executor_certs_map = executor_certs;

public:
  std::unique_ptr<ccf::AuthnIdentity> authenticate(
    kv::ReadOnlyTx&,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason) override
  {
    const auto& executor_cert = ctx->get_session_context()->caller_cert;
    if (executor_cert.empty())
    {
      error_reason = "No Executor certificate";
      return nullptr;
    }

    auto pubk_der = crypto::public_key_der_from_cert(executor_cert);
    auto executor_id = crypto::Sha256Hash(pubk_der).hex_str();

    if (executor_certs_map.find(executor_id) != executor_certs_map.end())
    {
      auto executor_identity = std::make_unique<ExecutorIdentity>();
      executor_identity->executor_id = executor_id;
      return executor_identity;
    }
    error_reason = "Could not find matching Executor certificate";
    return nullptr;
  }

  std::optional<ccf::OpenAPISecuritySchema> get_openapi_security_schema()
    const override
  {
    return std::nullopt;
  }

  std::string get_security_scheme_name() override
  {
    return "ExecutorAuthPolicy";
  }
};