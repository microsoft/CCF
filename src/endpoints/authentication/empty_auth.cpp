// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/empty_auth.h"

namespace ccf
{
  std::unique_ptr<AuthnIdentity> EmptyAuthnPolicy::authenticate(
    ccf::kv::ReadOnlyTx&, const std::shared_ptr<ccf::RpcContext>&, std::string&)
  {
    return std::make_unique<EmptyAuthnIdentity>();
  }

  void EmptyAuthnPolicy::set_unauthenticated_error(
    std::shared_ptr<ccf::RpcContext>, std::string&&)
  {
    throw std::logic_error("Should not happen");
  }
}
