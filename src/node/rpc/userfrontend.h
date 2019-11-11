// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "frontend.h"
#include "node/clientsignatures.h"

namespace ccf
{
  class UserRpcFrontend : public RpcFrontend<Users>
  {
  public:
    UserRpcFrontend(Store& tables_) :
      RpcFrontend<Users>(
        tables_,
        tables_.get<ClientSignatures>(Tables::USER_CLIENT_SIGNATURES),
        tables_.get<Certs>(Tables::USER_CERTS),
        tables_.get<Users>(Tables::USERS))
    {}

  protected:
    std::string invalid_caller_error_message() const override
    {
      return "Could not find matching user certificate";
    }
  };
}
