// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "frontend.h"
#include "node/clientsignatures.h"

namespace ccf
{
  class UserRpcFrontend : public RpcFrontend
  {
  public:
    UserRpcFrontend(Store& tables_) :
      RpcFrontend(
        tables_,
        tables_.get<ClientSignatures>(Tables::USER_CLIENT_SIGNATURES),
        tables_.get<Certs>(Tables::USER_CERTS),
        true)
    {}
  };
}
