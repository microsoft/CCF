// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "context.h"

namespace tls
{
  class Client : public ccf::tls::Context
  {
  private:
    std::shared_ptr<Cert> cert;

  public:
    Client(
      std::shared_ptr<Cert> cert_,
      const std::vector<std::string>& groups = {"P-521", "P-384", "P-256"}) :
      Context(true, groups),
      cert(std::move(cert_))
    {
      cert->configure_ssl(ssl, cfg);
    }
  };
}
