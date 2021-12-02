// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "context.h"

namespace tls
{
  class Server : public Context
  {
  private:
    std::shared_ptr<Cert> cert;

  public:
    Server(std::shared_ptr<Cert> cert_, bool dtls = false) :
      Context(false, dtls),
      cert(cert_)
    {
      cert->use(ssl.get(), cfg.get());
    }
  };
}
