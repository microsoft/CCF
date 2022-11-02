// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"

#include <memory>

namespace http
{
  class HTTPResponder;

  class AbstractResponderLookup : public ccf::AbstractNodeSubSystem
  {
  public:
    static char const* get_subsystem_name()
    {
      return "ResponderLookup";
    }

    virtual std::shared_ptr<HTTPResponder> lookup_responder(
      tls::ConnID session_id, http2::StreamId stream_id) = 0;
  };
}
