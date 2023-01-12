// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "grpc_status.h"
#include "status.pb.h"

#include <optional>
#include <string>

namespace ccf::grpc
{
  static int32_t status_to_code(const grpc_status& status)
  {
    return static_cast<int32_t>(status);
  }

  static protobuf::Status make_grpc_status(
    enum grpc_status status,
    const std::optional<std::string>& msg = std::nullopt)
  {
    protobuf::Status s;
    s.set_code(status_to_code(status));
    if (msg.has_value())
    {
      s.set_message(msg.value());
    }
    else
    {
      s.set_message(grpc_status_str(status));
    }
    // Note: details are not currently supported. The fields in this Status are
    // put used for the `grpc-status` and `grpc-message` response trailers, but
    // the details field is not serialised/included in the response
    // if (details.has_value())
    // {
    //   auto* d = s.add_details();
    //   d->set_value(details.value());
    // }
    return s;
  }

  static protobuf::Status make_grpc_status_ok()
  {
    return make_grpc_status(GRPC_STATUS_OK);
  }
}