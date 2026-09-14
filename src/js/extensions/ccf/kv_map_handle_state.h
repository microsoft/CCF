// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/kv_access_permissions.h"
#include "ccf/tx_id.h"

#include <string>

namespace ccf::js::extensions::kvhelpers
{
  // Prevent methods for one KV source from accepting handles for the other.
  enum class KVSource : uint8_t
  {
    CurrentTx,
    Historical
  };

  // C++-owned identity and permissions resolved at handle creation.
  struct KVMapHandleState
  {
    std::string map_name;

    KVAccessPermissions access_permission = KVAccessPermissions::ILLEGAL;

    // Used in denied-operation errors
    std::string permission_explanation;

    KVSource source = KVSource::CurrentTx;

    // Used for historical handles
    ccf::SeqNo seqno = 0;
  };
}
