// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace ccf::js
{
  /// Describes the context in which JS script is currently executing. Used to
  /// determine which KV tables should be accessible.
  enum class TxAccess : uint8_t
  {
    /// Application code, during evaluation of an endpoint handler function
    /// marked as readonly
    APP_RO,

    /// Application code, during evaluation of an endpoint handler function
    /// marked as readwrite
    APP_RW,

    /// Read-only governance execution, during evaluation of ballots, and of the
    /// 'validate' and 'resolve' functions in the constitution
    GOV_RO,

    /// Read-write governance execution, during evaluation of the 'apply'
    /// function in the constitution
    GOV_RW
  };
}
