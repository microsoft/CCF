// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"

namespace aft
{
  class IStore;

  class IGlobalCommitHandler
  {
  public:
    IGlobalCommitHandler() = default;
    virtual ~IGlobalCommitHandler() = default;

    virtual void perform_global_commit(
      kv::Version version, kv::Consensus::View view) = 0;
    virtual kv::Consensus::View get_view_for_version(kv::Version version) = 0;
  };

  std::unique_ptr<IGlobalCommitHandler> create_global_commit_handler(
    IStore& store);
}