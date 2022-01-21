// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft_types.h"
#include "kv/kv_types.h"

#include <optional>

namespace ccf
{
  class ResharingTracker
  {
  public:
    virtual void add_network_configuration(const kv::Configuration& config) = 0;
    virtual void add_resharing_result(
      ccf::SeqNo seqno,
      kv::ReconfigurationId rid,
      const ResharingResult& result) = 0;
    virtual bool have_resharing_result_for(
      kv::ReconfigurationId rid, ccf::SeqNo idx) const = 0;
    virtual ResharingResult get_resharing_result(
      kv::ReconfigurationId rid) const = 0;
    virtual void reshare(const kv::Configuration& config) = 0;
    virtual std::optional<kv::ReconfigurationId> find_reconfiguration(
      const kv::Configuration::Nodes& nodes) const = 0;

    virtual void rollback(aft::Index idx) = 0;
    virtual void compact(aft::Index idx) = 0;
  };
}
