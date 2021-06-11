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
    virtual void add_network_configuration(
      ccf::SeqNo seqno, const kv::NetworkConfiguration& config) = 0;
    virtual void add_resharing_result(
      ccf::SeqNo seqno,
      kv::ReconfigurationId rid,
      const ResharingResult& result) = 0;
    virtual bool have_resharing_result_for(
      kv::ReconfigurationId rid, ccf::SeqNo idx) const = 0;
    virtual ResharingResult get_resharing_result(
      kv::ReconfigurationId rid) const = 0;
    virtual void reshare(
      ccf::SeqNo seqno, const kv::NetworkConfiguration& config) = 0;
    virtual void start_next_session() {}
    virtual void set_active_config(const kv::NetworkConfiguration& cfg) = 0;
    virtual const kv::NetworkConfiguration& active_config() const = 0;
    virtual void rollback(aft::Index idx) = 0;
    virtual void compact(aft::Index idx) = 0;
  };
}
