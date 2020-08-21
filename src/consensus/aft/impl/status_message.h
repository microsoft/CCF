// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft_types.h"
#include "ds/ccf_assert.h"
#include "kv/kv_types.h"
#include "message.h"

namespace aft
{
#pragma pack(push)
#pragma pack(1)
  struct StatusMessageRep : public consensus::ConsensusHeader<RaftMsgType>
  {
    StatusMessageRep(
      aft::NodeId from_node,
      kv::Consensus::View view_,
      kv::Version last_good_version_) :
      consensus::ConsensusHeader<RaftMsgType>(
        RaftMsgType::bft_Status, from_node),
      view(view_),
      last_good_version(last_good_version_)
    {}

    kv::Consensus::View view;
    kv::Version last_good_version;
  };
#pragma pack(pop)

  class StatusMessage : public IMessage
  {
  public:
    StatusMessage(kv::Consensus::View view_, kv::Version last_good_version_) :
      view(view_),
      last_good_version(last_good_version_)
    {}

    bool should_encrypt() const override
    {
      return false;
    }

    void serialize_message(aft::NodeId from_node, uint8_t* data, size_t size) const override
    {
      StatusMessageRep rep(from_node, view, last_good_version);

      serialized::write(
        data, size, reinterpret_cast<uint8_t*>(&rep), sizeof(StatusMessageRep));
      CCF_ASSERT(size == 0, "allocated buffer is too large");
    }

    size_t size() const override
    {
      return sizeof(StatusMessageRep);
    }

  private:
    kv::Consensus::View view;
    kv::Version last_good_version;
  };

  class StatusMessageRecv
  {
  public:
    StatusMessageRecv(OArray&& oa_, kv::NodeId from_) :
      oa(std::move(oa_)),
      from(from_)
    {}

    kv::Consensus::View get_view()
    {
      return reinterpret_cast<const StatusMessageRep*>(oa.data())->view;
    }

    kv::Version get_version()
    {
      return reinterpret_cast<const StatusMessageRep*>(oa.data())
        ->last_good_version;
    }

  private:
    OArray oa;
    kv::NodeId from;
  };
}