// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "raft_types.h"

namespace aft
{
  class AbstractConsensusCallback
  {
  public:
    virtual void recv_append_entries(
      const kv::NodeId& from,
      AppendEntries r,
      const uint8_t* data,
      size_t size) = 0;
    virtual void recv_append_entries_response(
      const kv::NodeId& from, AppendEntriesResponse r) = 0;
    virtual void recv_append_entries_signed_response(
      const kv::NodeId& from, SignedAppendEntriesResponse r) = 0;
    virtual void recv_request_vote(const kv::NodeId& from, RequestVote r) = 0;
    virtual void recv_request_vote_response(
      const kv::NodeId& from, RequestVoteResponse r) = 0;
    virtual void recv_signature_received_ack(
      const kv::NodeId& from, SignaturesReceivedAck r) = 0;
    virtual void recv_nonce_reveal(
      const kv::NodeId& from, NonceRevealMsg r) = 0;
    virtual void recv_view_change(
      const kv::NodeId& from,
      RequestViewChangeMsg r,
      const uint8_t* data,
      size_t size) = 0;
    virtual void recv_view_change_evidence(
      const kv::NodeId& from,
      ViewChangeEvidenceMsg r,
      const uint8_t* data,
      size_t size) = 0;
  };

  class AbstractMsgCallback
  {
  public:
    virtual ~AbstractMsgCallback() = default;
    virtual void execute() = 0;
  };

  class AppendEntryCallback : public AbstractMsgCallback
  {
  public:
    AppendEntryCallback(
      AbstractConsensusCallback& store_,
      kv::NodeId from_,
      AppendEntries&& hdr_,
      const uint8_t* data_,
      size_t size_,
      OArray&& oarray_) :
      store(store_),
      from(from_),
      hdr(std::move(hdr_)),
      data(data_),
      size(size_),
      oarray(std::move(oarray_))
    {}

    void execute() override
    {
      store.recv_append_entries(from, hdr, data, size);
    }

  private:
    AbstractConsensusCallback& store;
    kv::NodeId from;
    AppendEntries hdr;
    const uint8_t* data;
    size_t size;
    OArray oarray;
  };

  class AppendEntryResponseCallback : public AbstractMsgCallback
  {
  public:
    AppendEntryResponseCallback(
      AbstractConsensusCallback& store_,
      kv::NodeId from_,
      AppendEntriesResponse&& hdr_) :
      store(store_),
      from(from_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store.recv_append_entries_response(from, hdr);
    }

  private:
    AbstractConsensusCallback& store;
    kv::NodeId from;
    AppendEntriesResponse hdr;
  };

  class SignedAppendEntryResponseCallback : public AbstractMsgCallback
  {
  public:
    SignedAppendEntryResponseCallback(
      AbstractConsensusCallback& store_,
      kv::NodeId from_,
      SignedAppendEntriesResponse&& hdr_) :
      store(store_),
      from(from_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store.recv_append_entries_signed_response(from, hdr);
    }

  private:
    AbstractConsensusCallback& store;
    kv::NodeId from;
    SignedAppendEntriesResponse hdr;
  };

  class RequestVoteCallback : public AbstractMsgCallback
  {
  public:
    RequestVoteCallback(
      AbstractConsensusCallback& store_, kv::NodeId from_, RequestVote&& hdr_) :
      store(store_),
      from(from_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store.recv_request_vote(from, hdr);
    }

  private:
    AbstractConsensusCallback& store;
    kv::NodeId from;
    RequestVote hdr;
  };

  class RequestVoteResponseCallback : public AbstractMsgCallback
  {
  public:
    RequestVoteResponseCallback(
      AbstractConsensusCallback& store_,
      kv::NodeId from_,
      RequestVoteResponse&& hdr_) :
      store(store_),
      from(from_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store.recv_request_vote_response(from, hdr);
    }

  private:
    AbstractConsensusCallback& store;
    kv::NodeId from;
    RequestVoteResponse hdr;
  };

  class SignatureAckCallback : public AbstractMsgCallback
  {
  public:
    SignatureAckCallback(
      AbstractConsensusCallback& store_,
      kv::NodeId from_,
      SignaturesReceivedAck&& hdr_) :
      store(store_),
      from(from_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store.recv_signature_received_ack(from, hdr);
    }

  private:
    AbstractConsensusCallback& store;
    kv::NodeId from;
    SignaturesReceivedAck hdr;
  };

  class NonceRevealCallback : public AbstractMsgCallback
  {
  public:
    NonceRevealCallback(
      AbstractConsensusCallback& store_,
      kv::NodeId from_,
      NonceRevealMsg&& hdr_) :
      store(store_),
      from(from_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store.recv_nonce_reveal(from, hdr);
    }

  private:
    AbstractConsensusCallback& store;
    kv::NodeId from;
    NonceRevealMsg hdr;
  };

  class ViewChangeCallback : public AbstractMsgCallback
  {
  public:
    ViewChangeCallback(
      AbstractConsensusCallback& store_,
      kv::NodeId from_,
      RequestViewChangeMsg&& hdr_,
      const uint8_t* data_,
      size_t size_,
      OArray&& oarray_) :
      store(store_),
      from(from_),
      hdr(std::move(hdr_)),
      data(data_),
      size(size_),
      oarray(std::move(oarray_))
    {}

    void execute() override
    {
      store.recv_view_change(from, hdr, data, size);
    }

  private:
    AbstractConsensusCallback& store;
    kv::NodeId from;
    RequestViewChangeMsg hdr;
    const uint8_t* data;
    size_t size;
    OArray oarray;
  };

  class ViewChangeEvidenceCallback : public AbstractMsgCallback
  {
  public:
    ViewChangeEvidenceCallback(
      AbstractConsensusCallback& store_,
      kv::NodeId from_,
      ViewChangeEvidenceMsg&& hdr_,
      const uint8_t* data_,
      size_t size_,
      OArray&& oarray_) :
      store(store_),
      from(from_),
      hdr(std::move(hdr_)),
      data(data_),
      size(size_),
      oarray(std::move(oarray_))
    {}

    void execute() override
    {
      store.recv_view_change_evidence(from, hdr, data, size);
    }

  private:
    AbstractConsensusCallback& store;
    kv::NodeId from;
    ViewChangeEvidenceMsg hdr;
    const uint8_t* data;
    size_t size;
    OArray oarray;
  };
}
