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
      kv::NodeId from, AppendEntries r, const uint8_t* data, size_t size) = 0;
    virtual void recv_append_entries_response(
      kv::NodeId from, AppendEntriesResponse r) = 0;
    virtual void recv_append_entries_signed_response(
      SignedAppendEntriesResponse r) = 0;
    virtual void recv_request_vote(RequestVote r) = 0;
    virtual void recv_request_vote_response(RequestVoteResponse r) = 0;
    virtual void recv_signature_received_ack(SignaturesReceivedAck r) = 0;
    virtual void recv_nonce_reveal(NonceRevealMsg r) = 0;
    virtual void recv_view_change(
      RequestViewChangeMsg r, const uint8_t* data, size_t size) = 0;
    virtual void recv_view_change_evidence(
      ViewChangeEvidenceMsg r, const uint8_t* data, size_t size) = 0;
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
      AbstractConsensusCallback& store_, SignedAppendEntriesResponse&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store.recv_append_entries_signed_response(hdr);
    }

  private:
    AbstractConsensusCallback& store;
    SignedAppendEntriesResponse hdr;
  };

  class RequestVoteCallback : public AbstractMsgCallback
  {
  public:
    RequestVoteCallback(AbstractConsensusCallback& store_, RequestVote&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store.recv_request_vote(hdr);
    }

  private:
    AbstractConsensusCallback& store;
    RequestVote hdr;
  };

  class RequestVoteResponseCallback : public AbstractMsgCallback
  {
  public:
    RequestVoteResponseCallback(
      AbstractConsensusCallback& store_, RequestVoteResponse&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store.recv_request_vote_response(hdr);
    }

  private:
    AbstractConsensusCallback& store;
    RequestVoteResponse hdr;
  };

  class SignatureAckCallback : public AbstractMsgCallback
  {
  public:
    SignatureAckCallback(
      AbstractConsensusCallback& store_, SignaturesReceivedAck&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store.recv_signature_received_ack(hdr);
    }

  private:
    AbstractConsensusCallback& store;
    SignaturesReceivedAck hdr;
  };

  class NonceRevealCallback : public AbstractMsgCallback
  {
  public:
    NonceRevealCallback(
      AbstractConsensusCallback& store_, NonceRevealMsg&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store.recv_nonce_reveal(hdr);
    }

  private:
    AbstractConsensusCallback& store;
    NonceRevealMsg hdr;
  };

  class ViewChangeCallback : public AbstractMsgCallback
  {
  public:
    ViewChangeCallback(
      AbstractConsensusCallback& store_,
      RequestViewChangeMsg&& hdr_,
      const uint8_t* data_,
      size_t size_,
      OArray&& oarray_) :
      store(store_),
      hdr(std::move(hdr_)),
      data(data_),
      size(size_),
      oarray(std::move(oarray_))
    {}

    void execute() override
    {
      store.recv_view_change(hdr, data, size);
    }

  private:
    AbstractConsensusCallback& store;
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
      ViewChangeEvidenceMsg&& hdr_,
      const uint8_t* data_,
      size_t size_,
      OArray&& oarray_) :
      store(store_),
      hdr(std::move(hdr_)),
      data(data_),
      size(size_),
      oarray(std::move(oarray_))
    {}

    void execute() override
    {
      store.recv_view_change_evidence(hdr, data, size);
    }

  private:
    AbstractConsensusCallback& store;
    ViewChangeEvidenceMsg hdr;
    const uint8_t* data;
    size_t size;
    OArray oarray;
  };
}
