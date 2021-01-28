// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "raft_types.h"

namespace aft
{
  class AbstractExecMsgStore
  {
  public:
    virtual void recv_append_entries(
      AppendEntries r, const uint8_t* data, size_t size) = 0;
    virtual void recv_append_entries_response(AppendEntriesResponse r) = 0;
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

  class AbstractExecMsg
  {
  public:
    virtual ~AbstractExecMsg() = default;
    virtual void execute() = 0;
  };

  class AppendEntryExecEntry : public AbstractExecMsg
  {
  public:
    AppendEntryExecEntry(
      AbstractExecMsgStore* store_,
      AppendEntries&& hdr_,
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
      store->recv_append_entries(hdr, data, size);
    }

  private:
    AbstractExecMsgStore* store;
    AppendEntries hdr;
    const uint8_t* data;
    size_t size;
    OArray oarray;
  };

  class AppendEntryResponseExecEntry : public AbstractExecMsg
  {
  public:
    AppendEntryResponseExecEntry(
      AbstractExecMsgStore* store_, AppendEntriesResponse&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store->recv_append_entries_response(hdr);
    }

  private:
    AbstractExecMsgStore* store;
    AppendEntriesResponse hdr;
  };

  class SignedAppendEntryResponseExecEntry : public AbstractExecMsg
  {
  public:
    SignedAppendEntryResponseExecEntry(
      AbstractExecMsgStore* store_, SignedAppendEntriesResponse&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store->recv_append_entries_signed_response(hdr);
    }

  private:
    AbstractExecMsgStore* store;
    SignedAppendEntriesResponse hdr;
  };

  class RequestVoteExecEntry : public AbstractExecMsg
  {
  public:
    RequestVoteExecEntry(AbstractExecMsgStore* store_, RequestVote&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store->recv_request_vote(hdr);
    }

  private:
    AbstractExecMsgStore* store;
    RequestVote hdr;
  };

  class RequestVoteResponseExecEntry : public AbstractExecMsg
  {
  public:
    RequestVoteResponseExecEntry(
      AbstractExecMsgStore* store_, RequestVoteResponse&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store->recv_request_vote_response(hdr);
    }

  private:
    AbstractExecMsgStore* store;
    RequestVoteResponse hdr;
  };

  class SignatureAckExecEntry : public AbstractExecMsg
  {
  public:
    SignatureAckExecEntry(
      AbstractExecMsgStore* store_, SignaturesReceivedAck&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store->recv_signature_received_ack(hdr);
    }

  private:
    AbstractExecMsgStore* store;
    SignaturesReceivedAck hdr;
  };

  class NonceRevealExecEntry : public AbstractExecMsg
  {
  public:
    NonceRevealExecEntry(AbstractExecMsgStore* store_, NonceRevealMsg&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store->recv_nonce_reveal(hdr);
    }

  private:
    AbstractExecMsgStore* store;
    NonceRevealMsg hdr;
  };

  class ViewChangeExecEntry : public AbstractExecMsg
  {
  public:
    ViewChangeExecEntry(
      AbstractExecMsgStore* store_,
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
      store->recv_view_change(hdr, data, size);
    }

  private:
    AbstractExecMsgStore* store;
    RequestViewChangeMsg hdr;
    const uint8_t* data;
    size_t size;
    OArray oarray;
  };

  class ViewChangeEvidenceExecEntry : public AbstractExecMsg
  {
  public:
    ViewChangeEvidenceExecEntry(
      AbstractExecMsgStore* store_,
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
      store->recv_view_change_evidence(hdr, data, size);
    }

  private:
    AbstractExecMsgStore* store;
    ViewChangeEvidenceMsg hdr;
    const uint8_t* data;
    size_t size;
    OArray oarray;
  };
}
