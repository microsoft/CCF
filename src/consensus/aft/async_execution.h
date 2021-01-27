// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "raft_types.h"

namespace aft
{
  class AbstractExecEntryStore
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
    virtual void recv_view_change(RequestViewChangeMsg r, const uint8_t* data, size_t size) = 0;
    virtual void recv_view_change_evidence(ViewChangeEvidenceMsg r, const uint8_t* data, size_t size) = 0;
  };

  class AbstractExecEntry
  {
  public:
    virtual ~AbstractExecEntry() = default;
    virtual void execute() = 0;
  };

  class AppendEntryExecEntry : public AbstractExecEntry
  {
  public:
    AppendEntryExecEntry(
      AbstractExecEntryStore* store_,
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
    AbstractExecEntryStore* store;
    AppendEntries hdr;
    const uint8_t* data;
    size_t size;
    OArray oarray;
  };

  class AppendEntryResponseExecEntry : public AbstractExecEntry
  {
  public:
    AppendEntryResponseExecEntry(
      AbstractExecEntryStore* store_,
      AppendEntriesResponse&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store->recv_append_entries_response(hdr);
    }

  private:
    AbstractExecEntryStore* store;
    AppendEntriesResponse hdr;
  };

  class SignedAppendEntryResponseExecEntry : public AbstractExecEntry
  {
  public:
    SignedAppendEntryResponseExecEntry(
      AbstractExecEntryStore* store_,
      SignedAppendEntriesResponse&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store->recv_append_entries_signed_response(hdr);
    }

  private:
    AbstractExecEntryStore* store;
    SignedAppendEntriesResponse hdr;
  };

  class RequestVoteExecEntry : public AbstractExecEntry
  {
  public:
    RequestVoteExecEntry(
      AbstractExecEntryStore* store_,
      RequestVote&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store->recv_request_vote(hdr);
    }

  private:
    AbstractExecEntryStore* store;
    RequestVote hdr;
  };

  class RequestVoteResponseExecEntry : public AbstractExecEntry
  {
  public:
    RequestVoteResponseExecEntry(
      AbstractExecEntryStore* store_,
      RequestVoteResponse&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store->recv_request_vote_response(hdr);
    }

  private:
    AbstractExecEntryStore* store;
    RequestVoteResponse hdr;
  };

  class SignatureAckExecEntry : public AbstractExecEntry
  {
  public:
    SignatureAckExecEntry(
      AbstractExecEntryStore* store_,
      SignaturesReceivedAck && hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store->recv_signature_received_ack(hdr);
    }

  private:
    AbstractExecEntryStore* store;
    SignaturesReceivedAck hdr;
  };

  class NonceRevealExecEntry : public AbstractExecEntry
  {
  public:
    NonceRevealExecEntry(
      AbstractExecEntryStore* store_,
      NonceRevealMsg&& hdr_) :
      store(store_),
      hdr(std::move(hdr_))
    {}

    void execute() override
    {
      store->recv_nonce_reveal(hdr);
    }

  private:
    AbstractExecEntryStore* store;
    NonceRevealMsg hdr;
  };

  class ViewChangeExecEntry : public AbstractExecEntry
  {
  public:
    ViewChangeExecEntry(
      AbstractExecEntryStore* store_,
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
    AbstractExecEntryStore* store;
    RequestViewChangeMsg hdr;
    const uint8_t* data;
    size_t size;
    OArray oarray;
  };

  class ViewChangeEvidenceExecEntry : public AbstractExecEntry
  {
  public:
    ViewChangeEvidenceExecEntry(
      AbstractExecEntryStore* store_,
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
    AbstractExecEntryStore* store;
    ViewChangeEvidenceMsg hdr;
    const uint8_t* data;
    size_t size;
    OArray oarray;
  };
}
