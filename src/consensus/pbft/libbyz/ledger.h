// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include "digest.h"
#include "types.h"

enum class Ledger_header_type : uint32_t
{
  Pre_prepare_ledger_header = 0,
  Pre_prepare_ledger_large_message_header = 1,
  Prepare_ledger_header = 2,
  View_change_header = 3
};

#pragma pack(push, 1)
struct Pre_prepare_ledger_header
{
  Pre_prepare_ledger_header() = default;

  Pre_prepare_ledger_header(
    uint64_t sequence_num_,
    size_t message_size_,
    uint16_t num_big_requests_
#ifdef SIGN_BATCH
    ,
    PbftSignature digest_sig
#endif
    ) :
    type(Ledger_header_type::Pre_prepare_ledger_header),
    sequence_num(sequence_num_),
    message_size(message_size_),
    num_big_requests(num_big_requests_)
  {}

  Ledger_header_type type;
  uint64_t sequence_num;
  size_t message_size;
  uint16_t num_big_requests;
#ifdef SIGN_BATCH
  PbftSignature digest_sig;
#endif
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Pre_prepare_ledger_large_message_header
{
  Pre_prepare_ledger_large_message_header() = default;

  Pre_prepare_ledger_large_message_header(size_t message_size_) :
    type(Ledger_header_type::Pre_prepare_ledger_large_message_header),
    message_size(message_size_)
  {}

  Ledger_header_type type;
  size_t message_size;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Prepare_ledger_header
{
  Prepare_ledger_header() = default;

  Prepare_ledger_header(Seqno sequence_num_, uint16_t num_prepare_signatures_) :
    type(Ledger_header_type::Prepare_ledger_header),
    sequence_num(sequence_num_),
    num_prepare_signatures(num_prepare_signatures_)
  {}

  Ledger_header_type type;
  Seqno sequence_num;
  uint16_t num_prepare_signatures;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct View_change_ledger_header
{
  View_change_ledger_header() = default;

  View_change_ledger_header(
    int id_,
    Seqno sequence_num_,
    View new_view_

#ifdef SIGN_BATCH
    ,
    Digest digest_,
    PbftSignature digest_sig_
#endif
    ) :
    type(Ledger_header_type::View_change_header),
    id(id_),
    sequence_num(sequence_num_),
    new_view(new_view_)

#ifdef SIGN_BATCH
    ,
    digest(digest_),
    digest_sig(digest_sig_)
#endif
  {}

  Ledger_header_type type;
  int id;
  Seqno sequence_num;
  View new_view;

#ifdef SIGN_BATCH
  Digest digest;
  PbftSignature digest_sig;
#endif
};
#pragma pack(pop)
