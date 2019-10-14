// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "LedgerWriter.h"

#include "Request.h"

LedgerWriter::LedgerWriter(
  append_ledger_entry_cb ledger_entry_cb_, void* ledger_cb_ctx_) :
  ledger_entry_cb(ledger_entry_cb_),
  ledger_cb_ctx(ledger_cb_ctx_)
{}

void LedgerWriter::write_prepare(
  const Prepared_cert& prepared_cert, Seqno seqno)
{
  const auto& proof = prepared_cert.get_pre_prepared_cert_proof();
  Prepare_ledger_header header(seqno, static_cast<uint16_t>(proof.size()));
  size_t entry_size = sizeof(Prepare_ledger_header);

  static_assert(
    sizeof(Prepared_cert::PrePrepareProof) ==
      (sizeof(Prepared_cert::PrePrepareProof::public_key) +
       sizeof(Prepared_cert::PrePrepareProof::signature)),
    "The size of Prepared_cert::PrePrepareProof is wrong");
  static_assert(
    std::is_pod<Prepared_cert::PrePrepareProof>::value,
    "Prepared_cert::PreprepareProof is not a pod");
  static_assert(
    std::is_trivial<Prepared_cert::PrePrepareProof>::value,
    "Prepared_cert::PrePrepareProof is not a trivial");

  entry_size += sizeof(Prepared_cert::PrePrepareProof) * proof.size();

  // write total entry size
  ledger_entry_cb((const uint8_t*)&entry_size, sizeof(size_t), ledger_cb_ctx);

  // now write the actual entry
  ledger_entry_cb((const uint8_t*)&header, sizeof(header), ledger_cb_ctx);

  for (const auto& p : proof)
  {
    ledger_entry_cb(
      (const uint8_t*)&(p.second),
      sizeof(Prepared_cert::PrePrepareProof),
      ledger_cb_ctx);
  }
}

void LedgerWriter::write_pre_prepare(Pre_prepare* pp)
{
  Pre_prepare_ledger_header header(
    pp->seqno(),
    pp->size(),
    pp->num_big_reqs()
#ifdef SIGN_BATCH
      ,
    pp->get_digest_sig()
#endif
  );

  size_t entry_size = sizeof(Pre_prepare_ledger_header) + pp->size();
  // write total entry size
  ledger_entry_cb((const uint8_t*)&entry_size, sizeof(size_t), ledger_cb_ctx);
  // write the actual entry
  // TODO: This needs to be encrypted
  ledger_entry_cb(
    (uint8_t*)&header, sizeof(Pre_prepare_ledger_header), ledger_cb_ctx);
  ledger_entry_cb((const uint8_t*)pp->contents(), pp->size(), ledger_cb_ctx);
  if (pp->num_big_reqs() > 0)
  {
    Pre_prepare::Requests_iter iter(pp);
    Request request;
    bool is_request_present;

    while (iter.get_big_request(request, is_request_present))
    {
      entry_size = sizeof(Pre_prepare_ledger_large_message_header);
      if (is_request_present)
      {
        // TODO: This needs to be encrypted
        Pre_prepare_ledger_large_message_header header(request.size());

        entry_size += request.size();

        // write total entry size
        ledger_entry_cb(
          (const uint8_t*)&entry_size, sizeof(size_t), ledger_cb_ctx);
        // write the actual entry
        ledger_entry_cb(
          (uint8_t*)&header,
          sizeof(Pre_prepare_ledger_large_message_header),
          ledger_cb_ctx);

        ledger_entry_cb(
          (uint8_t*)request.contents(), request.size(), ledger_cb_ctx);
      }
      else
      {
        // write total entry size
        ledger_entry_cb(
          (const uint8_t*)&entry_size, sizeof(size_t), ledger_cb_ctx);
        Pre_prepare_ledger_large_message_header header(0);
        ledger_entry_cb(
          (uint8_t*)&header,
          sizeof(Pre_prepare_ledger_large_message_header),
          ledger_cb_ctx);

        ledger_entry_cb(nullptr, 0, ledger_cb_ctx);
      }
    }
  }
}

void LedgerWriter::write_view_change(View_change* vc)
{
  View_change_ledger_header header(
    vc->id(),
    vc->max_seqno(),
    vc->view()
#ifdef SIGN_BATCH
      ,
    vc->digest(),
    vc->signature()
#endif
  );

  size_t entry_size = sizeof(View_change_ledger_header);
  // write total entry size
  ledger_entry_cb((const uint8_t*)&entry_size, sizeof(size_t), ledger_cb_ctx);
  // write actual entry
  ledger_entry_cb(
    (uint8_t*)&header, sizeof(View_change_ledger_header), ledger_cb_ctx);
}