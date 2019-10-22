// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "LedgerWriter.h"

#include "Request.h"

LedgerWriter::LedgerWriter(std::unique_ptr<consensus::LedgerEnclave> ledger_) :
  ledger(std::move(ledger_))
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

  std::vector<uint8_t> entry(entry_size);
  auto data = entry.data();

  serialized::write(data, entry_size, (uint8_t*)&header, sizeof(header));

  for (const auto& p : proof)
  {
    serialized::write(
      data,
      entry_size,
      (uint8_t*)&(p.second),
      sizeof(Prepared_cert::PrePrepareProof));
  }

  ledger->put_entry(entry);
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

  // big requests total size
  Pre_prepare::Requests_iter iter(pp);
  Request request;
  bool is_request_present;
  size_t brq_total_size = 0;
  while (iter.get_big_request(request, is_request_present))
  {
    if (is_request_present)
    {
      brq_total_size += request.size();
    }
  }

  // entry size for pre-prepare including its big requests
  size_t entry_size = sizeof(Pre_prepare_ledger_header) + pp->size() +
    (pp->num_big_reqs() * sizeof(Pre_prepare_ledger_large_message_header)) +
    brq_total_size;

  std::vector<uint8_t> entry(entry_size);
  auto data = entry.data();

  // TODO: This needs to be encrypted
  serialized::write(data, entry_size, (uint8_t*)&header, sizeof(header));
  serialized::write(
    data, entry_size, (const uint8_t*)pp->contents(), pp->size());

  if (pp->num_big_reqs() > 0)
  {
    Pre_prepare::Requests_iter iter(pp);
    Request request;
    bool is_request_present;

    while (iter.get_big_request(request, is_request_present))
    {
      if (is_request_present)
      {
        // TODO: This needs to be encrypted
        Pre_prepare_ledger_large_message_header header(request.size());

        serialized::write(data, entry_size, (uint8_t*)&header, sizeof(header));
        serialized::write(
          data, entry_size, (uint8_t*)request.contents(), request.size());
      }
      else
      {
        Pre_prepare_ledger_large_message_header header(0);
        serialized::write(data, entry_size, (uint8_t*)&header, sizeof(header));
      }
    }
  }
  ledger->put_entry(entry);
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

  std::vector<uint8_t> entry(sizeof(View_change_ledger_header));
  uint8_t* tdata = entry.data();
  auto size = sizeof(View_change_ledger_header);
  serialized::write(tdata, size, (uint8_t*)&header, size);
  ledger->put_entry(entry);
}

std::pair<std::vector<uint8_t>, bool> LedgerWriter::record_entry(
  const uint8_t*& data, size_t& size)
{
  return ledger->record_entry(data, size);
}

void LedgerWriter::truncate(Seqno seqno)
{
  ledger->truncate(seqno);
}