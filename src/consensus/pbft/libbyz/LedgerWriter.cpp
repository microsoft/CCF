// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "LedgerWriter.h"

#include "Request.h"

LedgerWriter::LedgerWriter(
  pbft::Store& store_, pbft::PrePreparesMap& pbft_pre_prepares_map_) :
  store(store_),
  pbft_pre_prepares_map(pbft_pre_prepares_map_)
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
}

void LedgerWriter::write_pre_prepare(Pre_prepare* pp)
{
  store.commit_pre_prepare(
    {pp->seqno(),
     pp->num_big_reqs(),
     pp->get_digest_sig(),
     {(const uint8_t*)pp->contents(),
      (const uint8_t*)pp->contents() + pp->size()}},
    pbft_pre_prepares_map);
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
}