// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "ledger_writer.h"

#include "request.h"

LedgerWriter::LedgerWriter(
  pbft::PbftStore& store_,
  pbft::PrePreparesMap& pbft_pre_prepares_map_,
  ccf::Signatures& signatures_,
  pbft::ViewChangesMap& pbft_view_changes_map_) :
  store(store_),
  pbft_pre_prepares_map(pbft_pre_prepares_map_),
  signatures(signatures_),
  pbft_view_changes_map(pbft_view_changes_map_)
{}

kv::Version LedgerWriter::write_pre_prepare(ccf::Store::Tx& tx, Pre_prepare* pp)
{
  return store.commit_tx(
    tx,
    {pp->get_replicated_state_merkle_root().data(),
     pp->get_replicated_state_merkle_root().size()},
    signatures);
}

kv::Version LedgerWriter::write_pre_prepare(Pre_prepare* pp, View view)
{
  auto stashed_view = pp->view();
  pp->set_view(view);
  auto v = write_pre_prepare(pp);
  pp->set_view(stashed_view);
  return v;
}

kv::Version LedgerWriter::write_pre_prepare(Pre_prepare* pp)
{
  LOG_TRACE_FMT(
    "Writing pre prepare with seqno {}, num big reqs {}, view {}",
    pp->seqno(),
    pp->num_big_reqs(),
    pp->view());

  return store.commit_pre_prepare(
    {pp->seqno(),
     pp->num_big_reqs(),
     pp->get_digest_sig(),
     {(const uint8_t*)pp->contents(),
      (const uint8_t*)pp->contents() + pp->size()}},
    pbft_pre_prepares_map,
    {pp->get_replicated_state_merkle_root().data(),
     pp->get_replicated_state_merkle_root().size()},
    signatures);
}

void LedgerWriter::write_view_change(View_change* vc)
{
  LOG_TRACE_FMT(
    "Writing view change with view {} for node {}", vc->view(), vc->id());
  store.commit_view_change(
    {vc->view(),
     vc->id(),
     {(const uint8_t*)vc->contents(),
      (const uint8_t*)vc->contents() + vc->size()}},
    pbft_view_changes_map);
}