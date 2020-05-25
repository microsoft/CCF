// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include "consensus/pbft/pbft_new_views.h"
#include "consensus/pbft/pbft_pre_prepares.h"
#include "consensus/pbft/pbft_requests.h"
#include "consensus/pbft/pbft_types.h"
#include "kv/kv_types.h"
#include "ledger.h"
#include "new_view.h"
#include "node/signatures.h"
#include "prepared_cert.h"
#include "types.h"

class LedgerWriter
{
private:
  pbft::PbftStore& store;
  pbft::PrePreparesMap& pbft_pre_prepares_map;
  ccf::Signatures& signatures;
  pbft::NewViewsMap& pbft_new_views_map;

public:
  LedgerWriter(
    pbft::PbftStore& store_,
    pbft::PrePreparesMap& pbft_pre_prepares_map_,
    ccf::Signatures& signatures_,
    pbft::NewViewsMap& pbft_new_views_map_);
  virtual ~LedgerWriter() = default;
  kv::Version write_pre_prepare(Pre_prepare* pp);
  kv::Version write_pre_prepare(Pre_prepare* pp, View view);
  kv::Version write_pre_prepare(kv::Tx& tx, Pre_prepare* pp);
  void write_new_view(New_view* nv);
};
