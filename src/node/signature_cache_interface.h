// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"
#include "ccf/tx_id.h"
#include "service/tables/signatures.h"

#include <optional>
#include <vector>

namespace ccf
{
  struct CachedSignature
  {
    PrimarySignature sig;
    std::vector<uint8_t> cose_signature;
    std::vector<uint8_t> serialised_tree;
    ccf::SeqNo sig_seqno;
    std::string commit_evidence;
  };

  class SignatureCacheInterface : public AbstractNodeSubSystem
  {
  public:
    ~SignatureCacheInterface() override = default;

    static char const* get_subsystem_name()
    {
      return "SignatureCache";
    }

    // Returns the covering signature for a given TxID, or nullopt if
    // unavailable. When a value is returned, all fields are populated,
    // including commit_evidence for the requested transaction.
    virtual std::optional<CachedSignature> get_signature_for(
      const ccf::TxID& tx_id) const = 0;

    virtual void set_max_cache_size(size_t n) = 0;
  };
}
