// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "apply_changes.h"
#include "kv/committable_tx.h"
#include "kv_types.h"
#include "service/tables/shares.h"
#include "service/tables/signatures.h"
#include "service/tables/snapshot_evidence.h"

#include <vector>

namespace ccf::kv
{
  class ExecutionWrapperStore
  {
  public:
    virtual bool fill_maps(
      const std::vector<uint8_t>& data,
      bool public_only,
      ccf::kv::Version& v,
      ccf::kv::Term& view,
      ccf::kv::OrderedChanges& changes,
      ccf::kv::MapCollection& new_maps,
      ccf::ClaimsDigest& claims_digest,
      std::optional<ccf::crypto::Sha256Hash>& commit_evidence_digest,
      bool ignore_strict_versions = false) = 0;

    virtual bool commit_deserialised(
      ccf::kv::OrderedChanges& changes,
      ccf::kv::Version v,
      ccf::kv::Term term,
      const MapCollection& new_maps,
      ccf::kv::ConsensusHookPtrs& hooks,
      bool track_deletes_on_missing_keys) = 0;
  };

  class CFTExecutionWrapper : public AbstractExecutionWrapper
  {
  private:
    ExecutionWrapperStore* store;
    std::shared_ptr<TxHistory> history;
    const std::vector<uint8_t> data;
    bool public_only;
    ccf::kv::Version version;
    Term term;
    OrderedChanges changes;
    MapCollection new_maps;
    ccf::kv::ConsensusHookPtrs hooks;
    ccf::ClaimsDigest claims_digest;
    std::optional<ccf::crypto::Sha256Hash> commit_evidence_digest = {};

    const std::optional<TxID> expected_txid;

  public:
    CFTExecutionWrapper(
      ExecutionWrapperStore* store_,
      std::shared_ptr<TxHistory> history_,
      const std::vector<uint8_t>& data_,
      bool public_only_,
      const std::optional<TxID>& expected_txid_) :
      store(store_),
      history(history_),
      data(data_),
      public_only(public_only_),
      expected_txid(expected_txid_)
    {}

    ccf::ClaimsDigest&& consume_claims_digest() override
    {
      return std::move(claims_digest);
    }

    std::optional<ccf::crypto::Sha256Hash>&& consume_commit_evidence_digest()
      override
    {
      return std::move(commit_evidence_digest);
    }

    ApplyResult apply(bool track_deletes_on_missing_keys) override
    {
      if (!store->fill_maps(
            data,
            public_only,
            version,
            term,
            changes,
            new_maps,
            claims_digest,
            commit_evidence_digest,
            true))
      {
        return ApplyResult::FAIL;
      }

      if (expected_txid.has_value())
      {
        if (term != expected_txid->term || version != expected_txid->version)
        {
          LOG_FAIL_FMT(
            "TxID mismatch during deserialisation. Expected {}.{}, got {}.{}",
            expected_txid->term,
            expected_txid->version,
            term,
            version);
          return ApplyResult::FAIL;
        }
      }

      if (!store->commit_deserialised(
            changes,
            version,
            term,
            new_maps,
            hooks,
            track_deletes_on_missing_keys))
      {
        return ApplyResult::FAIL;
      }
      auto success = ApplyResult::PASS;

      auto search = changes.find(ccf::Tables::SIGNATURES);
      if (search != changes.end())
      {
        bool has_cose = false;

        switch (changes.size())
        {
          case 2:
            if (
              changes.find(ccf::Tables::SERIALISED_MERKLE_TREE) !=
              changes.end())
            {
              break;
            }
          case 3:
            if (
              changes.find(ccf::Tables::SERIALISED_MERKLE_TREE) !=
                changes.end() &&
              changes.find(ccf::Tables::COSE_SIGNATURES) != changes.end())
            {
              has_cose = true;
              break;
            }
          default:
            LOG_DEBUG_FMT(
              "Unexpected contents in signature transaction {}", version);
            return ApplyResult::FAIL;
        }

        if (history)
        {
          if (!history->verify_root_signatures(has_cose))
          {
            LOG_FAIL_FMT("Failed to deserialise");
            LOG_DEBUG_FMT(
              "Signature in transaction {} failed to verify", version);
            return ApplyResult::FAIL;
          }
        }
        success = ApplyResult::PASS_SIGNATURE;
      }

      search = changes.find(ccf::Tables::ENCRYPTED_PAST_LEDGER_SECRET);
      if (search != changes.end())
      {
        success = ApplyResult::PASS_ENCRYPTED_PAST_LEDGER_SECRET;
      }

      if (history)
      {
        history->append_entry(
          ccf::entry_leaf(data, commit_evidence_digest, claims_digest));
      }
      return success;
    }

    ccf::kv::ConsensusHookPtrs& get_hooks() override
    {
      return hooks;
    }

    const std::vector<uint8_t>& get_entry() override
    {
      return data;
    }

    Term get_term() override
    {
      return term;
    }

    ccf::kv::Version get_index() override
    {
      return version;
    }

    bool support_async_execution() override
    {
      return false;
    }

    bool is_public_only() override
    {
      return public_only;
    }

    bool should_rollback_to_last_committed() override
    {
      return false;
    }
  };
}