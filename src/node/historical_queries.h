// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "kv/store.h"
#include "ds/ccf_assert.h"
#include "ds/spin_lock.h"
#include "node/encryptor.h"
#include "node/historical_queries_interface.h"
#include "node/history.h"
#include "node/ledger_secrets.h"
#include "node/rpc/node_interface.h"

#include <list>
#include <map>
#include <memory>
#include <set>

namespace ccf::historical
{
  static std::optional<ccf::PrimarySignature> get_signature(
    const StorePtr& sig_store)
  {
    auto tx = sig_store->create_tx();
    auto signatures = tx.ro<ccf::Signatures>(ccf::Tables::SIGNATURES);
    return signatures->get(0);
  }

  class StateCache : public AbstractStateCache
  {
  protected:
    kv::Store& source_store;
    std::shared_ptr<ccf::LedgerSecrets> source_ledger_secrets;
    ringbuffer::WriterPtr to_host;

    std::shared_ptr<ccf::LedgerSecrets> historical_ledger_secrets;
    std::shared_ptr<ccf::NodeEncryptor> historical_encryptor;

    enum class RequestStage
    {
      RecoveringLedgerSecret,
      Fetching,
      Untrusted,
      Trusted,
    };

    using LedgerEntry = std::vector<uint8_t>;

    struct LedgerSecretRecoveryInfo
    {
      consensus::Index target_idx = 0;
      LedgerSecretPtr last_ledger_secret;

      LedgerSecretRecoveryInfo(
        consensus::Index target_idx_, LedgerSecretPtr last_ledger_secret_) :
        target_idx(target_idx_),
        last_ledger_secret(last_ledger_secret_)
      {}
    };

    ccf::VersionedLedgerSecret get_first_known_ledger_secret()
    {
      if (historical_ledger_secrets->is_empty())
      {
        return source_ledger_secrets->get_first();
      }

      auto tx = source_store.create_read_only_tx();
      CCF_ASSERT_FMT(
        historical_ledger_secrets->get_latest(tx).first <
          source_ledger_secrets->get_first().first,
        "Historical ledger secrets are not older than main ledger secrets");

      return historical_ledger_secrets->get_first();
    }

    struct StoreDetails
    {
      RequestStage current_stage = RequestStage::Fetching;
      crypto::Sha256Hash entry_digest = {};
      StorePtr store = nullptr;
      bool is_signature = false;
    };
    using StoreDetailsPtr = std::shared_ptr<StoreDetails>;

    struct Request
    {
      consensus::Index first_requested_index = 0;
      consensus::Index last_requested_index = 0;
      std::vector<StoreDetailsPtr> requested_stores;
      std::chrono::milliseconds time_to_expiry;

      // An entry from outside the requested range containing the next signature
      // may be needed to trust this range. It is stored here, distinct from
      // user-requested stores.
      std::optional<std::pair<consensus::Index, StoreDetailsPtr>>
        supporting_signature;

      // Only set when recovering ledger secrets
      std::unique_ptr<LedgerSecretRecoveryInfo> ledger_secret_recovery_info =
        nullptr;

      Request() {}

      StoreDetailsPtr get_store_details(consensus::Index idx) const
      {
        if (idx >= first_requested_index && idx <= last_requested_index)
        {
          const auto offset = idx - first_requested_index;
          if (offset < requested_stores.size())
          {
            return requested_stores[offset];
          }
        }

        if (
          supporting_signature.has_value() &&
          supporting_signature->first == idx)
        {
          return supporting_signature->second;
        }

        return nullptr;
      }

      // Keep as many existing entries as possible, return indices that weren't
      // already present to indicate they should be fetched. For example, if we
      // were previously fetching:
      //        2  3  4  5
      // and then we adjust to:
      //              4  5
      // we don't need to fetch anything new; this is a subrange, we just need
      // to shift where these are in our requested_stores vector. But if we
      // adjust to:
      //  0  1  2  3  4  5  6
      // we need to shift _and_ start fetching 0, 1, and 6.
      std::set<consensus::Index> adjust_range(
        consensus::Index start_idx, size_t num_following_indices)
      {
        if (
          start_idx == first_requested_index &&
          (num_following_indices + 1) == requested_stores.size())
        {
          // This is precisely the range we're already tracking - do nothing
          return {};
        }

        std::set<consensus::Index> ret;
        std::vector<StoreDetailsPtr> new_stores(num_following_indices + 1);
        for (auto idx = start_idx; idx <= start_idx + num_following_indices;
             ++idx)
        {
          auto existing_details = get_store_details(idx);
          if (existing_details == nullptr)
          {
            ret.insert(idx);
            new_stores[idx - start_idx] = std::make_shared<StoreDetails>();
          }
          else
          {
            new_stores[idx - start_idx] = std::move(existing_details);
          }
        }

        requested_stores = std::move(new_stores);
        first_requested_index = start_idx;
        last_requested_index = first_requested_index + num_following_indices;

        // If the final entry in the new range is known and not a signature,
        // then we may need a subsequent signature to support it (or an earlier
        // entry received out-of-order!) So start fetching subsequent entries to
        // find supporting signature. Its possible this was the supporting entry
        // we already had, or a signature in the range we already had, but
        // working that out is tricky so be pessimistic and refetch instead.
        supporting_signature.reset();
        const auto last_details = get_store_details(last_requested_index);
        if (last_details->store != nullptr && !last_details->is_signature)
        {
          const auto next_idx = last_requested_index + 1;
          supporting_signature =
            std::make_pair(next_idx, std::make_shared<StoreDetails>());
          ret.insert(next_idx);
        }

        return ret;
      }

      enum class UpdateTrustedResult
      {
        // Common result. The new index may have transitioned some entries to
        // Trusted
        Continue,

        // Occasional result. The new index was at the end of the sequence (or
        // an attempt at retrieving a trailing supporting signature), but we
        // still have untrusted entries, so attempt to fetch the next
        FetchNext,

        // Error result. The new entry exposed a mismatch between a signature's
        // claim at a certain index and the entry we received there. Invalidate
        // entire request, it can be re-requested if necessary
        Invalidated,
      };

      UpdateTrustedResult update_trusted(consensus::Index new_idx)
      {
        auto new_details = get_store_details(new_idx);
        if (new_details->is_signature)
        {
          // Iterate through earlier indices. If this signature covers them (and
          // the digests match), move them to Trusted
          const auto sig = get_signature(new_details->store);
          ccf::MerkleTreeHistory tree(sig->tree);

          for (auto idx = first_requested_index; idx < new_idx; ++idx)
          {
            if (tree.in_range(idx))
            {
              auto details = get_store_details(idx);
              if (details != nullptr)
              {
                if (details->current_stage == RequestStage::Untrusted)
                {
                  // Compare signed digest, from signature mini-tree, with
                  // digest of the entry which was used to construct this store
                  const auto& untrusted_digest = details->entry_digest;
                  const auto trusted_digest = tree.get_leaf(idx);
                  if (trusted_digest != untrusted_digest)
                  {
                    LOG_FAIL_FMT(
                      "Signature at {} has a different transaction at {} than "
                      "previously received",
                      new_idx,
                      idx);

                    // We trust the signature (since it comes from a trusted
                    // node), and it disagrees with one of the entries we
                    // previously retrieved and deserialised. This generally
                    // means a malicious host gave us a bad transaction but a
                    // good signature. Delete the entire original request
                    // - if it is re-requested, maybe the host will give us a
                    // valid pair of transaction+sig next time
                    return UpdateTrustedResult::Invalidated;
                  }

                  details->current_stage = RequestStage::Trusted;
                }
              }
            }
          }
        }
        else if (new_details->current_stage == RequestStage::Untrusted)
        {
          // Iterate through later indices, see if there's a signature that
          // covers this one
          const auto& untrusted_digest = new_details->entry_digest;
          bool sig_seen = false;
          for (auto idx = new_idx + 1; idx <= last_requested_index; ++idx)
          {
            auto details = get_store_details(idx);
            if (details != nullptr)
            {
              if (details->store != nullptr && details->is_signature)
              {
                const auto sig = get_signature(details->store);
                ccf::MerkleTreeHistory tree(sig->tree);
                if (tree.in_range(new_idx))
                {
                  const auto trusted_digest = tree.get_leaf(new_idx);
                  if (trusted_digest != untrusted_digest)
                  {
                    return UpdateTrustedResult::Invalidated;
                  }

                  new_details->current_stage = RequestStage::Trusted;
                }

                // Break here - if this signature doesn't cover us, no later one
                // can
                sig_seen = true;
                break;
              }
            }
          }

          if (!sig_seen && supporting_signature.has_value())
          {
            const auto& [idx, details] = *supporting_signature;
            if (details->store != nullptr && details->is_signature)
            {
              const auto sig = get_signature(details->store);
              ccf::MerkleTreeHistory tree(sig->tree);
              if (tree.in_range(new_idx))
              {
                const auto trusted_digest = tree.get_leaf(new_idx);
                if (trusted_digest != untrusted_digest)
                {
                  return UpdateTrustedResult::Invalidated;
                }

                new_details->current_stage = RequestStage::Trusted;
              }
            }
          }

          // If still untrusted, and this non-signature is the last requested
          // index, or previous attempt at finding supporting signature, request
          // the _next_ index to find supporting signature
          if (new_details->current_stage == RequestStage::Untrusted)
          {
            if (
              new_idx == last_requested_index ||
              (supporting_signature.has_value() &&
               supporting_signature->first == new_idx))
            {
              return UpdateTrustedResult::FetchNext;
            }
          }
        }

        return UpdateTrustedResult::Continue;
      }
    };

    // Guard all access to internal state with this lock
    SpinLock requests_lock;

    // Track all things currently requested by external callers
    std::map<RequestHandle, Request> requests;

    std::set<consensus::Index> pending_fetches;

    ExpiryDuration default_expiry_duration = std::chrono::seconds(1800);

    void fetch_entry_at(consensus::Index idx)
    {
      const auto ib = pending_fetches.insert(idx);
      if (ib.second)
      {
        // Newly requested index
        RINGBUFFER_WRITE_MESSAGE(
          consensus::ledger_get,
          to_host,
          idx,
          consensus::LedgerRequestPurpose::HistoricalQuery);
      }
    }

    std::optional<ccf::NodeInfo> get_node_info(ccf::NodeId node_id)
    {
      // Current solution: Use current state of Nodes table from real store.
      // This only works while entries are never deleted from this table, and
      // makes no check that the signing node was active at the point it
      // produced this signature
      auto tx = source_store.create_read_only_tx();
      auto nodes = tx.ro<ccf::Nodes>(ccf::Tables::NODES);
      return nodes->get(node_id);
    }

    // Returns true if this is a valid signature that passes our verification
    // checks
    bool verify_signature(const StorePtr& sig_store, consensus::Index sig_idx)
    {
      const auto sig = get_signature(sig_store);
      if (!sig.has_value())
      {
        LOG_FAIL_FMT("Signature at {}: Missing signature value", sig_idx);
        return false;
      }

      // Build tree from signature
      ccf::MerkleTreeHistory tree(sig->tree);
      const auto real_root = tree.get_root();
      if (real_root != sig->root)
      {
        LOG_FAIL_FMT("Signature at {}: Invalid root", sig_idx);
        return false;
      }

      const auto node_info = get_node_info(sig->node);
      if (!node_info.has_value())
      {
        LOG_FAIL_FMT("Signature at {}: Node {} is unknown", sig_idx, sig->node);
        return false;
      }

      auto verifier = crypto::make_verifier(node_info->cert);
      const auto verified =
        verifier->verify_hash(real_root.h, sig->sig, MDType::SHA256);
      if (!verified)
      {
        LOG_FAIL_FMT("Signature at {}: Signature invalid", sig_idx);
        return false;
      }

      return true;
    }

    void process_deserialised_store(
      const StorePtr& store,
      const crypto::Sha256Hash& entry_digest,
      consensus::Index idx,
      bool is_signature)
    {
      auto request_it = requests.begin();
      while (request_it != requests.end())
      {
        auto& [handle, request] = *request_it;
        auto details = request.get_store_details(idx);
        if (
          details != nullptr &&
          details->current_stage == RequestStage::Fetching)
        {
          if (is_signature)
          {
            // Signatures have already been verified by the time we get here, so
            // we trust them already
            details->current_stage = RequestStage::Trusted;
          }
          else
          {
            details->current_stage = RequestStage::Untrusted;
          }

          details->entry_digest = entry_digest;

          CCF_ASSERT_FMT(
            details->store == nullptr,
            "Request {} already has store for index {}",
            handle,
            idx);
          details->store = store;

          details->is_signature = is_signature;

          const auto result = request.update_trusted(idx);
          switch (result)
          {
            case (Request::UpdateTrustedResult::Continue):
            {
              ++request_it;
              break;
            }
            case (Request::UpdateTrustedResult::Invalidated):
            {
              request_it = requests.erase(request_it);
              break;
            }
            case (Request::UpdateTrustedResult::FetchNext):
            {
              const auto next_idx = idx + 1;
              fetch_entry_at(next_idx);
              request.supporting_signature =
                std::make_pair(next_idx, std::make_shared<StoreDetails>());
              ++request_it;
              break;
            }
          }
        }
        else
        {
          ++request_it;
        }
      }
    }

    // TODO: Read closely, reconcile
    // Requests::value_type handle_encrypted_past_ledger_secret(
    //   consensus::Index idx,
    //   std::unique_ptr<LedgerSecretRecoveryInfo>&& ledger_secret_recovery_info,
    //   const StorePtr& store)
    // {
    //   auto tx = store->create_read_only_tx();
    //   auto encrypted_past_ledger_secret =
    //     tx.ro<ccf::EncryptedLedgerSecretsInfo>(
    //       ccf::Tables::ENCRYPTED_PAST_LEDGER_SECRET);
    //   if (!encrypted_past_ledger_secret)
    //   {
    //     throw std::logic_error(
    //       fmt::format("No encrypted ledger secret to read at {}", idx));
    //   }

    //   auto previous_ledger_secret =
    //     encrypted_past_ledger_secret->get(0)->previous_ledger_secret;

    //   auto recovered_ledger_secret_raw = decrypt_previous_ledger_secret_raw(
    //     ledger_secret_recovery_info->last_ledger_secret,
    //     std::move(previous_ledger_secret->encrypted_data));

    //   auto recovered_ledger_secret = std::make_shared<LedgerSecret>(
    //     std::move(recovered_ledger_secret_raw),
    //     previous_ledger_secret->previous_secret_stored_version);

    //   Request next_request;
    //   consensus::Index next_idx;

    //   if (
    //     previous_ledger_secret.has_value() &&
    //     previous_ledger_secret->version <=
    //       static_cast<kv::Version>(ledger_secret_recovery_info->target_idx))
    //   {
    //     // All ledger secrets required to deserialise the target index have
    //     // been fetched so fetch the target entry.

    //     next_request.current_stage = RequestStage::Fetching;
    //     next_idx = ledger_secret_recovery_info->target_idx;
    //   }
    //   else
    //   {
    //     // The previous ledger secret still needs to be fetched.

    //     // Store first known ledger secret in request, so that
    //     // we can deserialise the next fetched encrypted ledger secret
    //     ledger_secret_recovery_info->last_ledger_secret =
    //       recovered_ledger_secret;

    //     next_request.current_stage = RequestStage::RecoveringLedgerSecret;
    //     next_idx =
    //       previous_ledger_secret->previous_secret_stored_version.value();
    //     next_request.ledger_secret_recovery_info =
    //       std::move(ledger_secret_recovery_info);
    //   }

    //   historical_ledger_secrets->set_secret(
    //     previous_ledger_secret->version, std::move(recovered_ledger_secret));

    //   return std::make_pair(next_idx, std::move(next_request));
    // }

    std::vector<StorePtr> get_store_range_internal(
      RequestHandle handle,
      consensus::Index start_idx,
      size_t num_following_indices,
      ExpiryDuration expire_after)
    {
      std::lock_guard<SpinLock> guard(requests_lock);

      // TODO: Re-insert this hereish?
      //       consensus::Index first_idx_to_fetch = idx;

      // // If the target historical entry cannot be deserialised with the first
      // // known ledger secret, record the target idx and fetch the previous
      // // historical ledger secret.
      // auto [first_ledger_secret_idx, first_ledger_secret] =
      //   get_first_known_ledger_secret();
      // if (idx < static_cast<consensus::Index>(first_ledger_secret_idx))
      // {
      //   LOG_TRACE_FMT(
      //     "Requesting historical entry at {} but first known ledger secret is "
      //     "applicable from {}",
      //     idx,
      //     first_ledger_secret_idx);

      //   auto previous_secret_stored_version =
      //     first_ledger_secret->previous_secret_stored_version;
      //   if (!previous_secret_stored_version.has_value())
      //   {
      //     throw std::logic_error(fmt::format(
      //       "First known ledger secret at {} has no previous secret stored "
      //       "version",
      //       first_ledger_secret_idx));
      //   }

      //   first_idx_to_fetch = previous_secret_stored_version.value();
      //   request.current_stage = RequestStage::RecoveringLedgerSecret;
      //   request.ledger_secret_recovery_info =
      //     std::make_unique<LedgerSecretRecoveryInfo>(idx, first_ledger_secret);
      // }

      const auto expire_after_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(expire_after);

      auto it = requests.find(handle);
      if (it == requests.end())
      {
        // This is a new handle - insert a newly created Request for it
        it = requests.emplace_hint(it, handle, Request());
      }

      Request& request = it->second;

      // If there are any entries newly added to this Request, begin fetching
      // them now
      auto new_indices = request.adjust_range(start_idx, num_following_indices);
      for (const auto new_idx : new_indices)
      {
        fetch_entry_at(new_idx);
      }

      // Reset the expiry time as this has just been requested
      request.time_to_expiry = expire_after_ms;

      std::vector<StorePtr> trusted_stores;

      for (consensus::Index idx = start_idx;
           idx <= start_idx + num_following_indices;
           ++idx)
      {
        auto target_details = request.get_store_details(idx);
        if (target_details->current_stage == RequestStage::Trusted)
        {
          // Have this store and trust it - add it to return list
          trusted_stores.push_back(target_details->store);
        }
        else
        {
          // Still fetching this store or don't trust it yet, so range is
          // incomplete - return empty vector
          return {};
        }
      }

      return trusted_stores;
    }

    // Used when we received an invalid entry, to drop any requests which were
    // asking for it
    void delete_all_interested_requests(consensus::Index idx)
    {
      auto request_it = requests.begin();
      while (request_it != requests.end())
      {
        if (request_it->second.get_store_details(idx) != nullptr)
        {
          request_it = requests.erase(request_it);
        }
        else
        {
          ++request_it;
        }
      }
    }

  public:
    StateCache(
      kv::Store& store, const std::shared_ptr<ccf::LedgerSecrets>& secrets, const ringbuffer::WriterPtr& host_writer) :
      source_store(store),
      source_ledger_secrets(secrets),
      to_host(host_writer),
      historical_ledger_secrets(std::make_shared<ccf::LedgerSecrets>()),
      historical_encryptor(
        std::make_shared<ccf::NodeEncryptor>(historical_ledger_secrets))
    {}

    StorePtr get_store_at(
      RequestHandle handle,
      consensus::Index idx,
      ExpiryDuration expire_after) override
    {
      auto range = get_store_range(handle, idx, idx, expire_after);
      if (range.empty())
      {
        return nullptr;
      }

      return range[0];
    }

    StorePtr get_store_at(RequestHandle handle, consensus::Index idx) override
    {
      return get_store_at(handle, idx, default_expiry_duration);
    }

    std::vector<StorePtr> get_store_range(
      RequestHandle handle,
      consensus::Index start_idx,
      consensus::Index end_idx,
      ExpiryDuration expire_after) override
    {
      if (end_idx < start_idx)
      {
        throw std::logic_error(fmt::format(
          "Invalid range for historical query: end {} is before start {}",
          end_idx,
          start_idx));
      }

      const auto tail_length = end_idx - start_idx;
      return get_store_range_internal(
        handle, start_idx, tail_length, expire_after);
    }

    std::vector<StorePtr> get_store_range(
      RequestHandle handle,
      consensus::Index start_idx,
      consensus::Index end_idx) override
    {
      return get_store_range(
        handle, start_idx, end_idx, default_expiry_duration);
    }

    void set_default_expiry_duration(ExpiryDuration duration) override
    {
      default_expiry_duration = duration;
    }

    bool drop_request(RequestHandle handle) override
    {
      std::lock_guard<SpinLock> guard(requests_lock);
      const auto erased_count = requests.erase(handle);
      return erased_count > 0;
    }

    bool handle_ledger_entry(consensus::Index idx, const LedgerEntry& data)
    {
      std::lock_guard<SpinLock> guard(requests_lock);
      const auto it = pending_fetches.find(idx);
      if (it == pending_fetches.end())
      {
        // Unexpected entry - ignore it?
        return false;
      }

      pending_fetches.erase(it);

      // TODO: Re-insert this, around here
      //       if (
      //   idx < static_cast<consensus::Index>(
      //           source_ledger_secrets->get_first().first))
      // {
      //   store->set_encryptor(historical_encryptor);
      // }
      // else
      // {
      //   store->set_encryptor(source_store->get_encryptor());
      // }

      // auto request_it = requests.find(idx);
      // if (
      //   request_it != requests.end() &&
      //   request_it->second.current_stage ==
      //     RequestStage::RecoveringLedgerSecret)
      // {
      //   // Encrypted ledger secrets are deserialised in public-only mode.
      //   // Their Merkle tree integrity is not verified: even if the
      //   // recovered ledger secret was bogus, the deserialisation of
      //   // subsequent ledger entries would fail.
      //   const auto deserialise_result =
      //     store->apply(entry, ConsensusType::CFT, true)->execute();
      //   if (deserialise_result == kv::ApplyResult::FAIL)
      //   {
      //     throw std::logic_error(fmt::format(
      //       "Could not deserialise recovered ledger secret entry at {}", idx));
      //   }

      //   if (
      //     deserialise_result !=
      //     kv::ApplyResult::PASS_ENCRYPTED_PAST_LEDGER_SECRET)
      //   {
      //     throw std::logic_error(fmt::format(
      //       "Recovered ledger entry at {} is not an encrypted ledger secret",
      //       idx));
      //   }

      //   auto new_request = handle_encrypted_past_ledger_secret(
      //     idx,
      //     std::move(request_it->second.ledger_secret_recovery_info),
      //     store);
      //   const auto ib = requests.emplace(std::move(new_request));
      //   if (ib.second)
      //   {
      //     fetch_entry_at(ib.first->first);
      //   }
      //   requests.erase(request_it);
      //   return;
      // }

      // const auto deserialise_result =
      //   store->apply(entry, ConsensusType::CFT)->execute();

      // Create a new store and try to deserialise this entry into it
      StorePtr store = std::make_shared<kv::Store>(
        false /* Do not start from very first idx */,
        true /* Make use of historical secrets */);
      store->set_encryptor(source_store.get_encryptor());

      kv::ApplyResult deserialise_result;

      try
      {
        deserialise_result = store->apply(data, ConsensusType::CFT)->execute();
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "Exception while attempting to deserialise entry {}: {}",
          idx,
          e.what());
        deserialise_result = kv::ApplyResult::FAIL;
      }

      if (deserialise_result == kv::ApplyResult::FAIL)
      {
        return false;
      }

      const auto is_signature =
        deserialise_result == kv::ApplyResult::PASS_SIGNATURE;
      if (is_signature)
      {
        // This looks like a signature - check that we trust it
        if (!verify_signature(store, idx))
        {
          LOG_FAIL_FMT("Bad signature at {}", idx);
          delete_all_interested_requests(idx);
          return false;
        }
      }

      LOG_DEBUG_FMT(
        "Processing historical store at {} ({})",
        idx,
        (size_t)deserialise_result);
      const auto entry_digest = crypto::Sha256Hash(data);
      process_deserialised_store(store, entry_digest, idx, is_signature);

      return true;
    }

    void handle_no_entry(consensus::Index idx)
    {
      std::lock_guard<SpinLock> guard(requests_lock);

      // The host failed or refused to give this entry. Currently just
      // forget about it and drop any requests which were looking for it - don't
      // have a mechanism for remembering this failure and reporting it to
      // users.
      const auto fetches_it = pending_fetches.find(idx);
      if (fetches_it != pending_fetches.end())
      {
        delete_all_interested_requests(idx);

        pending_fetches.erase(fetches_it);
      }
    }

    void tick(const std::chrono::milliseconds& elapsed_ms)
    {
      std::lock_guard<SpinLock> guard(requests_lock);
      auto it = requests.begin();
      while (it != requests.end())
      {
        auto& request = it->second;
        if (elapsed_ms >= request.time_to_expiry)
        {
          it = requests.erase(it);
        }
        else
        {
          request.time_to_expiry -= elapsed_ms;
          ++it;
        }
      }
    }
  };
}
