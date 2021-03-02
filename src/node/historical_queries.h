// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "ds/ccf_assert.h"
#include "ds/spin_lock.h"
#include "historical_queries_interface.h"
#include "kv/store.h"
#include "node/encryptor.h"
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
    auto tx = sig_store->create_read_only_tx();
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
      Fetching,
      Untrusted,
      Trusted,
    };

    using LedgerEntry = std::vector<uint8_t>;

    struct LedgerSecretRecoveryInfo
    {
      kv::SeqNo target_seqno = 0;
      LedgerSecretPtr last_ledger_secret;

      LedgerSecretRecoveryInfo(
        kv::SeqNo target_seqno_, LedgerSecretPtr last_ledger_secret_) :
        target_seqno(target_seqno_),
        last_ledger_secret(last_ledger_secret_)
      {}
    };

    ccf::VersionedLedgerSecret get_earliest_known_ledger_secret()
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
      TxReceiptPtr receipt = nullptr;
    };
    using StoreDetailsPtr = std::shared_ptr<StoreDetails>;

    struct Request
    {
      kv::SeqNo first_requested_seqno = 0;
      kv::SeqNo last_requested_seqno = 0;
      std::vector<StoreDetailsPtr> requested_stores;
      std::chrono::milliseconds time_to_expiry;

      // Entries from outside the requested range (such as the next signature)
      // may be needed to trust this range. They are stored here, distinct from
      // user-requested stores.
      std::optional<std::pair<kv::SeqNo, StoreDetailsPtr>> supporting_signature;

      // Only set when recovering ledger secrets
      std::unique_ptr<LedgerSecretRecoveryInfo> ledger_secret_recovery_info =
        nullptr;

      Request() {}

      StoreDetailsPtr get_store_details(kv::SeqNo seqno) const
      {
        if (seqno >= first_requested_seqno && seqno <= last_requested_seqno)
        {
          const auto offset = seqno - first_requested_seqno;
          if (static_cast<size_t>(offset) < requested_stores.size())
          {
            return requested_stores[offset];
          }
        }

        if (
          supporting_signature.has_value() &&
          supporting_signature->first == seqno)
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
      std::set<kv::SeqNo> adjust_range(
        kv::SeqNo start_seqno, size_t num_following_indices)
      {
        if (
          start_seqno == first_requested_seqno &&
          (num_following_indices + 1) == requested_stores.size())
        {
          // This is precisely the range we're already tracking - do nothing
          return {};
        }

        std::set<kv::SeqNo> ret;
        std::vector<StoreDetailsPtr> new_stores(num_following_indices + 1);
        for (auto seqno = start_seqno; seqno <=
             static_cast<kv::SeqNo>(start_seqno + num_following_indices);
             ++seqno)
        {
          auto existing_details = get_store_details(seqno);
          if (existing_details == nullptr)
          {
            ret.insert(seqno);
            new_stores[seqno - start_seqno] = std::make_shared<StoreDetails>();
          }
          else
          {
            new_stores[seqno - start_seqno] = std::move(existing_details);
          }
        }

        requested_stores = std::move(new_stores);
        first_requested_seqno = start_seqno;
        last_requested_seqno = first_requested_seqno + num_following_indices;

        // If the final entry in the new range is known and not a signature,
        // then we may need a subsequent signature to support it (or an earlier
        // entry received out-of-order!) So start fetching subsequent entries to
        // find supporting signature. Its possible this was the supporting entry
        // we already had, or a signature in the range we already had, but
        // working that out is tricky so be pessimistic and refetch instead.
        supporting_signature.reset();
        const auto last_details = get_store_details(last_requested_seqno);
        if (last_details->store != nullptr && !last_details->is_signature)
        {
          const auto next_seqno = last_requested_seqno + 1;
          supporting_signature =
            std::make_pair(next_seqno, std::make_shared<StoreDetails>());
          ret.insert(next_seqno);
        }

        // If the range has changed, forget what ledger secrets we may have been
        // fetching - the caller can begin asking for them again
        ledger_secret_recovery_info = nullptr;

        return ret;
      }

      enum class UpdateTrustedResult
      {
        // Common result. The new seqno may have transitioned some entries to
        // Trusted
        Continue,

        // Occasional result. The new seqno was at the end of the sequence (or
        // an attempt at retrieving a trailing supporting signature), but we
        // still have untrusted entries, so attempt to fetch the next
        FetchNext,

        // Error result. The new entry exposed a mismatch between a signature's
        // claim at a certain seqno and the entry we received there. Invalidate
        // entire request, it can be re-requested if necessary
        Invalidated,
      };

      UpdateTrustedResult update_trusted(kv::SeqNo new_seqno)
      {
        auto new_details = get_store_details(new_seqno);
        if (new_details->is_signature)
        {
          // Iterate through earlier indices. If this signature covers them (and
          // the digests match), move them to Trusted
          const auto sig = get_signature(new_details->store);
          ccf::MerkleTreeHistory tree(sig->tree);

          for (auto seqno = first_requested_seqno; seqno < new_seqno; ++seqno)
          {
            if (tree.in_range(seqno))
            {
              auto details = get_store_details(seqno);
              if (details != nullptr)
              {
                if (details->current_stage == RequestStage::Untrusted)
                {
                  // Compare signed digest, from signature mini-tree, with
                  // digest of the entry which was used to construct this store
                  const auto& untrusted_digest = details->entry_digest;
                  const auto trusted_digest = tree.get_leaf(seqno);
                  if (trusted_digest != untrusted_digest)
                  {
                    LOG_FAIL_FMT(
                      "Signature at {} has a different transaction at {} than "
                      "previously received",
                      new_seqno,
                      seqno);

                    // We trust the signature (since it comes from a trusted
                    // node), and it disagrees with one of the entries we
                    // previously retrieved and deserialised. This generally
                    // means a malicious host gave us a bad transaction but a
                    // good signature. Delete the entire original request
                    // - if it is re-requested, maybe the host will give us a
                    // valid pair of transaction+sig next time
                    return UpdateTrustedResult::Invalidated;
                  }

                  auto receipt = tree.get_receipt(seqno);
                  details->receipt =
                    std::make_shared<TxReceipt>(sig->sig, receipt.to_v());
                  LOG_FAIL_FMT("Grabbed receipt for {}", seqno);
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
          for (auto seqno = new_seqno + 1; seqno <= last_requested_seqno;
               ++seqno)
          {
            auto details = get_store_details(seqno);
            if (details != nullptr)
            {
              if (details->store != nullptr && details->is_signature)
              {
                const auto sig = get_signature(details->store);
                ccf::MerkleTreeHistory tree(sig->tree);
                if (tree.in_range(new_seqno))
                {
                  const auto trusted_digest = tree.get_leaf(new_seqno);
                  if (trusted_digest != untrusted_digest)
                  {
                    return UpdateTrustedResult::Invalidated;
                  }

                  auto receipt = tree.get_receipt(new_seqno);
                  details->receipt =
                    std::make_shared<TxReceipt>(sig->sig, receipt.to_v());
                  LOG_FAIL_FMT("Grabbed receipt for {}", new_seqno);
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
            const auto& [seqno, details] = *supporting_signature;
            if (details->store != nullptr && details->is_signature)
            {
              const auto sig = get_signature(details->store);
              ccf::MerkleTreeHistory tree(sig->tree);
              if (tree.in_range(new_seqno))
              {
                const auto trusted_digest = tree.get_leaf(new_seqno);
                if (trusted_digest != untrusted_digest)
                {
                  return UpdateTrustedResult::Invalidated;
                }

                auto receipt = tree.get_receipt(new_seqno);
                details->receipt =
                  std::make_shared<TxReceipt>(sig->sig, receipt.to_v());
                LOG_FAIL_FMT("Grabbed receipt for {}", seqno);
                new_details->current_stage = RequestStage::Trusted;
              }
            }
          }

          // If still untrusted, and this non-signature is the last requested
          // seqno, or previous attempt at finding supporting signature, request
          // the _next_ seqno to find supporting signature
          if (new_details->current_stage == RequestStage::Untrusted)
          {
            if (
              new_seqno == last_requested_seqno ||
              (supporting_signature.has_value() &&
               supporting_signature->first == new_seqno))
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

    std::set<kv::SeqNo> pending_fetches;

    ExpiryDuration default_expiry_duration = std::chrono::seconds(1800);

    void fetch_entry_at(kv::SeqNo seqno)
    {
      const auto ib = pending_fetches.insert(seqno);
      if (ib.second)
      {
        // Newly requested seqno
        RINGBUFFER_WRITE_MESSAGE(
          consensus::ledger_get,
          to_host,
          static_cast<consensus::Index>(seqno),
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
    bool verify_signature(const StorePtr& sig_store, kv::SeqNo sig_seqno)
    {
      const auto sig = get_signature(sig_store);
      if (!sig.has_value())
      {
        LOG_FAIL_FMT("Signature at {}: Missing signature value", sig_seqno);
        return false;
      }

      // Build tree from signature
      ccf::MerkleTreeHistory tree(sig->tree);
      const auto real_root = tree.get_root();
      if (real_root != sig->root)
      {
        LOG_FAIL_FMT("Signature at {}: Invalid root", sig_seqno);
        return false;
      }

      const auto node_info = get_node_info(sig->node);
      if (!node_info.has_value())
      {
        LOG_FAIL_FMT(
          "Signature at {}: Node {} is unknown", sig_seqno, sig->node);
        return false;
      }

      auto verifier = crypto::make_verifier(node_info->cert);
      const auto verified =
        verifier->verify_hash(real_root.h, sig->sig, MDType::SHA256);
      if (!verified)
      {
        LOG_FAIL_FMT("Signature at {}: Signature invalid", sig_seqno);
        return false;
      }

      return true;
    }

    std::unique_ptr<LedgerSecretRecoveryInfo> fetch_supporting_secret_if_needed(
      kv::SeqNo seqno)
    {
      auto [earliest_ledger_secret_seqno, earliest_ledger_secret] =
        get_earliest_known_ledger_secret();
      if (seqno < earliest_ledger_secret_seqno)
      {
        // Still need more secrets, fetch the next
        auto previous_secret_stored_version =
          earliest_ledger_secret->previous_secret_stored_version;
        if (!previous_secret_stored_version.has_value())
        {
          throw std::logic_error(fmt::format(
            "Earliest known ledger secret at {} has no earlier secret stored "
            "version",
            earliest_ledger_secret_seqno));
        }

        const auto seqno_to_fetch = previous_secret_stored_version.value();
        LOG_TRACE_FMT(
          "Requesting historical entry at {} but first known ledger "
          "secret is applicable from {} - requesting older secret now",
          seqno,
          earliest_ledger_secret_seqno);

        fetch_entry_at(seqno_to_fetch);
        return std::make_unique<LedgerSecretRecoveryInfo>(
          seqno_to_fetch, earliest_ledger_secret);
      }

      return nullptr;
    }

    void process_deserialised_store(
      const StorePtr& store,
      const crypto::Sha256Hash& entry_digest,
      kv::SeqNo seqno,
      bool is_signature)
    {
      auto request_it = requests.begin();
      while (request_it != requests.end())
      {
        auto& [handle, request] = *request_it;

        // If this request was still waiting for a ledger secret, and this is
        // that secret
        if (
          request.ledger_secret_recovery_info != nullptr &&
          request.ledger_secret_recovery_info->target_seqno == seqno)
        {
          // Handle it, hopefully extending earliest_known_ledger_secret to
          // cover earlier entries
          const auto valid_secret = handle_encrypted_past_ledger_secret(
            store, std::move(request.ledger_secret_recovery_info));
          if (!valid_secret)
          {
            // Invalid! Erase this request: host gave us junk, need to start
            // over
            request_it = requests.erase(request_it);
            continue;
          }

          auto new_secret_fetch =
            fetch_supporting_secret_if_needed(request.first_requested_seqno);
          if (new_secret_fetch != nullptr)
          {
            request.ledger_secret_recovery_info = std::move(new_secret_fetch);
          }
          else
          {
            // Newly have all required secrets - begin fetching the actual
            // entries
            for (auto seqno = request.first_requested_seqno;
                 seqno <= request.last_requested_seqno;
                 ++seqno)
            {
              fetch_entry_at(seqno);
            }
          }

          // In either case, done with this request, try the next
          ++request_it;
          continue;
        }

        auto details = request.get_store_details(seqno);
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
            "Request {} already has store for seqno {}",
            handle,
            seqno);
          details->store = store;

          details->is_signature = is_signature;

          const auto result = request.update_trusted(seqno);
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
              const auto next_seqno = seqno + 1;
              fetch_entry_at(next_seqno);
              request.supporting_signature =
                std::make_pair(next_seqno, std::make_shared<StoreDetails>());
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

    bool handle_encrypted_past_ledger_secret(
      const StorePtr& store,
      std::unique_ptr<LedgerSecretRecoveryInfo> ledger_secret_recovery_info)
    {
      // Read encrypted secrets from store
      auto tx = store->create_read_only_tx();
      auto encrypted_past_ledger_secret =
        tx.ro<ccf::EncryptedLedgerSecretsInfo>(
          ccf::Tables::ENCRYPTED_PAST_LEDGER_SECRET);
      if (!encrypted_past_ledger_secret)
      {
        return false;
      }

      // Construct description and decrypted secret
      auto previous_ledger_secret =
        encrypted_past_ledger_secret->get(0)->previous_ledger_secret;

      auto recovered_ledger_secret = std::make_shared<LedgerSecret>(
        ccf::decrypt_previous_ledger_secret_raw(
          ledger_secret_recovery_info->last_ledger_secret,
          std::move(previous_ledger_secret->encrypted_data)),
        previous_ledger_secret->previous_secret_stored_version);

      // Add recovered secret to historical secrets
      historical_ledger_secrets->set_secret(
        previous_ledger_secret->version, std::move(recovered_ledger_secret));

      return true;
    }

    std::vector<std::pair<StorePtr, TxReceiptPtr>> get_store_range_internal(
      RequestHandle handle,
      kv::SeqNo start_seqno,
      size_t num_following_indices,
      ExpiryDuration seconds_until_expiry)
    {
      std::lock_guard<SpinLock> guard(requests_lock);

      const auto ms_until_expiry =
        std::chrono::duration_cast<std::chrono::milliseconds>(
          seconds_until_expiry);

      auto it = requests.find(handle);
      if (it == requests.end())
      {
        // This is a new handle - insert a newly created Request for it
        it = requests.emplace_hint(it, handle, Request());
      }

      Request& request = it->second;

      // Update this Request to represent the currently requested range,
      // returning any newly requested indices
      auto new_indices =
        request.adjust_range(start_seqno, num_following_indices);

      // If the earliest target entry cannot be deserialised with the earliest
      // known ledger secret, record the target seqno and begin fetching the
      // previous historical ledger secret.
      auto secret_fetch =
        fetch_supporting_secret_if_needed(request.first_requested_seqno);
      if (secret_fetch != nullptr)
      {
        if (
          request.ledger_secret_recovery_info == nullptr ||
          request.ledger_secret_recovery_info->target_seqno !=
            secret_fetch->target_seqno)
        {
          request.ledger_secret_recovery_info = std::move(secret_fetch);
        }
      }
      else
      {
        // If we have sufficiently early secrets, begin fetching any newly
        // requested entries. If we don't fall into this branch, they'll only
        // begin to be fetched once the secret arrives.
        for (const auto new_seqno : new_indices)
        {
          fetch_entry_at(new_seqno);
        }
      }

      // Reset the expiry timer as this has just been requested
      request.time_to_expiry = ms_until_expiry;

      std::vector<std::pair<StorePtr, TxReceiptPtr>> trusted_stores;

      for (kv::SeqNo seqno = start_seqno;
           seqno <= static_cast<kv::SeqNo>(start_seqno + num_following_indices);
           ++seqno)
      {
        auto target_details = request.get_store_details(seqno);
        if (target_details->current_stage == RequestStage::Trusted)
        {
          // Have this store and trust it - add it to return list
          trusted_stores.push_back(
            {target_details->store, target_details->receipt});
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
    void delete_all_interested_requests(kv::SeqNo seqno)
    {
      auto request_it = requests.begin();
      while (request_it != requests.end())
      {
        if (request_it->second.get_store_details(seqno) != nullptr)
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
      kv::Store& store,
      const std::shared_ptr<ccf::LedgerSecrets>& secrets,
      const ringbuffer::WriterPtr& host_writer) :
      source_store(store),
      source_ledger_secrets(secrets),
      to_host(host_writer),
      historical_ledger_secrets(std::make_shared<ccf::LedgerSecrets>()),
      historical_encryptor(
        std::make_shared<ccf::NodeEncryptor>(historical_ledger_secrets))
    {}

    StorePtr get_store_at(
      RequestHandle handle,
      kv::SeqNo seqno,
      ExpiryDuration seconds_until_expiry) override
    {
      auto range = get_store_range(handle, seqno, seqno, seconds_until_expiry);
      if (range.empty())
      {
        return nullptr;
      }

      return range[0];
    }

    StorePtr get_store_at(RequestHandle handle, kv::SeqNo seqno) override
    {
      return get_store_at(handle, seqno, default_expiry_duration);
    }

    std::optional<std::pair<StorePtr, TxReceiptPtr>> get_store_and_receipt_at(
      RequestHandle handle, kv::SeqNo seqno) override
    {
      auto range =
        get_store_range_internal(handle, seqno, 1, default_expiry_duration);

      if (range.empty())
      {
        return std::nullopt;
      }

      return range[0];
    }

    std::vector<StorePtr> get_store_range(
      RequestHandle handle,
      kv::SeqNo start_seqno,
      kv::SeqNo end_seqno,
      ExpiryDuration seconds_until_expiry) override
    {
      if (end_seqno < start_seqno)
      {
        throw std::logic_error(fmt::format(
          "Invalid range for historical query: end {} is before start {}",
          end_seqno,
          start_seqno));
      }

      const auto tail_length = end_seqno - start_seqno;
      auto range = get_store_range_internal(
        handle, start_seqno, tail_length, seconds_until_expiry);
      std::vector<StorePtr> stores;
      for (size_t i = 0; i < range.size(); i++)
      {
        stores.push_back(std::get<0>(range[i]));
      }
      return stores;
    }

    std::vector<StorePtr> get_store_range(
      RequestHandle handle, kv::SeqNo start_seqno, kv::SeqNo end_seqno) override
    {
      return get_store_range(
        handle, start_seqno, end_seqno, default_expiry_duration);
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

    bool handle_ledger_entry(kv::SeqNo seqno, const LedgerEntry& data)
    {
      std::lock_guard<SpinLock> guard(requests_lock);
      const auto it = pending_fetches.find(seqno);
      if (it == pending_fetches.end())
      {
        // Unexpected entry - ignore it?
        return false;
      }

      pending_fetches.erase(it);

      // Create a new store and try to deserialise this entry into it
      StorePtr store = std::make_shared<kv::Store>(
        false /* Do not start from very first seqno */,
        true /* Make use of historical secrets */);

      // If this is older than the node's currently known ledger secrets, use
      // the historical encryptor (which should have older secrets)
      if (seqno < source_ledger_secrets->get_first().first)
      {
        store->set_encryptor(historical_encryptor);
      }
      else
      {
        store->set_encryptor(source_store.get_encryptor());
      }

      kv::ApplyResult deserialise_result;

      try
      {
        // Encrypted ledger secrets are deserialised in public-only mode. Their
        // Merkle tree integrity is not verified: even if the recovered ledger
        // secret was bogus, the deserialisation of subsequent ledger entries
        // would fail.
        bool public_only = false;
        for (const auto& [_, request] : requests)
        {
          if (
            request.ledger_secret_recovery_info != nullptr &&
            request.ledger_secret_recovery_info->target_seqno == seqno)
          {
            public_only = true;
            break;
          }
        }

        deserialise_result =
          store->apply(data, ConsensusType::CFT, public_only)->execute();
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "Exception while attempting to deserialise entry {}: {}",
          seqno,
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
        if (!verify_signature(store, seqno))
        {
          LOG_FAIL_FMT("Bad signature at {}", seqno);
          delete_all_interested_requests(seqno);
          return false;
        }
      }

      LOG_DEBUG_FMT(
        "Processing historical store at {} ({})",
        seqno,
        (size_t)deserialise_result);
      const auto entry_digest = crypto::Sha256Hash(data);
      process_deserialised_store(store, entry_digest, seqno, is_signature);

      return true;
    }

    void handle_no_entry(kv::SeqNo seqno)
    {
      std::lock_guard<SpinLock> guard(requests_lock);

      // The host failed or refused to give this entry. Currently just
      // forget about it and drop any requests which were looking for it - don't
      // have a mechanism for remembering this failure and reporting it to
      // users.
      const auto fetches_it = pending_fetches.find(seqno);
      if (fetches_it != pending_fetches.end())
      {
        delete_all_interested_requests(seqno);

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
