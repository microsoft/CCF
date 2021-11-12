// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_interface.h"
#include "consensus/ledger_enclave_types.h"
#include "ds/ccf_assert.h"
#include "kv/store.h"
#include "node/encryptor.h"
#include "node/history.h"
#include "node/ledger_secrets.h"
#include "node/node_signature.h"
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
    return signatures->get();
  }

  static std::optional<std::vector<uint8_t>> get_tree(const StorePtr& sig_store)
  {
    auto tx = sig_store->create_read_only_tx();
    auto tree =
      tx.ro<ccf::SerialisedMerkleTree>(ccf::Tables::SERIALISED_MERKLE_TREE);
    return tree->get();
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
      ccf::SeqNo target_seqno = 0;
      LedgerSecretPtr last_ledger_secret;

      LedgerSecretRecoveryInfo(
        ccf::SeqNo target_seqno_, LedgerSecretPtr last_ledger_secret_) :
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
      ccf::TxID transaction_id;
    };
    using StoreDetailsPtr = std::shared_ptr<StoreDetails>;

    // TODO: This approach is wrong. Contiguous requests have an advantage, they
    // can store their requested_stores in a single vector. Non-contiguous
    // requests need a map, so we can go from SeqNo to store. So Request needs
    // to become virtual, implemented by an efficient ContiguousRequest and a
    // map-requiring NonContiguousRequest.
    // TODO: The above comment has reduced from a "we must" to a "should we/can
    // we?"
    struct Request
    {
      ccf::SeqNo first_requested_seqno = 0;
      ccf::SeqNo last_requested_seqno = 0;
      SeqNoCollection requested_seqnos;
      std::map<ccf::SeqNo, StoreDetailsPtr> requested_stores;
      std::chrono::milliseconds time_to_expiry;

      bool include_receipts;

      // Entries from outside the requested range (such as the next signature)
      // may be needed to produce receipts. They are stored here, distinct from
      // user-requested stores.
      std::optional<std::pair<ccf::SeqNo, StoreDetailsPtr>>
        supporting_signature;

      // Only set when recovering ledger secrets
      std::unique_ptr<LedgerSecretRecoveryInfo> ledger_secret_recovery_info =
        nullptr;

      Request() {}

      StoreDetailsPtr get_store_details(ccf::SeqNo seqno) const
      {
        auto it = requested_stores.find(seqno);
        if (it != requested_stores.end())
        {
          return it->second;
        }

        if (
          supporting_signature.has_value() &&
          supporting_signature->first == seqno)
        {
          return supporting_signature->second;
        }

        return nullptr;
      }

      using SeqNoRange = std::pair<ccf::SeqNo, ccf::SeqNo>;

      // Keep as many existing entries as possible, return indices that weren't
      // already present to indicate they should be fetched. For example, if we
      // were previously fetching:
      //        2  3  4  5
      // and then we adjust to:
      //              4  5
      // we don't need to fetch anything new; this is a subrange. But if we
      // adjust to:
      //  0  1  2  3  4  5  6
      // we need to start fetching 0, 1, and 6.
      SeqNoCollection adjust_ranges(
        const SeqNoCollection& new_seqnos, bool should_include_receipts)
      {
        if (
          new_seqnos == requested_seqnos &&
          should_include_receipts == include_receipts)
        {
          // This is precisely the request we're already tracking - do nothing
          return {};
        }

        std::set<SeqNo> newly_requested;
        std::map<ccf::SeqNo, StoreDetailsPtr> new_stores;

        for (const auto& [start_seqno, num_following_indices] :
             new_seqnos.get_ranges())
        {
          for (auto seqno = start_seqno; seqno <=
               static_cast<ccf::SeqNo>(start_seqno + num_following_indices);
               ++seqno)
          {
            auto existing_details = get_store_details(seqno);
            if (existing_details == nullptr)
            {
              newly_requested.insert(seqno);
              new_stores[seqno] = std::make_shared<StoreDetails>();
            }
            else
            {
              new_stores[seqno] = std::move(existing_details);
            }
          }
        }

        requested_stores = std::move(new_stores);
        first_requested_seqno = new_seqnos.front();
        last_requested_seqno = new_seqnos.back();

        // If the final entry in the new range is known and not a signature,
        // then we may need a subsequent signature to support it (or an
        // earlier entry received out-of-order!) So start fetching subsequent
        // entries to find supporting signature. It's possible this was the
        // supporting entry we already had, or a signature in the range we
        // already had, but working that out is tricky so be pessimistic and
        // refetch instead.
        supporting_signature.reset();
        if (should_include_receipts)
        {
          const auto last_details = get_store_details(last_requested_seqno);
          if (last_details->store != nullptr && !last_details->is_signature)
          {
            const auto next_seqno = last_requested_seqno + 1;
            supporting_signature =
              std::make_pair(next_seqno, std::make_shared<StoreDetails>());
            newly_requested.insert(next_seqno);
          }
        }

        // If the range has changed, forget what ledger secrets we may have been
        // fetching - the caller can begin asking for them again
        ledger_secret_recovery_info = nullptr;

        requested_seqnos = new_seqnos;
        include_receipts = should_include_receipts;

        return SeqNoCollection(newly_requested.begin(), newly_requested.end());
      }

      enum class PopulateReceiptsResult
      {
        // Common result. The new seqno may have added receipts for some entries
        Continue,

        // Occasional result. The new seqno was at the end of the sequence (or
        // an attempt at retrieving a trailing supporting signature), but we
        // still have receiptless entries, so attempt to fetch the next
        FetchNext,
      };

      PopulateReceiptsResult populate_receipts(ccf::SeqNo new_seqno)
      {
        auto new_details = get_store_details(new_seqno);
        if (new_details->is_signature)
        {
          // Iterate through earlier indices. If this signature covers them
          // then create a receipt for them
          const auto sig = get_signature(new_details->store);
          ccf::MerkleTreeHistory tree(get_tree(new_details->store).value());

          // TODO: Iterate over only requested entries
          for (auto seqno = first_requested_seqno; seqno < new_seqno; ++seqno)
          {
            if (tree.in_range(seqno))
            {
              auto details = get_store_details(seqno);
              if (details != nullptr)
              {
                auto proof = tree.get_proof(seqno);
                details->receipt = std::make_shared<TxReceipt>(
                  sig->sig,
                  proof.get_root(),
                  proof.get_path(),
                  sig->node,
                  sig->cert);
                details->transaction_id = {sig->view, seqno};
              }
            }
          }
        }
        else if (new_details->receipt == nullptr)
        {
          // Iterate through later indices, see if there's a signature that
          // covers this one
          const auto& untrusted_digest = new_details->entry_digest;
          bool sig_seen = false;
          // TODO: Fix this. Iterate only over requested seqnos, not this huge
          // range
          // TODO: Is there just a bug in this fundamental approach? Sparse
          // ranges means we don't know when/where we need to scan for further
          // signatures...
          for (auto seqno = new_seqno + 1; seqno <= last_requested_seqno;
               ++seqno)
          {
            auto details = get_store_details(seqno);
            if (details != nullptr)
            {
              if (details->store != nullptr && details->is_signature)
              {
                const auto sig = get_signature(details->store);
                ccf::MerkleTreeHistory tree(get_tree(details->store).value());
                if (tree.in_range(new_seqno))
                {
                  auto proof = tree.get_proof(new_seqno);
                  new_details->receipt = std::make_shared<TxReceipt>(
                    sig->sig,
                    proof.get_root(),
                    proof.get_path(),
                    sig->node,
                    sig->cert);
                  new_details->transaction_id = {sig->view, new_seqno};
                }

                // Break here - if this signature doesn't cover us, no later
                // one can
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
              ccf::MerkleTreeHistory tree(get_tree(details->store).value());
              if (tree.in_range(new_seqno))
              {
                auto proof = tree.get_proof(new_seqno);
                details->receipt = std::make_shared<TxReceipt>(
                  sig->sig,
                  proof.get_root(),
                  proof.get_path(),
                  sig->node,
                  sig->cert);
                details->transaction_id = {sig->view, new_seqno};
              }
            }
          }

          // If still have no receipt, and this non-signature is the last
          // requested seqno, or a previous attempt at finding supporting
          // signature, request the _next_ seqno to find supporting signature
          if (new_details->receipt == nullptr)
          {
            // TODO: This isn't just last_requested_seqno! This should be any
            // end-of-range newly-requested thing, which may require a
            // supporting signature to be fetched!
            if (
              new_seqno == last_requested_seqno ||
              (supporting_signature.has_value() &&
               supporting_signature->first == new_seqno))
            {
              return PopulateReceiptsResult::FetchNext;
            }
          }
        }

        return PopulateReceiptsResult::Continue;
      }
    };

    // Guard all access to internal state with this lock
    std::mutex requests_lock;

    // Track all things currently requested by external callers
    std::map<RequestHandle, Request> requests;

    std::set<ccf::SeqNo> pending_fetches;

    ExpiryDuration default_expiry_duration = std::chrono::seconds(1800);

    void fetch_entry_at(ccf::SeqNo seqno)
    {
      fetch_entries_range(seqno, seqno);
    }

    void fetch_entries_range(ccf::SeqNo from, ccf::SeqNo to)
    {
      std::optional<ccf::SeqNo> unfetched_from = std::nullopt;
      std::optional<ccf::SeqNo> unfetched_to = std::nullopt;

      for (auto seqno = from; seqno <= to; ++seqno)
      {
        const auto ib = pending_fetches.insert(seqno);
        if (ib.second)
        {
          if (!unfetched_from.has_value())
          {
            unfetched_from = seqno;
          }
          unfetched_to = seqno;
        }
      }

      if (unfetched_from.has_value())
      {
        // Newly requested seqnos
        RINGBUFFER_WRITE_MESSAGE(
          consensus::ledger_get_range,
          to_host,
          static_cast<consensus::Index>(unfetched_from.value()),
          static_cast<consensus::Index>(unfetched_to.value()),
          consensus::LedgerRequestPurpose::HistoricalQuery);
      }
    }

    std::unique_ptr<LedgerSecretRecoveryInfo> fetch_supporting_secret_if_needed(
      ccf::SeqNo seqno)
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
      ccf::SeqNo seqno,
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
            for (const auto& [first_requested_seqno, num_following] :
                 request.requested_seqnos.get_ranges())
            {
              fetch_entries_range(
                first_requested_seqno, first_requested_seqno + num_following);
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
          // Deserialisation includes a GCM integrity check, so all entries have
          // been verified by the time we get here.
          details->current_stage = RequestStage::Trusted;

          details->entry_digest = entry_digest;

          CCF_ASSERT_FMT(
            details->store == nullptr,
            "Request {} already has store for seqno {}",
            handle,
            seqno);
          details->store = store;

          details->is_signature = is_signature;
          if (is_signature)
          {
            // Construct a signature receipt.
            // We do this whether it was requested or not, because we have all
            // the state to do so already, and it's simpler than constructing
            // the receipt _later_ for an already-fetched signature transaction.
            const auto sig = get_signature(details->store);
            assert(sig.has_value());
            details->receipt = std::make_shared<TxReceipt>(
              sig->sig, sig->root.h, nullptr, sig->node, sig->cert);
            details->transaction_id = {sig->view, sig->seqno};
          }

          if (request.include_receipts)
          {
            const auto result = request.populate_receipts(seqno);
            switch (result)
            {
              case (Request::PopulateReceiptsResult::Continue):
              {
                ++request_it;
                break;
              }
              case (Request::PopulateReceiptsResult::FetchNext):
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
        encrypted_past_ledger_secret->get()->previous_ledger_secret;

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

    SeqNoCollection collection_from_single_range(
      ccf::SeqNo start_seqno, ccf::SeqNo end_seqno)
    {
      if (end_seqno < start_seqno)
      {
        throw std::logic_error(fmt::format(
          "Invalid range for historical query: end {} is before start {}",
          end_seqno,
          start_seqno));
      }

      SeqNoCollection c;
      for (auto seqno = start_seqno; seqno <= end_seqno; ++seqno)
      {
        // TODO: Add a range insert, this is way too slow!
        c.insert(seqno);
      }
      return c;
    }

    std::vector<StatePtr> get_states_internal(
      RequestHandle handle,
      const SeqNoCollection& seqno_ranges,
      ExpiryDuration seconds_until_expiry,
      bool include_receipts)
    {
      std::lock_guard<std::mutex> guard(requests_lock);

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

      // Update this Request to represent the currently requested ranges,
      // returning any newly requested indices
      auto new_seqnos = request.adjust_ranges(seqno_ranges, include_receipts);

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
        for (const auto& [start_seqno, additional] : new_seqnos.get_ranges())
        {
          fetch_entries_range(start_seqno, start_seqno + additional);
        }
      }

      // Reset the expiry timer as this has just been requested
      request.time_to_expiry = ms_until_expiry;

      std::vector<StatePtr> trusted_states;

      for (const auto& [start_seqno, num_following_indices] :
           seqno_ranges.get_ranges())
      {
        for (ccf::SeqNo seqno = start_seqno; seqno <=
             static_cast<ccf::SeqNo>(start_seqno + num_following_indices);
             ++seqno)
        {
          auto target_details = request.get_store_details(seqno);
          if (target_details == nullptr)
          {
            throw std::logic_error("Request isn't tracking state for seqno");
          }

          if (
            target_details->current_stage == RequestStage::Trusted &&
            (!request.include_receipts || target_details->receipt != nullptr))
          {
            // Have this store, associated txid and receipt and trust it - add
            // it to return list
            StatePtr state = std::make_shared<State>(
              target_details->store,
              target_details->receipt,
              target_details->transaction_id);
            trusted_states.push_back(state);
          }
          else
          {
            // Still fetching this store or don't trust it yet, so range is
            // incomplete - return empty vector
            return {};
          }
        }
      }

      return trusted_states;
    }

    // Used when we received an invalid entry, to drop any requests which were
    // asking for it
    void delete_all_interested_requests(ccf::SeqNo seqno)
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

    std::vector<StorePtr> states_to_stores(const std::vector<StatePtr>& states)
    {
      std::vector<StorePtr> stores;
      for (size_t i = 0; i < states.size(); i++)
      {
        stores.push_back(states[i]->store);
      }
      return stores;
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
      ccf::SeqNo seqno,
      ExpiryDuration seconds_until_expiry) override
    {
      auto range = get_store_range(handle, seqno, seqno, seconds_until_expiry);
      if (range.empty())
      {
        return nullptr;
      }

      return range[0];
    }

    StorePtr get_store_at(RequestHandle handle, ccf::SeqNo seqno) override
    {
      return get_store_at(handle, seqno, default_expiry_duration);
    }

    StatePtr get_state_at(
      RequestHandle handle,
      ccf::SeqNo seqno,
      ExpiryDuration seconds_until_expiry) override
    {
      auto range = get_state_range(handle, seqno, seqno, seconds_until_expiry);
      if (range.empty())
      {
        return nullptr;
      }

      return range[0];
    }

    StatePtr get_state_at(RequestHandle handle, ccf::SeqNo seqno) override
    {
      return get_state_at(handle, seqno, default_expiry_duration);
    }

    std::vector<StorePtr> get_store_range(
      RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno,
      ExpiryDuration seconds_until_expiry) override
    {
      return states_to_stores(get_states_internal(
        handle,
        collection_from_single_range(start_seqno, end_seqno),
        seconds_until_expiry,
        false));
    }

    std::vector<StorePtr> get_store_range(
      RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno) override
    {
      return get_store_range(
        handle, start_seqno, end_seqno, default_expiry_duration);
    }

    std::vector<StatePtr> get_state_range(
      RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno,
      ExpiryDuration seconds_until_expiry) override
    {
      return get_states_internal(
        handle,
        collection_from_single_range(start_seqno, end_seqno),
        seconds_until_expiry,
        true);
    }

    std::vector<StatePtr> get_state_range(
      RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno) override
    {
      return get_state_range(
        handle, start_seqno, end_seqno, default_expiry_duration);
    }

    std::vector<StorePtr> get_stores_for(
      RequestHandle handle,
      const SeqNoCollection& seqnos,
      ExpiryDuration seconds_until_expiry) override
    {
      return states_to_stores(
        get_states_internal(handle, seqnos, seconds_until_expiry, false));
    }

    std::vector<StorePtr> get_stores_for(
      RequestHandle handle, const SeqNoCollection& seqnos) override
    {
      return get_stores_for(handle, seqnos, default_expiry_duration);
    }

    std::vector<StatePtr> get_states_for(
      RequestHandle handle,
      const SeqNoCollection& seqnos,
      ExpiryDuration seconds_until_expiry) override
    {
      if (seqnos.empty())
      {
        throw std::runtime_error("Cannot request empty range");
      }
      return get_states_internal(handle, seqnos, seconds_until_expiry, true);
    }

    std::vector<StatePtr> get_states_for(
      RequestHandle handle, const SeqNoCollection& seqnos) override
    {
      return get_states_for(handle, seqnos, default_expiry_duration);
    }

    void set_default_expiry_duration(ExpiryDuration duration) override
    {
      default_expiry_duration = duration;
    }

    bool drop_cached_states(RequestHandle handle) override
    {
      std::lock_guard<std::mutex> guard(requests_lock);
      const auto erased_count = requests.erase(handle);
      return erased_count > 0;
    }

    bool handle_ledger_entry(ccf::SeqNo seqno, const std::vector<uint8_t>& data)
    {
      return handle_ledger_entry(seqno, data.data(), data.size());
    }

    bool handle_ledger_entry(ccf::SeqNo seqno, const uint8_t* data, size_t size)
    {
      std::lock_guard<std::mutex> guard(requests_lock);
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

        auto exec = store->deserialize(
          {data, data + size}, ConsensusType::CFT, public_only);
        if (exec == nullptr)
        {
          return false;
        }

        deserialise_result = exec->apply();
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

      {
        // Confirm this entry is from a precursor of the current state, and not
        // a fork
        const auto tx_id = store->current_txid();
        if (tx_id.version != seqno)
        {
          LOG_FAIL_FMT(
            "Corrupt ledger entry received - claims to be {} but is actually "
            "{}.{}",
            seqno,
            tx_id.term,
            tx_id.version);
          return false;
        }

        auto consensus = source_store.get_consensus();
        if (consensus == nullptr)
        {
          LOG_FAIL_FMT("No consensus on source store");
          return false;
        }

        const auto actual_view = consensus->get_view(seqno);
        if (actual_view != tx_id.term)
        {
          LOG_FAIL_FMT(
            "Ledger entry comes from fork - contains {}.{} but this service "
            "expected {}.{}",
            tx_id.term,
            tx_id.version,
            actual_view,
            seqno);
          return false;
        }
      }

      const auto is_signature =
        deserialise_result == kv::ApplyResult::PASS_SIGNATURE;

      LOG_DEBUG_FMT(
        "Processing historical store at {} ({})",
        seqno,
        (size_t)deserialise_result);
      const auto entry_digest = crypto::Sha256Hash({data, size});
      process_deserialised_store(store, entry_digest, seqno, is_signature);

      return true;
    }

    bool handle_ledger_entries(
      ccf::SeqNo from_seqno, ccf::SeqNo to_seqno, const LedgerEntry& data)
    {
      return handle_ledger_entries(
        from_seqno, to_seqno, data.data(), data.size());
    }

    bool handle_ledger_entries(
      ccf::SeqNo from_seqno,
      ccf::SeqNo to_seqno,
      const uint8_t* data,
      size_t size)
    {
      auto seqno = from_seqno;
      bool all_accepted = true;
      while (size > 0)
      {
        const auto header =
          serialized::peek<kv::SerialisedEntryHeader>(data, size);
        const auto whole_size = header.size + kv::serialised_entry_header_size;
        all_accepted &= handle_ledger_entry(seqno, data, whole_size);
        data += whole_size;
        size -= whole_size;
        ++seqno;
      }

      CCF_ASSERT_FMT(
        seqno == to_seqno + 1,
        "Ledger entry range doesn't contain claimed entries");
      return all_accepted;
    }

    void handle_no_entry(ccf::SeqNo seqno)
    {
      handle_no_entry_range(seqno, seqno);
    }

    void handle_no_entry_range(ccf::SeqNo from_seqno, ccf::SeqNo to_seqno)
    {
      std::lock_guard<std::mutex> guard(requests_lock);

      for (auto seqno = from_seqno; seqno <= to_seqno; ++seqno)
      {
        // The host failed or refused to give this entry. Currently just
        // forget about it and drop any requests which were looking for it -
        // don't have a mechanism for remembering this failure and reporting it
        // to users.
        const auto fetches_it = pending_fetches.find(seqno);
        if (fetches_it != pending_fetches.end())
        {
          delete_all_interested_requests(seqno);

          pending_fetches.erase(fetches_it);
        }
      }
    }

    void tick(const std::chrono::milliseconds& elapsed_ms)
    {
      std::lock_guard<std::mutex> guard(requests_lock);
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
