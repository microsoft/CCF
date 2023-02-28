// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_assert.h"
#include "ccf/historical_queries_interface.h"
#include "ccf/pal/locking.h"
#include "consensus/ledger_enclave_types.h"
#include "kv/store.h"
#include "node/encryptor.h"
#include "node/history.h"
#include "node/ledger_secrets.h"
#include "node/rpc/node_interface.h"
#include "node/tx_receipt_impl.h"
#include "service/tables/node_signature.h"

#include <list>
#include <map>
#include <memory>
#include <set>

#ifdef ENABLE_HISTORICAL_VERBOSE_LOGGING
#  define HISTORICAL_LOG(...) LOG_INFO_FMT(__VA_ARGS__)
#else
#  define HISTORICAL_LOG(...)
#endif

namespace ccf::historical
{
  enum class RequestNamespace : uint8_t
  {
    Application,
    System,
  };

  using CompoundHandle = std::pair<RequestNamespace, RequestHandle>;

};

FMT_BEGIN_NAMESPACE
template <>
struct formatter<ccf::historical::CompoundHandle>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(
    const ccf::historical::CompoundHandle& p, FormatContext& ctx) const
  {
    return format_to(
      ctx.out(),
      "[{}|{}]",
      std::get<0>(p) == ccf::historical::RequestNamespace::Application ? "APP" :
                                                                         "SYS",
      std::get<1>(p));
  }
};
FMT_END_NAMESPACE

namespace ccf::historical
{
  static constexpr auto slow_fetch_threshold = std::chrono::milliseconds(1000);

  static std::optional<ccf::PrimarySignature> get_signature(
    const kv::StorePtr& sig_store)
  {
    auto tx = sig_store->create_read_only_tx();
    auto signatures = tx.ro<ccf::Signatures>(ccf::Tables::SIGNATURES);
    return signatures->get();
  }

  static std::optional<std::vector<uint8_t>> get_tree(
    const kv::StorePtr& sig_store)
  {
    auto tx = sig_store->create_read_only_tx();
    auto tree =
      tx.ro<ccf::SerialisedMerkleTree>(ccf::Tables::SERIALISED_MERKLE_TREE);
    return tree->get();
  }

  class StateCacheImpl
  {
  protected:
    kv::Store& source_store;
    std::shared_ptr<ccf::LedgerSecrets> source_ledger_secrets;
    ringbuffer::WriterPtr to_host;

    std::shared_ptr<ccf::LedgerSecrets> historical_ledger_secrets;
    std::shared_ptr<ccf::NodeEncryptor> historical_encryptor;

    // whether to keep all the writes so that we can build a diff later
    bool track_deletes_on_missing_keys_v = false;

    enum class RequestStage
    {
      Fetching,
      Untrusted,
      Trusted,
    };

    using LedgerEntry = std::vector<uint8_t>;

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
      std::chrono::milliseconds time_until_fetch;
      RequestStage current_stage = RequestStage::Fetching;
      crypto::Sha256Hash entry_digest = {};
      ccf::ClaimsDigest claims_digest = {};
      kv::StorePtr store = nullptr;
      bool is_signature = false;
      TxReceiptImplPtr receipt = nullptr;
      ccf::TxID transaction_id;
      bool has_commit_evidence = false;

      crypto::HashBytes get_commit_nonce()
      {
        if (store != nullptr)
        {
          auto e = store->get_encryptor();
          return e->get_commit_nonce(
            {transaction_id.view, transaction_id.seqno}, true);
        }
        else
        {
          throw std::logic_error("Store pointer not set");
        }
      }

      std::optional<std::string> get_commit_evidence()
      {
        if (has_commit_evidence)
        {
          return fmt::format(
            "ce:{}.{}:{}",
            transaction_id.view,
            transaction_id.seqno,
            ds::to_hex(get_commit_nonce()));
        }
        else
        {
          return std::nullopt;
        }
      }
    };
    using StoreDetailsPtr = std::shared_ptr<StoreDetails>;
    using RequestedStores = std::map<ccf::SeqNo, StoreDetailsPtr>;

    using WeakStoreDetailsPtr = std::weak_ptr<StoreDetails>;
    using AllRequestedStores = std::map<ccf::SeqNo, WeakStoreDetailsPtr>;

    struct LedgerSecretRecoveryInfo
    {
      ccf::SeqNo target_seqno = 0;
      LedgerSecretPtr last_ledger_secret;
      StoreDetailsPtr target_details;

      LedgerSecretRecoveryInfo(
        ccf::SeqNo target_seqno_,
        LedgerSecretPtr last_ledger_secret_,
        StoreDetailsPtr target_details_) :
        target_seqno(target_seqno_),
        last_ledger_secret(last_ledger_secret_),
        target_details(target_details_)
      {}
    };

    struct Request
    {
      AllRequestedStores& all_stores;

      RequestedStores my_stores;
      std::chrono::milliseconds time_to_expiry;

      bool include_receipts = false;

      // Entries from outside the requested range (such as the next signature)
      // may be needed to produce receipts. They are stored here, distinct from
      // user-requested stores.
      RequestedStores supporting_signatures;

      // Only set when recovering ledger secrets
      std::unique_ptr<LedgerSecretRecoveryInfo> ledger_secret_recovery_info =
        nullptr;

      Request(AllRequestedStores& all_stores_) : all_stores(all_stores_) {}

      StoreDetailsPtr get_store_details(ccf::SeqNo seqno) const
      {
        auto it = all_stores.find(seqno);
        if (it != all_stores.end())
        {
          return it->second.lock();
        }

        return nullptr;
      }

      ccf::SeqNo first_requested_seqno() const
      {
        if (!my_stores.empty())
        {
          return my_stores.begin()->first;
        }

        return {};
      }

      void adjust_ranges(
        const SeqNoCollection& new_seqnos,
        bool should_include_receipts,
        SeqNo earliest_ledger_secret_seqno)
      {
        bool any_diff = false;

        // If a seqno is earlier than the earliest known ledger secret, we will
        // store that it was requested with a nullptr in `my_stores`, but not
        // add it to `all_stores` to begin fetching until a sufficiently early
        // secret has been retrieved. To avoid awkwardly sharding requests (and
        // delaying the secret-fetch with a large request for a later range), we
        // extend that to say that if _any_ seqno is too early, then _all_
        // subsequent seqnos will be pending. This bool tracks that behaviour.
        bool any_too_early = false;

        {
          auto prev_it = my_stores.begin();
          auto new_it = new_seqnos.begin();
          while (new_it != new_seqnos.end())
          {
            if (*new_it == prev_it->first)
            {
              // Asking for a seqno which was also requested previously - do
              // nothing and advance to compare next entries
              ++new_it;
              ++prev_it;
            }
            else if (*new_it > prev_it->first)
            {
              // No longer looking for a seqno which was previously requested.
              // Remove it from my_stores
              prev_it = my_stores.erase(prev_it);
              any_diff |= true;
            }
            else
            {
              // *new_it < prev_it->first
              // Asking for a seqno which was not previously being fetched =>
              // check if another request was fetching it, else create new
              // details to track it
              if (*new_it < earliest_ledger_secret_seqno || any_too_early)
              {
                // If this is too early for known secrets, just record that it
                // was requested but don't add it to all_stores yet
                prev_it = my_stores.insert_or_assign(prev_it, *new_it, nullptr);
                any_too_early = true;
              }
              else
              {
                auto all_it = all_stores.find(*new_it);
                auto details =
                  all_it == all_stores.end() ? nullptr : all_it->second.lock();
                if (details == nullptr)
                {
                  HISTORICAL_LOG("{} is newly requested", *new_it);
                  details = std::make_shared<StoreDetails>();
                  all_stores.insert_or_assign(all_it, *new_it, details);
                }
                prev_it = my_stores.insert_or_assign(prev_it, *new_it, details);
              }
              any_diff |= true;
            }
          }

          if (prev_it != my_stores.end())
          {
            // If we have a suffix of seqnos previously requested, now
            // unrequested, purge them
            my_stores.erase(prev_it, my_stores.end());
            any_diff |= true;
          }
        }

        if (!any_diff && (should_include_receipts == include_receipts))
        {
          HISTORICAL_LOG("Identical to previous request");
          return;
        }

        // If the range has changed, forget what ledger secrets we may have been
        // fetching - the caller can begin asking for them again
        ledger_secret_recovery_info = nullptr;

        const auto newly_requested_receipts =
          should_include_receipts && !include_receipts;

        include_receipts = should_include_receipts;

        HISTORICAL_LOG(
          "Clearing {} supporting signatures", supporting_signatures.size());
        supporting_signatures.clear();
        if (newly_requested_receipts)
        {
          // If requesting signatures, populate receipts for each entry that we
          // already have. Normally this would be done when each entry was
          // received, but in the case that we have the entries already and only
          // request signatures now, we delay that work to now.

          for (auto seqno : new_seqnos)
          {
            populate_receipts(seqno);
          }
        }
      }

      void populate_receipts(ccf::SeqNo new_seqno)
      {
        HISTORICAL_LOG(
          "Looking at {}, and populating receipts from it", new_seqno);
        auto new_details = get_store_details(new_seqno);
        if (new_details != nullptr && new_details->store != nullptr)
        {
          if (new_details->is_signature)
          {
            HISTORICAL_LOG("{} is a signature", new_seqno);

            fill_receipts_from_signature(new_details);
          }
          else
          {
            // This isn't a signature. To find the signature for this, we look
            // through every subsequent transaction, until we find either a gap
            // (a seqno that hasn't been fetched yet), or a signature. If it is
            // a signature, and we've found a contiguous range of seqnos to it,
            // then it must be a signature over this seqno. Else we find a gap
            // first, and fetch it in case it is the signature. It's possible
            // that we already have the later signature, and wastefully fill in
            // the gaps, but this reduces the cases we have to consider so makes
            // the code much simpler.

            HISTORICAL_LOG("{} is not a signature", new_seqno);
            supporting_signatures.erase(new_seqno);

            auto next_seqno = new_seqno + 1;
            while (true)
            {
              auto all_it = all_stores.find(next_seqno);
              auto details =
                all_it == all_stores.end() ? nullptr : all_it->second.lock();
              if (details == nullptr)
              {
                HISTORICAL_LOG(
                  "Looking for new supporting signature at {}", next_seqno);
                details = std::make_shared<StoreDetails>();
                all_stores.insert_or_assign(all_it, next_seqno, details);
              }

              if (details->store == nullptr)
              {
                // Whether we just started fetching or someone else was already
                // looking for this, it's the first gap we've found so _may_ be
                // our signature
                HISTORICAL_LOG(
                  "Assigning {} as potential signature for {}",
                  next_seqno,
                  new_seqno);
                supporting_signatures[next_seqno] = details;
                return;
              }
              else if (details->is_signature)
              {
                const auto filled_this =
                  fill_receipts_from_signature(details, new_seqno);

                if (
                  !filled_this && my_stores.find(new_seqno) != my_stores.end())
                {
                  throw std::logic_error(fmt::format(
                    "Unexpected: Found a signature at {}, and contiguous range "
                    "of transactions from {}, yet signature does not cover "
                    "this seqno!",
                    next_seqno,
                    new_seqno));
                }

                return;
              }
              else
              {
                // This is a normal transaction, and its already fetched.
                // Nothing to do, consider the next.
                ++next_seqno;
              }
            }
          }
        }
      }

    private:
      bool fill_receipts_from_signature(
        const std::shared_ptr<StoreDetails>& sig_details,
        std::optional<ccf::SeqNo> should_fill = std::nullopt)
      {
        // Iterate through earlier indices. If this signature covers them
        // then create a receipt for them
        const auto sig = get_signature(sig_details->store);
        ccf::MerkleTreeHistory tree(get_tree(sig_details->store).value());

        // This is either pointing at the sig itself, or the closest larger
        // seqno we're holding
        auto sig_lower_bound_it =
          my_stores.lower_bound(sig_details->transaction_id.seqno);

        if (sig_lower_bound_it != my_stores.begin()) // Skip empty map edge case
        {
          // Construct reverse iterator to search backwards from here
          auto search_rit = std::reverse_iterator(sig_lower_bound_it);
          while (search_rit != my_stores.rend())
          {
            auto seqno = search_rit->first;
            if (tree.in_range(seqno))
            {
              auto details = search_rit->second;
              if (details != nullptr && details->store != nullptr)
              {
                auto proof = tree.get_proof(seqno);
                details->transaction_id = {sig->view, seqno};
                details->receipt = std::make_shared<TxReceiptImpl>(
                  sig->sig,
                  proof.get_root(),
                  proof.get_path(),
                  sig->node,
                  sig->cert,
                  details->entry_digest,
                  details->get_commit_evidence(),
                  details->claims_digest);
                HISTORICAL_LOG(
                  "Assigned a sig for {} after given signature at {}",
                  seqno,
                  sig_details->transaction_id.to_str());

                if (should_fill.has_value() && seqno == *should_fill)
                {
                  should_fill.reset();
                }
              }

              ++search_rit;
            }
            else
            {
              // Found a seqno which this signature doesn't cover. It can't
              // cover anything else, so break here
              break;
            }
          }
        }

        return !should_fill.has_value();
      }
    };

    // Guard all access to internal state with this lock
    ccf::pal::Mutex requests_lock;

    // Track all things currently requested by external callers
    std::map<CompoundHandle, Request> requests;

    // A map containing (weak pointers to) _all_ of the stores for active
    // requests, allowing distinct requests for the same seqnos to share the
    // same underlying state (and benefit from faster lookup)
    AllRequestedStores all_stores;

    ExpiryDuration default_expiry_duration = std::chrono::seconds(1800);

    void fetch_entry_at(ccf::SeqNo seqno)
    {
      fetch_entries_range(seqno, seqno);
    }

    void fetch_entries_range(ccf::SeqNo from, ccf::SeqNo to)
    {
      LOG_TRACE_FMT("fetch_entries_range({}, {})", from, to);

      RINGBUFFER_WRITE_MESSAGE(
        consensus::ledger_get_range,
        to_host,
        static_cast<consensus::Index>(from),
        static_cast<consensus::Index>(to),
        consensus::LedgerRequestPurpose::HistoricalQuery);
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
            "version ({})",
            earliest_ledger_secret_seqno,
            seqno));
        }

        const auto seqno_to_fetch = previous_secret_stored_version.value();
        LOG_TRACE_FMT(
          "Requesting historical entry at {} but first known ledger "
          "secret is applicable from {}",
          seqno,
          earliest_ledger_secret_seqno);

        auto it = all_stores.find(seqno_to_fetch);
        auto details = it == all_stores.end() ? nullptr : it->second.lock();
        if (details == nullptr)
        {
          LOG_TRACE_FMT("Requesting older secret at {} now", seqno_to_fetch);
          details = std::make_shared<StoreDetails>();
          all_stores.insert_or_assign(it, seqno_to_fetch, details);
          fetch_entry_at(seqno_to_fetch);
        }

        return std::make_unique<LedgerSecretRecoveryInfo>(
          seqno_to_fetch, earliest_ledger_secret, details);
      }

      return nullptr;
    }

    void process_deserialised_store(
      const StoreDetailsPtr& details,
      const kv::StorePtr& store,
      const crypto::Sha256Hash& entry_digest,
      ccf::SeqNo seqno,
      bool is_signature,
      ccf::ClaimsDigest&& claims_digest,
      bool has_commit_evidence)
    {
      // Deserialisation includes a GCM integrity check, so all entries
      // have been verified by the time we get here.
      details->current_stage = RequestStage::Trusted;
      details->has_commit_evidence = has_commit_evidence;

      details->entry_digest = entry_digest;
      if (!claims_digest.empty())
        details->claims_digest = std::move(claims_digest);

      CCF_ASSERT_FMT(
        details->store == nullptr,
        "Cache already has store for seqno {}",
        seqno);
      details->store = store;

      details->is_signature = is_signature;
      if (is_signature)
      {
        // Construct a signature receipt.
        // We do this whether it was requested or not, because we have all
        // the state to do so already, and it's simpler than constructing
        // the receipt _later_ for an already-fetched signature
        // transaction.
        const auto sig = get_signature(details->store);
        assert(sig.has_value());
        details->transaction_id = {sig->view, sig->seqno};
        details->receipt = std::make_shared<TxReceiptImpl>(
          sig->sig, sig->root.h, nullptr, sig->node, sig->cert);
      }

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
            fetch_supporting_secret_if_needed(request.first_requested_seqno());
          if (new_secret_fetch != nullptr)
          {
            request.ledger_secret_recovery_info = std::move(new_secret_fetch);
          }
          else
          {
            // Newly have all required secrets - begin fetching the actual
            // entries. Note this is adding them to `all_stores`, from where
            // they'll be requested on the next tick.
            auto my_stores_it = request.my_stores.begin();
            while (my_stores_it != request.my_stores.end())
            {
              auto [seqno, _] = *my_stores_it;
              auto it = all_stores.find(seqno);
              auto details =
                it == all_stores.end() ? nullptr : it->second.lock();

              if (details == nullptr)
              {
                details = std::make_shared<StoreDetails>();
                all_stores.insert_or_assign(it, seqno, details);
              }

              my_stores_it->second = details;
              ++my_stores_it;
            }
          }

          // In either case, done with this request, try the next
          ++request_it;
          continue;
        }

        if (request.include_receipts)
        {
          const bool seqno_in_this_request =
            (request.my_stores.find(seqno) != request.my_stores.end() ||
             request.supporting_signatures.find(seqno) !=
               request.supporting_signatures.end());
          if (seqno_in_this_request)
          {
            request.populate_receipts(seqno);
          }
        }

        ++request_it;
      }
    }

    bool handle_encrypted_past_ledger_secret(
      const kv::StorePtr& store,
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

      SeqNoCollection c(start_seqno, end_seqno - start_seqno);
      return c;
    }

    std::vector<StatePtr> get_states_internal(
      const CompoundHandle& handle,
      const SeqNoCollection& seqnos,
      ExpiryDuration seconds_until_expiry,
      bool include_receipts)
    {
      if (seqnos.empty())
      {
        throw std::logic_error(
          "Invalid range for historical query: Cannot request empty range");
      }

      std::lock_guard<ccf::pal::Mutex> guard(requests_lock);

      const auto ms_until_expiry =
        std::chrono::duration_cast<std::chrono::milliseconds>(
          seconds_until_expiry);

      auto it = requests.find(handle);
      if (it == requests.end())
      {
        // This is a new handle - insert a newly created Request for it
        it = requests.emplace_hint(it, handle, Request(all_stores));
        HISTORICAL_LOG("First time I've seen handle {}", handle);
      }

      Request& request = it->second;

      auto [earliest_ledger_secret_seqno, _] =
        get_earliest_known_ledger_secret();

      // Update this Request to represent the currently requested ranges
      HISTORICAL_LOG(
        "Adjusting handle {} to cover {} seqnos starting at {} "
        "(include_receipts={})",
        handle,
        seqnos.size(),
        *seqnos.begin(),
        include_receipts);
      request.adjust_ranges(
        seqnos, include_receipts, earliest_ledger_secret_seqno);

      // If the earliest target entry cannot be deserialised with the earliest
      // known ledger secret, record the target seqno and begin fetching the
      // previous historical ledger secret.
      auto secret_fetch =
        fetch_supporting_secret_if_needed(request.first_requested_seqno());
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

      // Reset the expiry timer as this has just been requested
      request.time_to_expiry = ms_until_expiry;

      std::vector<StatePtr> trusted_states;

      for (auto seqno : seqnos)
      {
        auto target_details = request.get_store_details(seqno);

        if (
          target_details != nullptr &&
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

    std::vector<kv::ReadOnlyStorePtr> states_to_stores(
      const std::vector<StatePtr>& states)
    {
      std::vector<kv::ReadOnlyStorePtr> stores;
      for (size_t i = 0; i < states.size(); i++)
      {
        stores.push_back(states[i]->store);
      }
      return stores;
    }

  public:
    StateCacheImpl(
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

    kv::ReadOnlyStorePtr get_store_at(
      const CompoundHandle& handle,
      ccf::SeqNo seqno,
      ExpiryDuration seconds_until_expiry)
    {
      auto range = get_store_range(handle, seqno, seqno, seconds_until_expiry);
      if (range.empty())
      {
        return nullptr;
      }

      return range[0];
    }

    kv::ReadOnlyStorePtr get_store_at(
      const CompoundHandle& handle, ccf::SeqNo seqno)
    {
      return get_store_at(handle, seqno, default_expiry_duration);
    }

    StatePtr get_state_at(
      const CompoundHandle& handle,
      ccf::SeqNo seqno,
      ExpiryDuration seconds_until_expiry)
    {
      auto range = get_state_range(handle, seqno, seqno, seconds_until_expiry);
      if (range.empty())
      {
        return nullptr;
      }

      return range[0];
    }

    StatePtr get_state_at(const CompoundHandle& handle, ccf::SeqNo seqno)
    {
      return get_state_at(handle, seqno, default_expiry_duration);
    }

    std::vector<kv::ReadOnlyStorePtr> get_store_range(
      const CompoundHandle& handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno,
      ExpiryDuration seconds_until_expiry)
    {
      return states_to_stores(get_states_internal(
        handle,
        collection_from_single_range(start_seqno, end_seqno),
        seconds_until_expiry,
        false));
    }

    std::vector<kv::ReadOnlyStorePtr> get_store_range(
      const CompoundHandle& handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno)
    {
      return get_store_range(
        handle, start_seqno, end_seqno, default_expiry_duration);
    }

    std::vector<StatePtr> get_state_range(
      const CompoundHandle& handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno,
      ExpiryDuration seconds_until_expiry)
    {
      return get_states_internal(
        handle,
        collection_from_single_range(start_seqno, end_seqno),
        seconds_until_expiry,
        true);
    }

    std::vector<StatePtr> get_state_range(
      const CompoundHandle& handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno)
    {
      return get_state_range(
        handle, start_seqno, end_seqno, default_expiry_duration);
    }

    std::vector<kv::ReadOnlyStorePtr> get_stores_for(
      const CompoundHandle& handle,
      const SeqNoCollection& seqnos,
      ExpiryDuration seconds_until_expiry)
    {
      return states_to_stores(
        get_states_internal(handle, seqnos, seconds_until_expiry, false));
    }

    std::vector<kv::ReadOnlyStorePtr> get_stores_for(
      const CompoundHandle& handle, const SeqNoCollection& seqnos)
    {
      return get_stores_for(handle, seqnos, default_expiry_duration);
    }

    std::vector<StatePtr> get_states_for(
      const CompoundHandle& handle,
      const SeqNoCollection& seqnos,
      ExpiryDuration seconds_until_expiry)
    {
      if (seqnos.empty())
      {
        throw std::runtime_error("Cannot request empty range");
      }
      return get_states_internal(handle, seqnos, seconds_until_expiry, true);
    }

    std::vector<StatePtr> get_states_for(
      const CompoundHandle& handle, const SeqNoCollection& seqnos)
    {
      return get_states_for(handle, seqnos, default_expiry_duration);
    }

    void set_default_expiry_duration(ExpiryDuration duration)
    {
      default_expiry_duration = duration;
    }

    void track_deletes_on_missing_keys(bool track)
    {
      track_deletes_on_missing_keys_v = track;
    }

    bool drop_cached_states(const CompoundHandle& handle)
    {
      std::lock_guard<ccf::pal::Mutex> guard(requests_lock);
      const auto erased_count = requests.erase(handle);
      HISTORICAL_LOG("Dropping historical request {}", handle);
      return erased_count > 0;
    }

    bool handle_ledger_entry(ccf::SeqNo seqno, const std::vector<uint8_t>& data)
    {
      return handle_ledger_entry(seqno, data.data(), data.size());
    }

    bool handle_ledger_entry(ccf::SeqNo seqno, const uint8_t* data, size_t size)
    {
      std::lock_guard<ccf::pal::Mutex> guard(requests_lock);
      const auto it = all_stores.find(seqno);
      auto details = it == all_stores.end() ? nullptr : it->second.lock();
      if (
        details == nullptr || details->current_stage != RequestStage::Fetching)
      {
        // Unexpected entry, we already have it or weren't asking for it -
        // ignore this resubmission
        return false;
      }

      kv::ApplyResult deserialise_result;
      ccf::ClaimsDigest claims_digest;
      bool has_commit_evidence;
      auto store = deserialise_ledger_entry(
        seqno,
        data,
        size,
        deserialise_result,
        claims_digest,
        has_commit_evidence);

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

      HISTORICAL_LOG(
        "Processing historical store at {} ({})",
        seqno,
        (size_t)deserialise_result);
      const auto entry_digest = crypto::Sha256Hash({data, size});
      process_deserialised_store(
        details,
        store,
        entry_digest,
        seqno,
        is_signature,
        std::move(claims_digest),
        has_commit_evidence);

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
      LOG_TRACE_FMT("handle_ledger_entries({}, {})", from_seqno, to_seqno);

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

      if (seqno != to_seqno + 1)
      {
        LOG_FAIL_FMT(
          "Claimed ledger entries: [{}, {}), actual [{}, {}]",
          from_seqno,
          to_seqno,
          from_seqno,
          seqno);
      }

      return all_accepted;
    }

    void handle_no_entry(ccf::SeqNo seqno)
    {
      handle_no_entry_range(seqno, seqno);
    }

    void handle_no_entry_range(ccf::SeqNo from_seqno, ccf::SeqNo to_seqno)
    {
      std::lock_guard<ccf::pal::Mutex> guard(requests_lock);

      LOG_TRACE_FMT("handle_no_entry_range({}, {})", from_seqno, to_seqno);

      for (auto seqno = from_seqno; seqno <= to_seqno; ++seqno)
      {
        // The host failed or refused to give this entry. Currently just
        // forget about it and drop any requests which were looking for it -
        // don't have a mechanism for remembering this failure and reporting it
        // to users.
        const auto fetches_it = all_stores.find(seqno);
        if (fetches_it != all_stores.end())
        {
          delete_all_interested_requests(seqno);

          all_stores.erase(fetches_it);
        }
      }
    }

    kv::StorePtr deserialise_ledger_entry(
      ccf::SeqNo seqno,
      const uint8_t* data,
      size_t size,
      kv::ApplyResult& result,
      ccf::ClaimsDigest& claims_digest,
      bool& has_commit_evidence)
    {
      // Create a new store and try to deserialise this entry into it
      kv::StorePtr store = std::make_shared<kv::Store>(
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
          result = kv::ApplyResult::FAIL;
          return nullptr;
        }

        result = exec->apply(track_deletes_on_missing_keys_v);
        claims_digest = std::move(exec->consume_claims_digest());

        auto commit_evidence_digest =
          std::move(exec->consume_commit_evidence_digest());
        has_commit_evidence = commit_evidence_digest.has_value();
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "Exception while attempting to deserialise entry {}: {}",
          seqno,
          e.what());
        result = kv::ApplyResult::FAIL;
      }

      return store;
    }

    void tick(const std::chrono::milliseconds& elapsed_ms)
    {
      std::lock_guard<ccf::pal::Mutex> guard(requests_lock);

      {
        auto it = requests.begin();
        while (it != requests.end())
        {
          auto& request = it->second;
          if (elapsed_ms >= request.time_to_expiry)
          {
            LOG_DEBUG_FMT(
              "Dropping expired historical query with handle {}", it->first);
            it = requests.erase(it);
          }
          else
          {
            request.time_to_expiry -= elapsed_ms;
            ++it;
          }
        }
      }

      {
        auto it = all_stores.begin();
        std::optional<std::pair<ccf::SeqNo, ccf::SeqNo>> range_to_request =
          std::nullopt;
        while (it != all_stores.end())
        {
          auto details = it->second.lock();
          if (details == nullptr)
          {
            it = all_stores.erase(it);
          }
          else
          {
            if (details->current_stage == RequestStage::Fetching)
            {
              details->time_until_fetch -= elapsed_ms;
              if (details->time_until_fetch.count() <= 0)
              {
                details->time_until_fetch = slow_fetch_threshold;

                const auto seqno = it->first;
                if (
                  range_to_request.has_value() &&
                  range_to_request->second + 1 == seqno)
                {
                  range_to_request->second = seqno;
                }
                else
                {
                  if (range_to_request.has_value())
                  {
                    // Submit fetch for previously tracked range
                    fetch_entries_range(
                      range_to_request->first, range_to_request->second);
                  }

                  // Track new range
                  range_to_request = std::make_pair(seqno, seqno);
                }
              }
            }

            ++it;
          }
        }

        if (range_to_request.has_value())
        {
          // Submit fetch for final tracked range
          fetch_entries_range(
            range_to_request->first, range_to_request->second);
        }
      }
    }
  };

  class StateCache : public StateCacheImpl, public AbstractStateCache
  {
  protected:
    CompoundHandle make_compound_handle(RequestHandle rh)
    {
      return {RequestNamespace::Application, rh};
    }

  public:
    template <typename... Ts>
    StateCache(Ts&&... ts) : StateCacheImpl(std::forward<Ts>(ts)...)
    {}

    kv::ReadOnlyStorePtr get_store_at(
      RequestHandle handle,
      ccf::SeqNo seqno,
      ExpiryDuration seconds_until_expiry) override
    {
      return StateCacheImpl::get_store_at(
        make_compound_handle(handle), seqno, seconds_until_expiry);
    }

    kv::ReadOnlyStorePtr get_store_at(
      RequestHandle handle, ccf::SeqNo seqno) override
    {
      return StateCacheImpl::get_store_at(make_compound_handle(handle), seqno);
    }

    StatePtr get_state_at(
      RequestHandle handle,
      ccf::SeqNo seqno,
      ExpiryDuration seconds_until_expiry) override
    {
      return StateCacheImpl::get_state_at(
        make_compound_handle(handle), seqno, seconds_until_expiry);
    }

    StatePtr get_state_at(RequestHandle handle, ccf::SeqNo seqno) override
    {
      return StateCacheImpl::get_state_at(make_compound_handle(handle), seqno);
    }

    std::vector<kv::ReadOnlyStorePtr> get_store_range(
      RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno,
      ExpiryDuration seconds_until_expiry) override
    {
      return StateCacheImpl::get_store_range(
        make_compound_handle(handle),
        start_seqno,
        end_seqno,
        seconds_until_expiry);
    }

    std::vector<kv::ReadOnlyStorePtr> get_store_range(
      RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno) override
    {
      return StateCacheImpl::get_store_range(
        make_compound_handle(handle), start_seqno, end_seqno);
    }

    std::vector<StatePtr> get_state_range(
      RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno,
      ExpiryDuration seconds_until_expiry) override
    {
      return StateCacheImpl::get_state_range(
        make_compound_handle(handle),
        start_seqno,
        end_seqno,
        seconds_until_expiry);
    }

    std::vector<StatePtr> get_state_range(
      RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno) override
    {
      return StateCacheImpl::get_state_range(
        make_compound_handle(handle), start_seqno, end_seqno);
    }

    std::vector<kv::ReadOnlyStorePtr> get_stores_for(
      RequestHandle handle,
      const SeqNoCollection& seqnos,
      ExpiryDuration seconds_until_expiry) override
    {
      return StateCacheImpl::get_stores_for(
        make_compound_handle(handle), seqnos, seconds_until_expiry);
    }

    std::vector<kv::ReadOnlyStorePtr> get_stores_for(
      RequestHandle handle, const SeqNoCollection& seqnos) override
    {
      return StateCacheImpl::get_stores_for(
        make_compound_handle(handle), seqnos);
    }

    std::vector<StatePtr> get_states_for(
      RequestHandle handle,
      const SeqNoCollection& seqnos,
      ExpiryDuration seconds_until_expiry) override
    {
      return StateCacheImpl::get_states_for(
        make_compound_handle(handle), seqnos, seconds_until_expiry);
    }

    std::vector<StatePtr> get_states_for(
      RequestHandle handle, const SeqNoCollection& seqnos) override
    {
      return StateCacheImpl::get_states_for(
        make_compound_handle(handle), seqnos);
    }

    void set_default_expiry_duration(ExpiryDuration duration) override
    {
      StateCacheImpl::set_default_expiry_duration(duration);
    }

    void track_deletes_on_missing_keys(bool track) override
    {
      StateCacheImpl::track_deletes_on_missing_keys(track);
    }

    bool drop_cached_states(RequestHandle handle) override
    {
      return StateCacheImpl::drop_cached_states(make_compound_handle(handle));
    }
  };
}
