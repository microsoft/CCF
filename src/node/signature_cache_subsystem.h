// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/signature_cache_interface.h"

#include <algorithm>
#include <deque>
#include <mutex>

namespace ccf
{
  class SignatureCacheSubsystem : public SignatureCacheInterface
  {
  private:
    static constexpr size_t DEFAULT_MAX_CACHE_SIZE = 5;

    struct PendingEntry
    {
      std::optional<PrimarySignature> sig = std::nullopt;
      std::optional<std::vector<uint8_t>> cose_signature = std::nullopt;
      std::optional<std::vector<uint8_t>> serialised_tree = std::nullopt;
      ccf::SeqNo sig_seqno = 0;

      bool is_complete() const
      {
        return sig.has_value() && cose_signature.has_value() &&
          serialised_tree.has_value();
      }
    };

    std::deque<PendingEntry> cache;
    size_t max_cache_size = DEFAULT_MAX_CACHE_SIZE;
    mutable std::mutex cache_mutex;

    void evict_oldest()
    {
      while (cache.size() > max_cache_size)
      {
        cache.pop_front();
      }
    }

    PendingEntry& get_or_create_entry(ccf::kv::Version version)
    {
      // Fast path: the new version extends the cache (expected common case)
      if (cache.empty() || version > cache.back().sig_seqno)
      {
        cache.push_back(PendingEntry{
          std::nullopt, std::nullopt, std::nullopt, version});
        evict_oldest();
        return cache.back();
      }

      // Match the last entry (another hook for the same version)
      if (version == cache.back().sig_seqno)
      {
        return cache.back();
      }

      // Anything else would break our strictly ascending ordering invariant
      throw std::logic_error(fmt::format(
        "SignatureCache: received version {} but cache already contains "
        "version {}; entries must arrive in strictly ascending order",
        version,
        cache.back().sig_seqno));
    }

  public:
    SignatureCacheSubsystem() = default;

    void set_max_cache_size(size_t n) override
    {
      std::lock_guard<std::mutex> guard(cache_mutex);
      max_cache_size = n;
      evict_oldest();
    }

    std::optional<CachedSignature> get_signature_for(
      ccf::SeqNo seqno) const override
    {
      std::lock_guard<std::mutex> guard(cache_mutex);

      // Cache is strictly sorted by sig_seqno ascending. We want the
      // first entry with sig_seqno > seqno (the covering signature).
      // Reverse linear scan is used since callers typically want recently
      // committed signatures.
      const PendingEntry* match = nullptr;
      for (auto it = cache.rbegin(); it != cache.rend(); ++it)
      {
        if (it->sig_seqno <= seqno)
        {
          break;
        }
        match = &*it;
      }

      if (match == nullptr || !match->is_complete())
      {
        return std::nullopt;
      }

      return CachedSignature{
        match->sig.value(),
        match->cose_signature.value(),
        match->serialised_tree.value(),
        match->sig_seqno};
    }

    void on_signature_committed(
      ccf::kv::Version version, const PrimarySignature& sig)
    {
      std::lock_guard<std::mutex> guard(cache_mutex);
      auto& entry = get_or_create_entry(version);
      entry.sig = sig;
    }

    void on_cose_signature_committed(
      ccf::kv::Version version, const std::vector<uint8_t>& cose_sig)
    {
      std::lock_guard<std::mutex> guard(cache_mutex);
      auto& entry = get_or_create_entry(version);
      entry.cose_signature = cose_sig;
    }

    void on_tree_committed(
      ccf::kv::Version version, const std::vector<uint8_t>& tree)
    {
      std::lock_guard<std::mutex> guard(cache_mutex);
      auto& entry = get_or_create_entry(version);
      entry.serialised_tree = tree;
    }

    void register_hooks(ccf::kv::Store& tables)
    {
      tables.set_global_hook(
        Tables::SIGNATURES,
        Signatures::wrap_commit_hook(
          [this](
            ccf::kv::Version version, const Signatures::Write& w) {
            if (w.has_value())
            {
              on_signature_committed(version, w.value());
            }
          }));

      tables.set_global_hook(
        Tables::COSE_SIGNATURES,
        CoseSignatures::wrap_commit_hook(
          [this](
            ccf::kv::Version version, const CoseSignatures::Write& w) {
            if (w.has_value())
            {
              on_cose_signature_committed(version, w.value());
            }
          }));

      tables.set_global_hook(
        Tables::SERIALISED_MERKLE_TREE,
        SerialisedMerkleTree::wrap_commit_hook(
          [this](
            ccf::kv::Version version,
            const SerialisedMerkleTree::Write& w) {
            if (w.has_value())
            {
              on_tree_committed(version, w.value());
            }
          }));
    }
  };
}
