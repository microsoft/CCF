// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/signature_cache_interface.h"

#include <map>
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

      [[nodiscard]] bool is_complete() const
      {
        return (sig.has_value() || cose_signature.has_value()) &&
          serialised_tree.has_value();
      }
    };

    std::map<ccf::SeqNo, PendingEntry> cache;
    size_t max_cache_size = DEFAULT_MAX_CACHE_SIZE;
    mutable std::mutex cache_mutex;

    void evict_oldest()
    {
      if (cache.size() > max_cache_size)
      {
        auto excess = cache.size() - max_cache_size;
        auto end = std::next(cache.begin(), static_cast<ptrdiff_t>(excess));
        cache.erase(cache.begin(), end);
      }
    }

    PendingEntry& get_or_create_entry(ccf::kv::Version version)
    {
      cache.try_emplace(version);
      evict_oldest();

      // If eviction removed the entry we just inserted (version was
      // older than everything and cache was full), re-insert it. This
      // is an edge case that shouldn't occur in practice, would mean extremely
      // out-of-order/large-batch hooks
      auto it = cache.find(version);
      if (it == cache.end())
      {
        it = cache.try_emplace(version).first;
      }
      return it->second;
    }

  public:
    SignatureCacheSubsystem() = default;

    void set_max_cache_size(size_t n) override
    {
      std::lock_guard<std::mutex> guard(cache_mutex);
      max_cache_size = std::max<size_t>(1, n);
      evict_oldest();
    }

    [[nodiscard]] std::optional<CachedSignature> get_signature_for(
      ccf::SeqNo seqno) const override
    {
      std::lock_guard<std::mutex> guard(cache_mutex);

      // Find the first entry with version > seqno (the covering signature).
      auto it = cache.upper_bound(seqno);
      if (it == cache.end())
      {
        return std::nullopt;
      }

      const auto& [version, entry] = *it;
      if (
        !(entry.sig.has_value() || entry.cose_signature.has_value()) ||
        !entry.serialised_tree.has_value())
      {
        return std::nullopt;
      }

      return CachedSignature{
        entry.sig,
        entry.cose_signature,
        entry.serialised_tree.value(),
        version};
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
          [this](ccf::kv::Version version, const Signatures::Write& w) {
            if (w.has_value())
            {
              on_signature_committed(version, w.value());
            }
          }));

      tables.set_global_hook(
        Tables::COSE_SIGNATURES,
        CoseSignatures::wrap_commit_hook(
          [this](ccf::kv::Version version, const CoseSignatures::Write& w) {
            if (w.has_value())
            {
              on_cose_signature_committed(version, w.value());
            }
          }));

      tables.set_global_hook(
        Tables::SERIALISED_MERKLE_TREE,
        SerialisedMerkleTree::wrap_commit_hook(
          [this](
            ccf::kv::Version version, const SerialisedMerkleTree::Write& w) {
            if (w.has_value())
            {
              on_tree_committed(version, w.value());
            }
          }));
    }
  };
}
