// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "crypto/hash.h"
#include "ds/ccf_assert.h"
#include "ds/dl_list.h"

#include <array>
#include <chrono>
#include <optional>
#include <set>

namespace aft
{
  class RequestTracker
  {
    struct Request
    {
      Request(
        const crypto::Sha256Hash& hash_, std::chrono::milliseconds time_) :
        hash(hash_),
        time(time_)
      {}

      Request(const crypto::Sha256Hash& hash_) : hash(hash_) {}

      crypto::Sha256Hash hash;
      std::chrono::milliseconds time;

      Request* next = nullptr;
      Request* prev = nullptr;
    };

    struct RequestComp
    {
      bool operator()(const Request* lhs, const Request* rhs) const
      {
        const std::array<uint64_t, 4>& lhs_hash =
          (std::array<uint64_t, 4>&)lhs->hash;
        const std::array<uint64_t, 4>& rhs_hash =
          (std::array<uint64_t, 4>&)rhs->hash;

        for (uint32_t i = 0; i < 4; ++i)
        {
          if (lhs_hash[i] == rhs_hash[i])
          {
            continue;
          }
          return lhs_hash[i] > rhs_hash[i];
        }
        return false;
      }
    };

    static constexpr std::chrono::seconds retail_unmatched_deleted_hashes =
      std::chrono::seconds(1);

  public:
    void insert(const crypto::Sha256Hash& hash, std::chrono::milliseconds time)
    {
      std::unique_lock<std::mutex> guard(lock);
      if (!tracking_requests)
      {
        return;
      }

      if (remove(hash, hashes_without_requests, hashes_without_requests_list))
      {
        return;
      }
      insert(hash, time, requests, requests_list);
    }

    void insert_deleted(
      const crypto::Sha256Hash& hash, std::chrono::milliseconds time)
    {
      std::unique_lock<std::mutex> guard(lock);
      if (!tracking_requests)
      {
        return;
      }
#ifndef NDEBUG
      Request r(hash);
      CCF_ASSERT_FMT(
        requests.find(&r) == requests.end(),
        "cannot add deleted request that is a known request, hash:{}",
        hash);
#endif
      insert(hash, time, hashes_without_requests, hashes_without_requests_list);
    }

    bool remove(const crypto::Sha256Hash& hash)
    {
      std::unique_lock<std::mutex> guard(lock);
      if (!tracking_requests)
      {
        return false;
      }
      return remove(hash, requests, requests_list);
    }

    void tick(std::chrono::milliseconds current_time)
    {
      std::unique_lock<std::mutex> guard(lock);
      if (current_time < retail_unmatched_deleted_hashes)
      {
        return;
      }
      current_time += retail_unmatched_deleted_hashes;

      while (!hashes_without_requests_list.is_empty() &&
             hashes_without_requests_list.get_head()->time < current_time)
      {
        Request* req = hashes_without_requests_list.get_head();
        remove(
          req->hash, hashes_without_requests, hashes_without_requests_list);
      }
    }

    std::optional<std::chrono::milliseconds> oldest_entry()
    {
      std::unique_lock<std::mutex> guard(lock);
      if (requests_list.is_empty())
      {
        return std::nullopt;
      }
      return requests_list.get_head()->time;
    }

    bool is_empty()
    {
      std::unique_lock<std::mutex> guard(lock);
      return requests.empty() && requests_list.is_empty() &&
        hashes_without_requests.empty() &&
        hashes_without_requests_list.is_empty();
    }

    void insert_signed_request(ccf::SeqNo seqno, std::chrono::milliseconds time)
    {
      std::unique_lock<std::mutex> guard(lock);
      if (seqno > seqno_last_signature)
      {
        seqno_last_signature = seqno;
        time_last_signature = time;
      }
    }

    std::tuple<ccf::SeqNo, std::chrono::milliseconds>
    get_seqno_time_last_request() const
    {
      std::unique_lock<std::mutex> guard(lock);
      return {seqno_last_signature, time_last_signature};
    }

    void clear()
    {
      std::unique_lock<std::mutex> guard(lock);
      requests.clear();
      requests_list.clear();

      hashes_without_requests.clear();
      hashes_without_requests_list.clear();
    }

    void start_tracking_requests()
    {
      std::unique_lock<std::mutex> guard(lock);
      tracking_requests = true;
    }

  private:
    std::multiset<Request*, RequestComp> requests;
    snmalloc::DLList<Request, std::nullptr_t, true> requests_list;

    std::multiset<Request*, RequestComp> hashes_without_requests;
    snmalloc::DLList<Request, std::nullptr_t, true>
      hashes_without_requests_list;

    ccf::SeqNo seqno_last_signature = ccf::SEQNO_UNKNOWN;
    std::chrono::milliseconds time_last_signature =
      std::chrono::milliseconds(0);
    bool tracking_requests = false;
    mutable std::mutex lock;

    static void insert(
      const crypto::Sha256Hash& hash,
      std::chrono::milliseconds time,
      std::multiset<Request*, RequestComp>& requests_,
      snmalloc::DLList<Request, std::nullptr_t, true>& requests_list_)
    {
      if (
        requests_list_.get_tail() != nullptr &&
        requests_list_.get_tail()->time > time)
      {
        // Time is not a precise measurement and can be different
        // on different threads. To ensure that the time values are
        // correctly ordered reuse the time value of the last
        // inserted item if the new item's time is not the highest known value.
        time = requests_list_.get_tail()->time;
      }
      auto r = std::make_unique<Request>(hash, time);
      requests_.insert(r.get());
      requests_list_.insert_back(r.release());
    }

    bool remove(
      const crypto::Sha256Hash& hash,
      std::multiset<Request*, RequestComp>& requests_,
      snmalloc::DLList<Request, std::nullptr_t, true>& requests_list_)
    {
      Request r(hash);
      auto ret = requests_.equal_range(&r);
      if (ret.first == ret.second)
      {
        return false;
      }

      auto it = ret.first;
      for (auto c = ret.first; c != ret.second; ++c)
      {
        if ((*it)->time > (*c)->time)
        {
          it = c;
        }
      }

      std::unique_ptr<Request> req(*it);
      requests_.erase(it);
      requests_list_.remove(req.get());
      return true;
    }
  };
}