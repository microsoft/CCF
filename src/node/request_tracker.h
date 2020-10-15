// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
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
        const std::array<uint8_t, 32>& hash_, std::chrono::milliseconds time_) :
        hash(hash_),
        time(time_)
      {}

      Request(const std::array<uint8_t, 32>& hash_) : hash(hash_) {}

      std::array<uint8_t, 32> hash;
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

    static constexpr std::chrono::minutes retail_unmatched_deleted_hashes =
      std::chrono::minutes(1);

  public:
    void insert(
      const std::array<uint8_t, 32>& hash, std::chrono::milliseconds time)
    {
      if (remove(hash, deleted_requests, deleted_requests_list))
      {
        return;
      }
      insert(hash, time, requests, requests_list);
    }

    void insert_deleted(
      const std::array<uint8_t, 32>& hash, std::chrono::milliseconds time)
    {
#ifndef NDEBUG
      Request r(hash);
      CCF_ASSERT_FMT(
        requests.find(&r) == requests.end(),
        "cannot add deleted request that is a known request, hash:{}",
        hash);
#endif
      insert(hash, time, deleted_requests, deleted_requests_list);
    }

    bool remove(const std::array<uint8_t, 32>& hash)
    {
      return remove(hash, requests, requests_list);
    }

    void tick(std::chrono::milliseconds current_time)
    {
      if (current_time < retail_unmatched_deleted_hashes)
      {
        return;
      }
      current_time += retail_unmatched_deleted_hashes;

      while (!deleted_requests_list.is_empty() &&
             deleted_requests_list.get_head()->time < current_time)
      {
        Request* req = deleted_requests_list.get_head();
        remove(req->hash, deleted_requests, deleted_requests_list);
      }
    }

    std::optional<std::chrono::milliseconds> oldest_entry()
    {
      if (requests_list.is_empty())
      {
        return std::nullopt;
      }
      return requests_list.get_head()->time;
    }

    bool is_empty()
    {
      return requests.empty() && requests_list.is_empty() &&
        deleted_requests.empty() && deleted_requests_list.is_empty();
    }

  private:
    std::multiset<Request*, RequestComp> requests;
    snmalloc::DLList<Request, std::nullptr_t, true> requests_list;

    std::multiset<Request*, RequestComp> deleted_requests;
    snmalloc::DLList<Request, std::nullptr_t, true> deleted_requests_list;

    void insert(
      const std::array<uint8_t, 32>& hash,
      std::chrono::milliseconds time,
      std::multiset<Request*, RequestComp>& requests_,
      snmalloc::DLList<Request, std::nullptr_t, true>& requests_list_)
    {
      CCF_ASSERT_FMT(
        requests_list_.get_tail() == nullptr ||
          requests_list_.get_tail()->time <= time,
        "items not entred in the correct order. last:{}, time:{}",
        requests_list_.get_tail()->time,
        time);
      auto r = std::make_unique<Request>(hash, time);
      requests_.insert(r.get());
      requests_list_.insert_back(r.release());
    }

    bool remove(
      const std::array<uint8_t, 32>& hash,
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