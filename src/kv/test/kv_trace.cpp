// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/kv/map.h"
#include "kv/compacted_version_conflict.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"

#include <atomic>
#include <barrier>
#include <doctest/doctest.h>
#include <thread>

#ifdef CCF_KV_TRACING
namespace
{
  class KVTraceReporter : public doctest::IReporter
  {
    std::string name;
    std::vector<std::string> subcases;
    std::atomic<bool> failed = false;

  public:
    explicit KVTraceReporter(const doctest::ContextOptions&) {}

    void report_query(const doctest::QueryData&) override {}
    void test_run_start() override
    {
      ccf::kv::trace::start();
    }
    void test_run_end(const doctest::TestRunStats&) override
    {
      ccf::kv::trace::finish();
    }
    void test_case_start(const doctest::TestCaseData& data) override
    {
      name = data.m_name;
      failed = false;
      ccf::kv::trace::event("case_begin", {{"name", name}});
    }
    void test_case_reenter(const doctest::TestCaseData& data) override
    {
      ccf::kv::trace::event(
        "case_end", {{"name", name}, {"failed", failed.load()}});
      test_case_start(data);
    }
    void test_case_end(const doctest::CurrentTestCaseStats& stats) override
    {
      ccf::kv::trace::event(
        "case_end",
        {{"name", name}, {"failed", failed.load() || !stats.testCaseSuccess}});
    }
    void test_case_exception(const doctest::TestCaseException&) override
    {
      failed = true;
      ccf::kv::trace::event(
        "unsupported", {{"operation", "test case exception"}});
    }
    void subcase_start(const doctest::SubcaseSignature& signature) override
    {
      subcases.emplace_back(signature.m_name.c_str());
      ccf::kv::trace::event("subcase_begin", {{"name", subcases.back()}});
    }
    void subcase_end() override
    {
      ccf::kv::trace::event("subcase_end", {{"name", subcases.back()}});
      subcases.pop_back();
    }
    void log_assert(const doctest::AssertData& data) override
    {
      if (data.m_failed)
      {
        failed = true;
      }
    }
    void log_message(const doctest::MessageData&) override {}
    void test_case_skipped(const doctest::TestCaseData&) override {}
  };

  DOCTEST_REGISTER_REPORTER("kv_trace", 1, KVTraceReporter);
}
#endif

namespace
{
  using Map = ccf::kv::MapSerialisedWith<
    std::string,
    std::string,
    ccf::kv::serialisers::BlitSerialiser>;
  using Result = ccf::kv::CommitResult;

  struct TraceStore : public ccf::kv::Store
  {
    TraceStore()
    {
      set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
    }
  };
}

TEST_CASE("KV trace multi-map semantics")
{
  TraceStore store;
  Map a("public:trace.a");
  Map b("trace.b");
  {
    auto tx = store.create_tx();
    CHECK(tx.commit() == Result::SUCCESS);
  }
  {
    auto tx = store.create_tx();
    auto ha = tx.rw(a);
    auto hb = tx.rw(b);
    CHECK_FALSE(ha->has("missing"));
    CHECK_FALSE(hb->get("missing").has_value());
    CHECK_FALSE(ha->get_version_of_previous_write("key").has_value());
    ha->put("key", "first");
    tx.rw(a)->put("key", "second");
    hb->put("other", std::string("\0\xff", 2));
    hb->put("", "");
    CHECK(ha->get("key") == "second");
    CHECK(hb->get("") == "");
    CHECK_FALSE(ha->get_globally_committed("key").has_value());
    CHECK_FALSE(
      tx.rw<ccf::kv::untyped::Map>(a.get_name())
        ->has_globally_committed(Map::KeySerialiser::to_serialised("key")));
    ha->remove("key");
    CHECK_FALSE(ha->has("key"));
    ha->put("key", "final");
    CHECK(tx.commit() == Result::SUCCESS);
  }
  {
    auto tx = store.create_tx();
    tx.rw(a)->put("abandoned", "value");
    tx = store.create_tx();
    CHECK_FALSE(tx.ro(a)->has("abandoned"));
    CHECK(tx.ro(a)->get("key") == "final");
    CHECK(tx.ro(b)->get("other") == std::string("\0\xff", 2));
    CHECK(tx.ro(a)->get_version_of_previous_write("key") == 1);
    CHECK(tx.commit() == Result::SUCCESS);
  }
  {
    auto tx = store.create_tx();
    tx.rw(a)->put("key", "final");
    CHECK(tx.commit() == Result::SUCCESS);
  }
  {
    auto tx = store.create_tx();
    CHECK(tx.ro(a)->get_version_of_previous_write("key") == 2);
    tx.rw(b)->remove("absent");
    CHECK(tx.commit() == Result::SUCCESS);
    CHECK(store.current_version() == 3);
  }
}

TEST_CASE("KV trace dependencies")
{
  TraceStore store;
  Map a("trace.a");
  Map b("trace.b");
  {
    auto tx = store.create_tx();
    tx.rw(a)->put("key", "on");
    tx.rw(b)->put("key", "on");
    REQUIRE(tx.commit() == Result::SUCCESS);
  }
  {
    auto left = store.create_tx();
    auto right = store.create_tx();
    CHECK(left.ro(b)->get("key") == "on");
    CHECK(right.ro(a)->get("key") == "on");
    left.rw(a)->put("key", "off");
    right.rw(b)->put("key", "off");
    CHECK(left.commit() == Result::SUCCESS);
    CHECK(right.commit() == Result::FAIL_CONFLICT);
  }
  {
    auto absent = store.create_tx();
    CHECK_FALSE(absent.ro(a)->has("absent"));
    absent.rw(b)->put("key", "depends");
    auto other = store.create_tx();
    other.rw(a)->put("absent", "present");
    CHECK(other.commit() == Result::SUCCESS);
    CHECK(absent.commit() == Result::FAIL_CONFLICT);
  }
  {
    auto first = store.create_tx();
    auto second = store.create_tx();
    first.rw(a)->put("key", "blind1");
    second.rw(a)->put("key", "blind2");
    CHECK(first.commit() == Result::SUCCESS);
    CHECK(second.commit() == Result::SUCCESS);
  }
}

TEST_CASE("KV trace iteration")
{
  TraceStore store;
  Map map("trace.iteration");
  {
    auto tx = store.create_tx();
    auto h = tx.rw(map);
    h->put("a", "1");
    h->put("b", "2");
    REQUIRE(tx.commit() == Result::SUCCESS);
  }
  {
    auto tx = store.create_tx();
    auto h = tx.rw(map);
    size_t visited = 0;
    h->foreach([&](const auto& key, const auto& value) {
      ++visited;
      CHECK(h->get(key) == value);
      h->remove(key);
      h->put("c", "3");
      return true;
    });
    CHECK(visited == 2);
    CHECK(h->size() == 1);
    h->put("d", "4");
    visited = 0;
    h->foreach([&](const auto&, const auto&) {
      ++visited;
      h->foreach([](const auto&, const auto&) { return false; });
      return false;
    });
    CHECK(visited == 1);
    h->clear();
    CHECK(h->size() == 0);
    REQUIRE(tx.commit() == Result::SUCCESS);
  }
  {
    auto reader = store.create_tx();
    CHECK(reader.ro(map)->size() == 0);
    reader.rw(map)->put("dependent", "value");
    auto writer = store.create_tx();
    writer.rw(map)->put("phantom", "value");
    CHECK(writer.commit() == Result::SUCCESS);
    CHECK(reader.commit() == Result::FAIL_CONFLICT);
  }
}

TEST_CASE("KV trace compaction rollback")
{
  TraceStore store;
  store.initialise_term(1);
  Map a("trace.a");
  Map b("trace.b");
  {
    auto tx = store.create_tx();
    tx.rw(a)->put("key", "one");
    tx.rw(b)->put("key", "one");
    REQUIRE(tx.commit() == Result::SUCCESS);
  }
  store.compact(1);
  auto pinned = store.create_tx();
  auto ha = pinned.rw(a);
  CHECK(ha->get("key") == "one");
  {
    auto tx = store.create_tx();
    tx.rw(a)->put("key", "two");
    REQUIRE(tx.commit() == Result::SUCCESS);
  }
  store.compact(2);
  store.compact(3);
  CHECK(store.current_version() == 2);
  CHECK(store.compacted_version() == 2);
  CHECK(ha->get("key") == "one");
  CHECK(ha->get_globally_committed("key") == "one");
  CHECK(pinned.ro(b)->get("key") == "one");
  CHECK(pinned.commit() == Result::SUCCESS);
  CHECK_THROWS_AS(store.rollback({1, 1}, 2), std::logic_error);
  {
    auto tx = store.create_tx();
    tx.rw(a)->put("key", "three");
    REQUIRE(tx.commit() == Result::SUCCESS);
  }
  auto stale = store.create_tx();
  auto old = stale.rw(a);
  CHECK(old->get("key") == "three");
  store.rollback({1, 2}, 2);
  CHECK(old->get("key") == "three");
  old->put("key", "stale");
  CHECK(stale.commit() == Result::FAIL_CONFLICT);
  auto term_stale = store.create_tx();
  term_stale.rw(b)->put("key", "stale term");
  store.rollback({1, 2}, 3);
  CHECK(term_stale.commit() == Result::FAIL_NO_REPLICATE);
  auto fresh = store.create_tx();
  CHECK(fresh.ro(a)->get("key") == "two");
  CHECK(fresh.ro(a)->get_globally_committed("key") == "two");
  CHECK(fresh.commit() == Result::SUCCESS);

  {
    TraceStore late_store;
    auto waiting = late_store.create_tx();
    CHECK_FALSE(waiting.ro(a)->get("key").has_value());
    {
      auto writer = late_store.create_tx();
      writer.rw(b)->put("key", "created later");
      REQUIRE(writer.commit() == Result::SUCCESS);
    }
    late_store.compact(1);
    CHECK_FALSE(waiting.ro(b)->get("key").has_value());
    CHECK_FALSE(waiting.ro(b)->get_globally_committed("key").has_value());
  }

  {
    TraceStore empty_store;
    {
      auto creator = empty_store.create_tx();
      creator.rw(b)->remove("missing");
      REQUIRE(creator.commit() == Result::SUCCESS);
      REQUIRE(empty_store.current_version() == 1);
    }
    auto waiting = empty_store.create_tx();
    CHECK_FALSE(waiting.ro(a)->get("key").has_value());
    {
      auto writer = empty_store.create_tx();
      writer.rw(b)->put("key", "created earlier");
      REQUIRE(writer.commit() == Result::SUCCESS);
    }
    empty_store.compact(2);
    CHECK_THROWS_AS(waiting.ro(b), ccf::kv::CompactedVersionConflict);
  }
}

TEST_CASE("KV trace per-map global snapshots")
{
  TraceStore store;
  Map a("trace.a");
  Map b("trace.b");
  for (const auto* value : {"one", "two"})
  {
    auto tx = store.create_tx();
    tx.rw(a)->put("key", value);
    tx.rw(a)->put("other", std::string(value) + "-other");
    tx.rw(b)->put("key", value);
    tx.rw(b)->put("other", std::string(value) + "-other");
    REQUIRE(tx.commit() == Result::SUCCESS);
    if (store.current_version() == 1)
    {
      store.compact(1);
    }
  }
  auto tx = store.create_tx();
  auto ha = tx.ro(a);
  CHECK(ha->get("key") == "two");
  CHECK(ha->get_globally_committed("key") == "one");
  store.compact(2);
  auto hb = tx.ro(b);
  CHECK(hb->get("key") == "two");
  // Each map retains its global view, including unread keys and handle aliases.
  CHECK(tx.ro(a) == ha);
  CHECK(ha->get_globally_committed("key") == "one");
  CHECK(ha->get_globally_committed("other") == "one-other");
  CHECK(hb->get_globally_committed("key") == "two");
  CHECK(hb->get_globally_committed("other") == "two-other");
  CHECK(tx.commit() == Result::SUCCESS);
}

TEST_CASE("KV trace disjoint concurrent commits")
{
  TraceStore store;
  constexpr size_t count = 4;
  constexpr size_t rounds = 16;
  std::vector<Map> maps;
  {
    auto tx = store.create_tx();
    for (size_t i = 0; i < count; ++i)
    {
      maps.emplace_back("trace.concurrent." + std::to_string(i));
      tx.rw(maps.back())->put("key", "initial");
    }
    REQUIRE(tx.commit() == Result::SUCCESS);
  }
  std::barrier start(static_cast<ptrdiff_t>(count));
  std::vector<std::thread> threads;
  std::atomic<size_t> failures = 0;
  for (size_t i = 0; i < count; ++i)
  {
    threads.emplace_back([&, i]() {
      start.arrive_and_wait();
      for (size_t j = 0; j < rounds; ++j)
      {
        auto tx = store.create_tx();
        tx.rw(maps[i])->put("key", std::to_string(j));
        if (tx.commit() != Result::SUCCESS)
        {
          ++failures;
        }
      }
    });
  }
  for (auto& thread : threads)
  {
    thread.join();
  }
  CHECK(failures == 0);
  CHECK(store.current_version() == 1 + count * rounds);
}

TEST_CASE("KV trace replication failure after apply")
{
  TraceStore store;
  store.set_consensus(std::make_shared<ccf::kv::test::BackupStubConsensus>());
  Map map("trace.replication");
  auto tx = store.create_tx();
  tx.rw(map)->put("key", "local");
  CHECK(tx.commit() == Result::FAIL_NO_REPLICATE);
  CHECK(store.current_version() == 1);
  auto reader = store.create_tx();
  CHECK(reader.ro(map)->get("key") == "local");
}
