// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/files.h"
#include "ds/internal_logger.h"
#include "host/files_cleanup_timer.h"
#include "ledger/filenames.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <cstdlib>
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <utility>

namespace fs = std::filesystem;
using namespace asynchost;
using namespace ccf::ledger;
using namespace asynchost::files_cleanup;

// Creates a unique temporary directory using mkdtemp to avoid cross-test
// interference when tests run in parallel or a prior run left files behind.
static fs::path make_unique_test_dir(const std::string& prefix)
{
  auto pattern = (fs::temp_directory_path() / (prefix + "_XXXXXX")).string();
  auto* result = mkdtemp(pattern.data());
  REQUIRE(result != nullptr);
  return fs::path(result);
}

static void write_file(const fs::path& path, const std::string& content)
{
  std::ofstream f(path, std::ios::binary);
  REQUIRE(f.good());
  f << content;
}

static fs::path create_committed_chunk(
  const fs::path& dir,
  size_t start_idx,
  size_t end_idx,
  const std::string& content = "data")
{
  auto name = fmt::format("ledger_{}-{}.committed", start_idx, end_idx);
  auto path = dir / name;
  write_file(path, content);
  return path;
}

class ScopedCleanupLogger
{
  class Logger : public ccf::logger::AbstractLogger
  {
    ScopedCleanupLogger& owner;

  public:
    Logger(ScopedCleanupLogger& owner_) : owner(owner_) {}

    void write(const ccf::logger::LogLine& line) override
    {
      owner.messages.push_back(line.msg);
      if (owner.on_log)
      {
        owner.on_log(line.msg);
      }
    }
  };

  const ccf::LoggerLevel previous_level = ccf::logger::config::level();
  const std::chrono::microseconds previous_max_time =
    ccf::ds::TimeBoundLogger::default_max_time;
  std::vector<std::unique_ptr<ccf::logger::AbstractLogger>> previous_loggers;

public:
  std::vector<std::string> messages;
  std::function<void(const std::string&)> on_log;

  ScopedCleanupLogger() :
    previous_loggers(std::exchange(ccf::logger::config::loggers(), {}))
  {
    ccf::logger::config::loggers().push_back(std::make_unique<Logger>(*this));
    ccf::logger::config::level() = ccf::LoggerLevel::TRACE;
    // Emit every hash open/read scope without timing-dependent assertions.
    ccf::ds::TimeBoundLogger::default_max_time = std::chrono::microseconds{-1};
  }

  ScopedCleanupLogger(const ScopedCleanupLogger&) = delete;
  ScopedCleanupLogger& operator=(const ScopedCleanupLogger&) = delete;

  ~ScopedCleanupLogger()
  {
    ccf::logger::config::loggers() = std::move(previous_loggers);
    ccf::logger::config::level() = previous_level;
    ccf::ds::TimeBoundLogger::default_max_time = previous_max_time;
  }

  size_t count(const std::string& message) const
  {
    return std::count_if(
      messages.begin(), messages.end(), [&](const auto& logged) {
        return logged.contains(message);
      });
  }

  void check_hash_count(const fs::path& path, size_t expected) const
  {
    CHECK(
      count(fmt::format("Hashing file - ifstream open({})", path)) == expected);
    CHECK(count(fmt::format("Hashing file - read loop({})", path)) == expected);
  }
};

// ---- find_committed_ledger_chunks tests ----

TEST_CASE("find_committed_ledger_chunks: empty directory")
{
  auto tmp = make_unique_test_dir("test_cleanup_empty");

  auto result = find_committed_ledger_chunks(tmp);
  CHECK(result.empty());

  fs::remove_all(tmp);
}

TEST_CASE(
  "find_committed_ledger_chunks: returns only committed chunks sorted "
  "ascending")
{
  auto tmp = make_unique_test_dir("test_cleanup_sorted");

  // Create committed chunks in non-sorted order
  create_committed_chunk(tmp, 300, 400);
  create_committed_chunk(tmp, 100, 200);
  create_committed_chunk(tmp, 200, 300);

  auto result = find_committed_ledger_chunks(tmp);
  REQUIRE(result.size() == 3);
  CHECK(result[0].first == 100);
  CHECK(result[1].first == 200);
  CHECK(result[2].first == 300);

  fs::remove_all(tmp);
}

TEST_CASE("find_committed_ledger_chunks: skips non-committed and special files")
{
  auto tmp = make_unique_test_dir("test_cleanup_skip");

  // Committed chunk (should be included)
  create_committed_chunk(tmp, 1, 100);

  // Uncommitted file (no .committed suffix)
  write_file(tmp / "ledger_101", "data");

  // Recovery file
  write_file(tmp / "ledger_1-100.committed.recovery", "data");

  // Ignored file
  write_file(tmp / "ledger_1-100.committed.ignored", "data");

  // Subdirectory
  fs::create_directories(tmp / "subdir");

  // Non-ledger file
  write_file(tmp / "random_file.txt", "data");

  auto result = find_committed_ledger_chunks(tmp);
  REQUIRE(result.size() == 1);
  CHECK(result[0].first == 1);

  fs::remove_all(tmp);
}

TEST_CASE("find_committed_ledger_chunks: nonexistent directory throws")
{
  auto tmp = make_unique_test_dir("test_cleanup_nonexistent");
  fs::remove_all(tmp); // mkdtemp creates it; remove so we test a missing dir

  CHECK_THROWS_AS(
    find_committed_ledger_chunks(tmp), std::filesystem::filesystem_error);
}

// ---- hash_file tests ----

TEST_CASE("hash_file: normal file returns a hash")
{
  auto tmp = make_unique_test_dir("test_hash_normal");
  auto path = tmp / "test_file";
  write_file(path, "hello world");

  auto result = hash_file(path);
  REQUIRE(result.has_value());

  // Hash same content again - should be deterministic
  auto result2 = hash_file(path);
  REQUIRE(result2.has_value());
  CHECK(result.value() == result2.value());

  fs::remove_all(tmp);
}

TEST_CASE("hash_file: different content produces different hash")
{
  auto tmp = make_unique_test_dir("test_hash_different");

  auto path_a = tmp / "file_a";
  auto path_b = tmp / "file_b";
  write_file(path_a, "content A");
  write_file(path_b, "content B");

  auto hash_a = hash_file(path_a);
  auto hash_b = hash_file(path_b);
  REQUIRE(hash_a.has_value());
  REQUIRE(hash_b.has_value());
  CHECK(hash_a.value() != hash_b.value());

  fs::remove_all(tmp);
}

TEST_CASE("hash_file: empty file returns a hash")
{
  auto tmp = make_unique_test_dir("test_hash_empty");
  auto path = tmp / "empty_file";
  write_file(path, "");

  auto result = hash_file(path);
  REQUIRE(result.has_value());

  fs::remove_all(tmp);
}

TEST_CASE("hash_file: nonexistent file returns nullopt")
{
  auto tmp = make_unique_test_dir("test_hash_nosuch");
  auto path = tmp / "no_such_file";
  // path doesn't exist within the unique dir

  auto result = hash_file(path);
  CHECK_FALSE(result.has_value());

  fs::remove_all(tmp);
}

// ---- check_digest_against_read_only_dirs tests ----

TEST_CASE("check_digest_against_read_only_dirs: matching copy in read-only dir")
{
  auto tmp = make_unique_test_dir("test_digest_match");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  auto local_path =
    create_committed_chunk(main_dir, 1, 100, "identical content");
  // Copy to read-only dir with same name and content
  write_file(ro_dir / local_path.filename(), "identical content");

  std::vector<fs::path> ro_dirs = {ro_dir};
  CHECK(
    check_digest_against_read_only_dirs(local_path, ro_dirs) ==
    DigestCheckResult::match_found);

  fs::remove_all(tmp);
}

TEST_CASE("check_digest_against_read_only_dirs: mismatched digest")
{
  auto tmp = make_unique_test_dir("test_digest_mismatch");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  auto local_path = create_committed_chunk(main_dir, 1, 100, "local content");
  write_file(ro_dir / local_path.filename(), "different content");

  std::vector<fs::path> ro_dirs = {ro_dir};
  CHECK(
    check_digest_against_read_only_dirs(local_path, ro_dirs) ==
    DigestCheckResult::no_match);

  fs::remove_all(tmp);
}

TEST_CASE("check_digest_against_read_only_dirs: no copy in read-only dir")
{
  auto tmp = make_unique_test_dir("test_digest_no_copy");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  auto local_path = create_committed_chunk(main_dir, 1, 100, "content");
  // ro_dir is empty - no matching file

  std::vector<fs::path> ro_dirs = {ro_dir};
  ScopedCleanupLogger logs;
  CHECK(
    check_digest_against_read_only_dirs(local_path, ro_dirs) ==
    DigestCheckResult::no_match);
  logs.check_hash_count(local_path, 0);

  fs::remove_all(tmp);
}

TEST_CASE(
  "check_digest_against_read_only_dirs: deleted local file returns file_gone")
{
  auto tmp = make_unique_test_dir("test_digest_deleted");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  auto local_path = main_dir / "ledger_1-100.committed";
  // Do not create the file - simulate concurrent deletion

  std::vector<fs::path> ro_dirs = {ro_dir};
  CHECK(
    check_digest_against_read_only_dirs(local_path, ro_dirs) ==
    DigestCheckResult::file_gone);

  fs::remove_all(tmp);
}

TEST_CASE(
  "check_digest_against_read_only_dirs: match found in second read-only dir")
{
  auto tmp = make_unique_test_dir("test_digest_multi_ro");
  auto main_dir = tmp / "main";
  auto ro_dir1 = tmp / "ro1";
  auto ro_dir2 = tmp / "ro2";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir1);
  fs::create_directories(ro_dir2);

  auto local_path = create_committed_chunk(main_dir, 1, 100, "my data");
  // Only in second read-only dir
  write_file(ro_dir2 / local_path.filename(), "my data");

  std::vector<fs::path> ro_dirs = {ro_dir1, ro_dir2};
  CHECK(
    check_digest_against_read_only_dirs(local_path, ro_dirs) ==
    DigestCheckResult::match_found);

  fs::remove_all(tmp);
}

TEST_CASE("check_digest_against_read_only_dirs: empty read-only dirs list")
{
  auto tmp = make_unique_test_dir("test_digest_no_ro_dirs");
  auto main_dir = tmp / "main";
  fs::create_directories(main_dir);

  auto local_path = create_committed_chunk(main_dir, 1, 100, "content");

  std::vector<fs::path> ro_dirs = {};
  ScopedCleanupLogger logs;
  CHECK(
    check_digest_against_read_only_dirs(local_path, ro_dirs) ==
    DigestCheckResult::no_match);
  logs.check_hash_count(local_path, 0);

  fs::remove_all(tmp);
}

TEST_CASE(
  "check_digest_against_read_only_dirs: nonregular candidates skip source "
  "hashing")
{
  auto tmp = make_unique_test_dir("test_digest_nonregular_copy");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);
  auto local_path = create_committed_chunk(main_dir, 1, 100, "content");
  auto candidate = ro_dir / local_path.filename();

  SUBCASE("directory")
  {
    fs::create_directory(candidate);
  }
  SUBCASE("dangling symlink")
  {
    fs::create_symlink(tmp / "missing", candidate);
  }
  SUBCASE("read-only path is not a directory")
  {
    fs::remove(ro_dir);
    write_file(ro_dir, "not a directory");
  }

  ScopedCleanupLogger logs;
  CHECK(
    check_digest_against_read_only_dirs(local_path, {ro_dir}) ==
    DigestCheckResult::no_match);
  logs.check_hash_count(local_path, 0);

  fs::remove_all(tmp);
}

TEST_CASE(
  "check_digest_against_read_only_dirs: metadata errors remain distinct from "
  "missing files")
{
  auto tmp = make_unique_test_dir("test_digest_metadata_error");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);
  auto local_path = main_dir / "ledger_1-100.committed";

  ScopedCleanupLogger logs;
  SUBCASE("candidate query fails")
  {
    write_file(local_path, "content");
    auto candidate = ro_dir / local_path.filename();
    fs::create_symlink(candidate.filename(), candidate);
    CHECK(
      check_digest_against_read_only_dirs(local_path, {ro_dir}) ==
      DigestCheckResult::no_match);
    logs.check_hash_count(local_path, 0);
    CHECK(logs.count("Failed to query ledger chunk") == 1);
  }
  SUBCASE("local query fails without a candidate")
  {
    fs::create_symlink(local_path.filename(), local_path);
    CHECK(
      check_digest_against_read_only_dirs(local_path, {ro_dir}) ==
      DigestCheckResult::no_match);
    CHECK(logs.count("Failed to query status of ledger chunk") == 1);
  }
  SUBCASE("local path is no longer regular without a candidate")
  {
    fs::create_directory(local_path);
    CHECK(
      check_digest_against_read_only_dirs(local_path, {ro_dir}) ==
      DigestCheckResult::file_gone);
    logs.check_hash_count(local_path, 0);
    CHECK(logs.count("is no longer a regular file") == 1);
  }

  fs::remove_all(tmp);
}

TEST_CASE(
  "check_digest_against_read_only_dirs: verifies complete contents and hashes "
  "source once")
{
  auto tmp = make_unique_test_dir("test_digest_full_contents");
  auto main_dir = tmp / "main";
  auto ro_dir1 = tmp / "ro1";
  auto ro_dir2 = tmp / "ro2";
  auto ro_dir3 = tmp / "ro3";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir1);
  fs::create_directories(ro_dir2);
  fs::create_directories(ro_dir3);

  std::string content(2 * HASH_READ_CHUNK_SIZE + 1, 'a');
  auto local_path = create_committed_chunk(main_dir, 1, 100, content);
  fs::create_directory(ro_dir1 / local_path.filename());
  auto mismatch = content;
  mismatch.back() = 'b';
  write_file(ro_dir2 / local_path.filename(), mismatch);
  write_file(ro_dir3 / local_path.filename(), content);

  ScopedCleanupLogger logs;
  CHECK(
    check_digest_against_read_only_dirs(
      local_path, {ro_dir1, ro_dir2, ro_dir3}) ==
    DigestCheckResult::match_found);
  logs.check_hash_count(local_path, 1);
  logs.check_hash_count(ro_dir1 / local_path.filename(), 0);
  logs.check_hash_count(ro_dir2 / local_path.filename(), 1);
  logs.check_hash_count(ro_dir3 / local_path.filename(), 1);
  CHECK(logs.count("but digest does not match") == 1);

  cleanup_old_ledger_chunks(main_dir, {ro_dir1, ro_dir2}, 0);
  CHECK(fs::exists(local_path));

  fs::remove_all(tmp);
}

TEST_CASE("check_digest_against_read_only_dirs: read errors prevent deletion")
{
  auto tmp = make_unique_test_dir("test_digest_read_error");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);
  auto local_path = main_dir / "ledger_1-100.committed";
  auto candidate = ro_dir / local_path.filename();
  ScopedCleanupLogger logs;

  // This regular procfs file fails reads at offset zero.
  SUBCASE("unreadable source without a candidate is not opened")
  {
    fs::create_symlink("/proc/self/mem", local_path);
    REQUIRE(fs::is_regular_file(local_path));
    CHECK(
      check_digest_against_read_only_dirs(local_path, {ro_dir}) ==
      DigestCheckResult::no_match);
    logs.check_hash_count(local_path, 0);
    CHECK(logs.count("exists but could not be read") == 0);
  }
  SUBCASE("unreadable source with a candidate reports a read error")
  {
    fs::create_symlink("/proc/self/mem", local_path);
    REQUIRE(fs::is_regular_file(local_path));
    write_file(candidate, "content");
    CHECK(
      check_digest_against_read_only_dirs(local_path, {ro_dir}) ==
      DigestCheckResult::no_match);
    CHECK(logs.count("exists but could not be read") == 1);
  }
  SUBCASE("unreadable candidate does not approve deletion")
  {
    write_file(local_path, "content");
    fs::create_symlink("/proc/self/mem", candidate);
    REQUIRE(fs::is_regular_file(candidate));
    CHECK(
      check_digest_against_read_only_dirs(local_path, {ro_dir}) ==
      DigestCheckResult::no_match);
    CHECK(logs.count("could not be read") == 1);
  }

  CHECK(fs::exists(local_path));
  fs::remove_all(tmp);
}

TEST_CASE(
  "check_digest_against_read_only_dirs: candidate disappears after preflight")
{
  auto tmp = make_unique_test_dir("test_digest_candidate_disappears");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);
  auto local_path = create_committed_chunk(main_dir, 1, 100, "content");
  auto candidate = ro_dir / local_path.filename();
  write_file(candidate, "content");

  ScopedCleanupLogger logs;
  bool removed = false;
  std::error_code removal_error;
  const auto local_open =
    fmt::format("Hashing file - ifstream open({})", local_path);
  logs.on_log = [&](const std::string& message) {
    if (message.contains(local_open))
    {
      removed = fs::remove(candidate, removal_error);
    }
  };

  CHECK(
    check_digest_against_read_only_dirs(local_path, {ro_dir}) ==
    DigestCheckResult::no_match);
  REQUIRE_FALSE(removal_error);
  REQUIRE(removed);
  CHECK(logs.count("could not be read") == 1);
  logs.on_log = {};

  cleanup_old_ledger_chunks(main_dir, {ro_dir}, 0);
  CHECK(fs::exists(local_path));
  logs.check_hash_count(local_path, 1);

  fs::remove_all(tmp);
}

// ---- cleanup_old_ledger_chunks tests ----

TEST_CASE("cleanup_old_ledger_chunks: empty directory is a no-op")
{
  auto tmp = make_unique_test_dir("test_ledger_cleanup_empty");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  std::vector<fs::path> ro_dirs = {ro_dir};
  // Should not throw or crash
  cleanup_old_ledger_chunks(main_dir, ro_dirs, 3);

  fs::remove_all(tmp);
}

TEST_CASE("cleanup_old_ledger_chunks: deletes oldest chunks when backed up")
{
  auto tmp = make_unique_test_dir("test_ledger_cleanup_delete");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  // Create 5 committed chunks
  for (size_t i = 0; i < 5; ++i)
  {
    auto start = i * 100 + 1;
    auto end = (i + 1) * 100;
    auto content = fmt::format("chunk_{}", i);
    create_committed_chunk(main_dir, start, end, content);
    // Also copy to read-only dir
    create_committed_chunk(ro_dir, start, end, content);
  }

  std::vector<fs::path> ro_dirs = {ro_dir};
  // Keep only 2 - should delete 3 oldest
  cleanup_old_ledger_chunks(main_dir, ro_dirs, 2);

  auto remaining = find_committed_ledger_chunks(main_dir);
  REQUIRE(remaining.size() == 2);
  // Retained should be the newest (start_idx 301 and 401)
  CHECK(remaining[0].first == 301);
  CHECK(remaining[1].first == 401);

  fs::remove_all(tmp);
}

TEST_CASE("cleanup_old_ledger_chunks: keeps chunks not backed up in read-only")
{
  auto tmp = make_unique_test_dir("test_ledger_cleanup_keep");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  // Create 4 committed chunks
  for (size_t i = 0; i < 4; ++i)
  {
    auto start = i * 100 + 1;
    auto end = (i + 1) * 100;
    create_committed_chunk(main_dir, start, end, fmt::format("chunk_{}", i));
  }

  // Only back up chunk 0 (oldest) to read-only dir
  create_committed_chunk(ro_dir, 1, 100, "chunk_0");

  std::vector<fs::path> ro_dirs = {ro_dir};
  // Keep 2 - should try to delete 2 oldest, but only chunk 0 is backed up
  cleanup_old_ledger_chunks(main_dir, ro_dirs, 2);

  auto remaining = find_committed_ledger_chunks(main_dir);
  // Chunk 0 deleted (backed up), chunk 1 kept (not backed up),
  // chunks 2-3 kept (within retention)
  REQUIRE(remaining.size() == 3);
  CHECK(remaining[0].first == 101); // chunk 1 (not backed up, kept)
  CHECK(remaining[1].first == 201); // chunk 2
  CHECK(remaining[2].first == 301); // chunk 3

  fs::remove_all(tmp);
}

TEST_CASE("cleanup_old_ledger_chunks: max_retained = 0 deletes all backed up")
{
  auto tmp = make_unique_test_dir("test_ledger_cleanup_zero");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  // Create 3 committed chunks, all backed up
  for (size_t i = 0; i < 3; ++i)
  {
    auto start = i * 100 + 1;
    auto end = (i + 1) * 100;
    auto content = fmt::format("chunk_{}", i);
    create_committed_chunk(main_dir, start, end, content);
    create_committed_chunk(ro_dir, start, end, content);
  }

  std::vector<fs::path> ro_dirs = {ro_dir};
  cleanup_old_ledger_chunks(main_dir, ro_dirs, 0);

  auto remaining = find_committed_ledger_chunks(main_dir);
  CHECK(remaining.empty());

  fs::remove_all(tmp);
}

TEST_CASE("cleanup_old_ledger_chunks: count within limit is a no-op")
{
  auto tmp = make_unique_test_dir("test_ledger_cleanup_within");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  // Create 2 committed chunks
  create_committed_chunk(main_dir, 1, 100, "a");
  create_committed_chunk(main_dir, 101, 200, "b");

  std::vector<fs::path> ro_dirs = {ro_dir};
  // max_retained = 5, only 2 chunks - no deletions
  cleanup_old_ledger_chunks(main_dir, ro_dirs, 5);

  auto remaining = find_committed_ledger_chunks(main_dir);
  CHECK(remaining.size() == 2);

  fs::remove_all(tmp);
}

TEST_CASE("cleanup_old_ledger_chunks: digest mismatch prevents deletion")
{
  auto tmp = make_unique_test_dir("test_ledger_cleanup_mismatch");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  // Create 3 committed chunks
  for (size_t i = 0; i < 3; ++i)
  {
    auto start = i * 100 + 1;
    auto end = (i + 1) * 100;
    create_committed_chunk(main_dir, start, end, fmt::format("chunk_{}", i));
  }

  // Back up chunk 0 with corrupted content
  create_committed_chunk(ro_dir, 1, 100, "CORRUPTED");

  std::vector<fs::path> ro_dirs = {ro_dir};
  cleanup_old_ledger_chunks(main_dir, ro_dirs, 1);

  auto remaining = find_committed_ledger_chunks(main_dir);
  // chunk 0 and 1 should both be kept (0: digest mismatch, 1: not backed up)
  // chunk 2 is within retention limit
  REQUIRE(remaining.size() == 3);

  fs::remove_all(tmp);
}

// ---- find_committed_snapshots / highest_committed_snapshot_seqno tests ----

static fs::path create_committed_snapshot(
  const fs::path& dir, size_t seqno, size_t evidence_seqno)
{
  auto name = fmt::format("snapshot_{}_{}.committed", seqno, evidence_seqno);
  auto path = dir / name;
  write_file(path, fmt::format("snapshot_data_{}", seqno));
  return path;
}

TEST_CASE("highest_committed_snapshot_seqno: returns newest snapshot seqno")
{
  auto tmp = make_unique_test_dir("test_snap_watermark");

  create_committed_snapshot(tmp, 100, 105);
  create_committed_snapshot(tmp, 300, 310);
  create_committed_snapshot(tmp, 200, 210);

  auto committed_opt = find_committed_snapshots(tmp);
  REQUIRE(committed_opt.has_value());
  auto& committed = committed_opt.value();
  auto result = highest_committed_snapshot_seqno(committed);
  REQUIRE(result.has_value());
  CHECK(result.value() == 300);

  fs::remove_all(tmp);
}

TEST_CASE(
  "highest_committed_snapshot_seqno: returns nullopt for empty directory")
{
  auto tmp = make_unique_test_dir("test_snap_watermark_empty");

  auto committed_opt = find_committed_snapshots(tmp);
  REQUIRE(committed_opt.has_value());
  auto& committed = committed_opt.value();
  auto result = highest_committed_snapshot_seqno(committed);
  CHECK_FALSE(result.has_value());

  fs::remove_all(tmp);
}

TEST_CASE("highest_committed_snapshot_seqno: ignores uncommitted snapshots")
{
  auto tmp = make_unique_test_dir("test_snap_watermark_uncommitted");

  // Uncommitted snapshot (no .committed suffix)
  write_file(tmp / "snapshot_500_510", "data");
  create_committed_snapshot(tmp, 200, 210);

  auto committed_opt = find_committed_snapshots(tmp);
  REQUIRE(committed_opt.has_value());
  auto& committed = committed_opt.value();
  auto result = highest_committed_snapshot_seqno(committed);
  REQUIRE(result.has_value());
  CHECK(result.value() == 200);

  fs::remove_all(tmp);
}

// ---- snapshot watermark in cleanup_old_ledger_chunks tests ----

TEST_CASE(
  "cleanup_old_ledger_chunks: watermark prevents deletion of recent chunks")
{
  auto tmp = make_unique_test_dir("test_ledger_watermark");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  // Create 5 committed chunks: 1-100, 101-200, 201-300, 301-400, 401-500
  for (size_t i = 0; i < 5; ++i)
  {
    auto start = i * 100 + 1;
    auto end = (i + 1) * 100;
    auto content = fmt::format("chunk_{}", i);
    create_committed_chunk(main_dir, start, end, content);
    create_committed_chunk(ro_dir, start, end, content);
  }

  std::vector<fs::path> ro_dirs = {ro_dir};
  // Keep only 1, but snapshot watermark at 250 protects chunks ending >= 250
  // Chunks 1-100 and 101-200 end below 250, so eligible for deletion
  // Chunks 201-300, 301-400, 401-500 end >= 250, protected
  cleanup_old_ledger_chunks(main_dir, ro_dirs, 1, 250);

  auto remaining = find_committed_ledger_chunks(main_dir);
  // 1-100 deleted, 101-200 deleted, 201-300 kept (watermark), 301-400 kept,
  // 401-500 kept (within retention)
  REQUIRE(remaining.size() == 3);
  CHECK(remaining[0].first == 201);
  CHECK(remaining[1].first == 301);
  CHECK(remaining[2].first == 401);

  fs::remove_all(tmp);
}

TEST_CASE(
  "cleanup_old_ledger_chunks: watermark at exact chunk boundary protects it")
{
  auto tmp = make_unique_test_dir("test_ledger_watermark_exact");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  for (size_t i = 0; i < 4; ++i)
  {
    auto start = i * 100 + 1;
    auto end = (i + 1) * 100;
    auto content = fmt::format("chunk_{}", i);
    create_committed_chunk(main_dir, start, end, content);
    create_committed_chunk(ro_dir, start, end, content);
  }

  std::vector<fs::path> ro_dirs = {ro_dir};
  // Watermark at 200 (exactly matching end of chunk 101-200)
  // Chunk 1-100 ends at 100 < 200, eligible for deletion
  // Chunk 101-200 ends at 200 >= 200, protected
  cleanup_old_ledger_chunks(main_dir, ro_dirs, 1, 200);

  auto remaining = find_committed_ledger_chunks(main_dir);
  REQUIRE(remaining.size() == 3);
  CHECK(remaining[0].first == 101); // kept by watermark
  CHECK(remaining[1].first == 201);
  CHECK(remaining[2].first == 301); // kept by retention

  fs::remove_all(tmp);
}

TEST_CASE("cleanup_old_ledger_chunks: no watermark allows normal deletion")
{
  auto tmp = make_unique_test_dir("test_ledger_no_watermark");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  for (size_t i = 0; i < 4; ++i)
  {
    auto start = i * 100 + 1;
    auto end = (i + 1) * 100;
    auto content = fmt::format("chunk_{}", i);
    create_committed_chunk(main_dir, start, end, content);
    create_committed_chunk(ro_dir, start, end, content);
  }

  std::vector<fs::path> ro_dirs = {ro_dir};
  // No watermark - all backed-up chunks eligible
  cleanup_old_ledger_chunks(main_dir, ro_dirs, 1, std::nullopt);

  auto remaining = find_committed_ledger_chunks(main_dir);
  REQUIRE(remaining.size() == 1);
  CHECK(remaining[0].first == 301);

  fs::remove_all(tmp);
}

// ---- FilesCleanupImpl constructor tests ----

TEST_CASE(
  "FilesCleanupImpl: constructor rejects ledger cleanup without read-only dirs")
{
  CHECK_THROWS_AS(
    FilesCleanupImpl(
      "/tmp/snapshots",
      std::nullopt,
      "/tmp/ledger",
      {}, // no read-only dirs
      3 // but max_committed_ledger_chunks is set
      ),
    std::logic_error);
}

TEST_CASE(
  "FilesCleanupImpl: constructor accepts ledger cleanup with read-only dirs")
{
  CHECK_NOTHROW(FilesCleanupImpl(
    "/tmp/snapshots", std::nullopt, "/tmp/ledger", {"/tmp/ro"}, 3));
}

TEST_CASE("FilesCleanupImpl: constructor rejects max_snapshots < 1")
{
  CHECK_THROWS_AS(
    FilesCleanupImpl(
      "/tmp/snapshots",
      0, // max_snapshots = 0
      "/tmp/ledger",
      {},
      std::nullopt),
    std::logic_error);
}

TEST_CASE("FilesCleanupImpl: constructor accepts both cleanup options together")
{
  CHECK_NOTHROW(
    FilesCleanupImpl("/tmp/snapshots", 2, "/tmp/ledger", {"/tmp/ro"}, 3));
}

TEST_CASE("FilesCleanupImpl: constructor accepts all nullopt (no cleanup)")
{
  CHECK_NOTHROW(FilesCleanupImpl(
    "/tmp/snapshots", std::nullopt, "/tmp/ledger", {}, std::nullopt));
}

// ---- ledger/filenames.h tests ----

TEST_CASE("get_start_idx_from_file_name: parses start index")
{
  CHECK(get_start_idx_from_file_name("ledger_42-100.committed") == 42);
  CHECK(get_start_idx_from_file_name("ledger_1") == 1);
  CHECK(get_start_idx_from_file_name("ledger_0") == 0);
}

TEST_CASE("get_start_idx_from_file_name: throws on missing delimiter")
{
  CHECK_THROWS_AS(
    get_start_idx_from_file_name("nodelimiter"), std::logic_error);
}

TEST_CASE("get_last_idx_from_file_name: parses last index")
{
  auto result = get_last_idx_from_file_name("ledger_1-100.committed");
  REQUIRE(result.has_value());
  CHECK(result.value() == 100);
}

TEST_CASE("get_last_idx_from_file_name: returns nullopt for uncommitted files")
{
  auto result = get_last_idx_from_file_name("ledger_1");
  CHECK_FALSE(result.has_value());
}

TEST_CASE("is_ledger_file_name_committed: detects committed suffix")
{
  CHECK(is_ledger_file_name_committed("ledger_1-100.committed"));
  CHECK_FALSE(is_ledger_file_name_committed("ledger_1"));
  CHECK_FALSE(is_ledger_file_name_committed("ledger_1-100.committed.recovery"));
  CHECK_FALSE(is_ledger_file_name_committed("ledger_1-100.committed.ignored"));
}

TEST_CASE("committed prefix names contain a strict range")
{
  const auto range = get_ledger_committed_prefix_range_from_file_name(
    "ledger_42-100.committed_prefix");
  REQUIRE(range.has_value());
  CHECK(range->start_idx == 42);
  CHECK(range->end_idx == 100);

  for (const auto* invalid_name :
       {"ledger_0-100.committed_prefix",
        "ledger_42-41.committed_prefix",
        "ledger_42.committed_prefix",
        "ledger_42-100.committed",
        "ledger_42-100-101.committed_prefix",
        "ledger_42x-100.committed_prefix",
        "ledger_042-100.committed_prefix",
        "ledger_+42-100.committed_prefix",
        "ledger_42-100.committed_prefix.ignored",
        "../ledger_42-100.committed_prefix"})
  {
    CHECK_FALSE(get_ledger_committed_prefix_range_from_file_name(invalid_name)
                  .has_value());
  }
}

TEST_CASE("committed prefix names round-trip through their range")
{
  for (const auto& range :
       {CommittedLedgerPrefixRange{.start_idx = 1, .end_idx = 1},
        CommittedLedgerPrefixRange{.start_idx = 42, .end_idx = 100},
        CommittedLedgerPrefixRange{
          .start_idx = std::numeric_limits<size_t>::max(),
          .end_idx = std::numeric_limits<size_t>::max()}})
  {
    const auto name = get_ledger_committed_prefix_file_name(range);
    CHECK(is_ledger_file_name_committed_prefix(name));
    const auto parsed = get_ledger_committed_prefix_range_from_file_name(name);
    REQUIRE(parsed.has_value());
    CHECK(parsed->start_idx == range.start_idx);
    CHECK(parsed->end_idx == range.end_idx);
  }
  CHECK(
    get_ledger_committed_prefix_file_name({.start_idx = 42, .end_idx = 100}) ==
    "ledger_42-100.committed_prefix");
}

TEST_CASE("committed prefix files are ignored by the host ledger")
{
  const auto prefix = "ledger_42-100.committed_prefix";
  CHECK(is_ledger_file_name_committed_prefix(prefix));
  CHECK(is_ledger_file_ignored(prefix));
  CHECK_FALSE(is_ledger_file_name_committed(prefix));
}

TEST_CASE("is_ledger_file_name_recovery: detects recovery suffix")
{
  CHECK(is_ledger_file_name_recovery("ledger_1-100.committed.recovery"));
  CHECK_FALSE(is_ledger_file_name_recovery("ledger_1-100.committed"));
}

TEST_CASE("is_ledger_file_name_ignored: detects ignored suffix")
{
  CHECK(is_ledger_file_name_ignored("ledger_1-100.committed.ignored"));
  CHECK_FALSE(is_ledger_file_name_ignored("ledger_1-100.committed"));
}

int main(int argc, char** argv)
{
  ccf::logger::config::default_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
