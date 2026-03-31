// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/files.h"
#include "ds/internal_logger.h"
#include "host/files_cleanup_timer.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <cstdlib>
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using namespace asynchost;
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

// ---- file_exists_with_matching_digest tests ----

TEST_CASE("file_exists_with_matching_digest: matching copy in read-only dir")
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
  CHECK(file_exists_with_matching_digest(local_path, ro_dirs));

  fs::remove_all(tmp);
}

TEST_CASE("file_exists_with_matching_digest: mismatched digest")
{
  auto tmp = make_unique_test_dir("test_digest_mismatch");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  auto local_path = create_committed_chunk(main_dir, 1, 100, "local content");
  write_file(ro_dir / local_path.filename(), "different content");

  std::vector<fs::path> ro_dirs = {ro_dir};
  CHECK_FALSE(file_exists_with_matching_digest(local_path, ro_dirs));

  fs::remove_all(tmp);
}

TEST_CASE("file_exists_with_matching_digest: no copy in read-only dir")
{
  auto tmp = make_unique_test_dir("test_digest_no_copy");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  auto local_path = create_committed_chunk(main_dir, 1, 100, "content");
  // ro_dir is empty - no matching file

  std::vector<fs::path> ro_dirs = {ro_dir};
  CHECK_FALSE(file_exists_with_matching_digest(local_path, ro_dirs));

  fs::remove_all(tmp);
}

TEST_CASE("file_exists_with_matching_digest: deleted local file returns true")
{
  auto tmp = make_unique_test_dir("test_digest_deleted");
  auto main_dir = tmp / "main";
  auto ro_dir = tmp / "ro";
  fs::create_directories(main_dir);
  fs::create_directories(ro_dir);

  auto local_path = main_dir / "ledger_1-100.committed";
  // Do not create the file - simulate concurrent deletion

  std::vector<fs::path> ro_dirs = {ro_dir};
  CHECK(file_exists_with_matching_digest(local_path, ro_dirs));

  fs::remove_all(tmp);
}

TEST_CASE(
  "file_exists_with_matching_digest: match found in second read-only dir")
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
  CHECK(file_exists_with_matching_digest(local_path, ro_dirs));

  fs::remove_all(tmp);
}

TEST_CASE("file_exists_with_matching_digest: empty read-only dirs list")
{
  auto tmp = make_unique_test_dir("test_digest_no_ro_dirs");
  auto main_dir = tmp / "main";
  fs::create_directories(main_dir);

  auto local_path = create_committed_chunk(main_dir, 1, 100, "content");

  std::vector<fs::path> ro_dirs = {};
  CHECK_FALSE(file_exists_with_matching_digest(local_path, ro_dirs));

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

// ---- ledger_filenames.h tests ----

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
