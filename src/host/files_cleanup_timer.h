// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/hash_provider.h"
#include "ccf/crypto/sha256_hash.h"
#include "ledger_filenames.h"
#include "snapshots/filenames.h"
#include "timer.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace asynchost
{
  // Pure helper functions for file cleanup, extracted for testability.
  namespace files_cleanup
  {
    // Return type for check_digest_against_read_only_dirs(), distinguishing
    // between a verified digest match, no match, and concurrent deletion.
    enum class DigestCheckResult : std::uint8_t
    {
      match_found, // An identical copy exists in a read-only directory
      no_match, // File exists locally but no matching copy was found
      file_gone // Local file was concurrently deleted (benign)
    };
    static constexpr size_t HASH_READ_CHUNK_SIZE = size_t{64} * 1024; // 64 KB

    // Returns committed ledger chunks in the given directory, sorted ascending
    // by start index. Each entry is (start_idx, path).
    inline std::vector<std::pair<size_t, std::filesystem::path>>
    find_committed_ledger_chunks(const std::filesystem::path& dir)
    {
      namespace fs = std::filesystem;
      std::vector<std::pair<size_t, fs::path>> result;

      for (const auto& entry : fs::directory_iterator(dir))
      {
        if (!entry.is_regular_file())
        {
          continue;
        }

        auto file_name = entry.path().filename().string();

        if (!is_ledger_file_name_committed(file_name))
        {
          continue;
        }

        try
        {
          auto start_idx = get_start_idx_from_file_name(file_name);
          result.emplace_back(start_idx, entry.path());
        }
        catch (const std::exception& e)
        {
          LOG_DEBUG_FMT(
            "Skipping ledger file {} during cleanup: {}", file_name, e.what());
        }
      }

      // Sort ascending by start index (oldest first)
      std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) {
        return a.first < b.first;
      });

      return result;
    }

    // Compute SHA-256 digest of a file by reading it in chunks, without
    // loading the entire file into memory.
    inline std::optional<ccf::crypto::Sha256Hash> hash_file(
      const std::filesystem::path& path)
    {
      std::ifstream f(path, std::ios::binary);
      if (!f)
      {
        return std::nullopt;
      }

      auto hasher = ccf::crypto::make_incremental_sha256();
      std::vector<uint8_t> buf(HASH_READ_CHUNK_SIZE);
      while (f.read(reinterpret_cast<char*>(buf.data()), buf.size()) ||
             f.gcount() > 0)
      {
        hasher->update_hash({buf.data(), static_cast<size_t>(f.gcount())});
        if (f.eof())
        {
          break;
        }
      }

      if (f.bad())
      {
        return std::nullopt;
      }

      return hasher->finalise();
    }

    inline DigestCheckResult check_digest_against_read_only_dirs(
      const std::filesystem::path& local_path,
      const std::vector<std::filesystem::path>& read_only_dirs)
    {
      namespace fs = std::filesystem;

      auto local_hash = hash_file(local_path);
      if (!local_hash.has_value())
      {
        // Distinguish between a concurrent deletion (benign) and a genuine
        // read error on an existing file. Use non-throwing overloads to
        // avoid exceptions from permission issues or broken mounts.
        std::error_code ec;
        const auto exists = fs::exists(local_path, ec);
        if (ec)
        {
          LOG_FAIL_FMT(
            "Failed to query existence of ledger chunk {}: {}. "
            "Skipping deletion.",
            local_path.filename(),
            ec.message());
          return DigestCheckResult::no_match;
        }
        if (!exists)
        {
          LOG_INFO_FMT(
            "Ledger chunk {} no longer exists, skipping",
            local_path.filename());
          return DigestCheckResult::file_gone;
        }

        ec.clear();
        const auto is_reg = fs::is_regular_file(local_path, ec);
        if (ec)
        {
          LOG_FAIL_FMT(
            "Failed to query type of ledger chunk {}: {}. "
            "Skipping deletion.",
            local_path.filename(),
            ec.message());
          return DigestCheckResult::no_match;
        }
        if (!is_reg)
        {
          LOG_INFO_FMT(
            "Ledger chunk {} is no longer a regular file, skipping",
            local_path.filename());
          return DigestCheckResult::file_gone;
        }

        LOG_FAIL_FMT(
          "Ledger chunk {} exists but could not be read, skipping deletion",
          local_path.filename());
        return DigestCheckResult::no_match;
      }

      auto file_name = local_path.filename();

      for (const auto& ro_dir : read_only_dirs)
      {
        auto candidate = ro_dir / file_name;
        std::error_code ec;
        if (
          !fs::exists(candidate, ec) || ec ||
          !fs::is_regular_file(candidate, ec) || ec)
        {
          continue;
        }

        try
        {
          auto ro_hash = hash_file(candidate);
          if (!ro_hash.has_value())
          {
            LOG_DEBUG_FMT(
              "Ledger chunk {} in read-only directory {} could not be read",
              file_name,
              ro_dir);
            continue;
          }
          if (local_hash.value() == ro_hash.value())
          {
            return DigestCheckResult::match_found;
          }

          LOG_FAIL_FMT(
            "Ledger chunk {} found in read-only directory {} but digest "
            "does not match (local: {}, read-only: {}). Skipping deletion.",
            file_name,
            ro_dir,
            local_hash.value().hex_str(),
            ro_hash.value().hex_str());
        }
        catch (const std::exception& e)
        {
          LOG_FAIL_FMT(
            "Failed to read ledger chunk {} from read-only directory {}: "
            "{}. Skipping deletion.",
            file_name,
            ro_dir,
            e.what());
        }
      }

      return DigestCheckResult::no_match;
    }

    // Lists committed snapshots in the given directory. Returns them sorted
    // descending by snapshot index (newest first). Returns nullopt on error
    // to allow callers to distinguish "no snapshots" from "listing failed".
    inline std::optional<std::vector<std::pair<size_t, std::filesystem::path>>>
    find_committed_snapshots(const std::filesystem::path& dir)
    {
      std::vector<std::filesystem::path> directories{dir};
      try
      {
        return snapshots::find_committed_snapshots_in_directories(directories);
      }
      catch (const std::filesystem::filesystem_error& e)
      {
        LOG_FAIL_FMT(
          "Failed to list committed snapshots in {}: {}", dir, e.what());
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "Unexpected error while listing committed snapshots in {}: {}",
          dir,
          e.what());
      }
      return std::nullopt;
    }

    // Returns the sequence number of the newest committed snapshot from a
    // pre-gathered list, or nullopt if the list is empty.
    inline std::optional<size_t> highest_committed_snapshot_seqno(
      const std::vector<std::pair<size_t, std::filesystem::path>>&
        committed_snapshots)
    {
      if (!committed_snapshots.empty())
      {
        // Sorted descending by snapshot index; first is newest
        return committed_snapshots.front().first;
      }
      return std::nullopt;
    }

    inline void cleanup_old_snapshots(
      const std::vector<std::pair<size_t, std::filesystem::path>>&
        committed_snapshots,
      size_t max_retained)
    {
      if (committed_snapshots.size() > max_retained)
      {
        // committed_snapshots is sorted descending by snapshot index, so the
        // oldest are at the end
        for (auto it = committed_snapshots.rbegin();
             it != committed_snapshots.rend() - max_retained;
             ++it)
        {
          const auto& path = it->second;
          LOG_INFO_FMT(
            "Deleting old snapshot {} (retaining {})",
            path.filename(),
            max_retained);
          std::error_code ec;
          std::filesystem::remove(path, ec);
          if (ec)
          {
            LOG_FAIL_FMT(
              "Failed to delete old snapshot {}: {}",
              path.filename(),
              ec.message());
          }
        }
      }
    }

    inline void cleanup_old_ledger_chunks(
      const std::filesystem::path& main_dir,
      const std::vector<std::filesystem::path>& read_only_dirs,
      size_t max_retained,
      std::optional<size_t> snapshot_watermark = std::nullopt)
    {
      std::vector<std::pair<size_t, std::filesystem::path>> committed;
      try
      {
        committed = find_committed_ledger_chunks(main_dir);
      }
      catch (const std::filesystem::filesystem_error& e)
      {
        LOG_FAIL_FMT(
          "Failed to list committed ledger chunks in {}: {}",
          main_dir,
          e.what());
        return;
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "Unexpected error while listing committed ledger chunks in {}: {}",
          main_dir,
          e.what());
        return;
      }

      if (committed.size() <= max_retained)
      {
        return;
      }

      if (snapshot_watermark.has_value())
      {
        LOG_DEBUG_FMT(
          "Ledger chunk cleanup: snapshot watermark is {}",
          snapshot_watermark.value());
      }

      // committed is sorted ascending by start index; the oldest are at the
      // front. Delete from front, keeping the last max_retained entries.
      size_t to_delete = committed.size() - max_retained;
      for (size_t i = 0; i < to_delete; ++i)
      {
        const auto& path = committed[i].second;

        // Never delete a chunk that ends at or after the newest committed
        // snapshot - we must preserve a complete ledger from that snapshot
        // onwards for disaster recovery.
        if (snapshot_watermark.has_value())
        {
          auto end_idx = get_last_idx_from_file_name(path.filename().string());
          if (
            end_idx.has_value() &&
            end_idx.value() >= snapshot_watermark.value())
          {
            LOG_DEBUG_FMT(
              "Keeping ledger chunk {} (end seqno {} >= snapshot "
              "watermark {})",
              path.filename(),
              end_idx.value(),
              snapshot_watermark.value());
            continue;
          }
        }

        auto digest_result =
          check_digest_against_read_only_dirs(path, read_only_dirs);
        if (digest_result == DigestCheckResult::file_gone)
        {
          // File was concurrently deleted — nothing to do.
          continue;
        }
        if (digest_result == DigestCheckResult::no_match)
        {
          LOG_FAIL_FMT(
            "Keeping ledger chunk {} because no matching copy was found "
            "in any read-only ledger directory",
            path.filename());
          continue;
        }

        LOG_INFO_FMT(
          "Deleting old committed ledger chunk {} (retaining {})",
          path.filename(),
          max_retained);
        std::error_code ec;
        std::filesystem::remove(path, ec);
        if (ec)
        {
          if (ec == std::errc::no_such_file_or_directory)
          {
            LOG_INFO_FMT(
              "Ledger chunk {} was already removed", path.filename());
          }
          else
          {
            LOG_FAIL_FMT(
              "Failed to delete committed ledger chunk {}: {}",
              path.filename(),
              ec.message());
          }
        }
      }
    }
  } // namespace files_cleanup

  class FilesCleanupImpl
  {
  private:
    // Snapshot cleanup config
    std::filesystem::path snapshots_dir;
    std::optional<size_t> max_snapshots;

    // Ledger chunk cleanup config
    std::filesystem::path ledger_dir;
    std::vector<std::filesystem::path> read_only_ledger_dirs;
    std::optional<size_t> max_committed_ledger_chunks;

    // Guard against overlapping cleanup tasks. Shared between the impl and
    // any in-flight CleanupWork so the flag remains valid even if the timer
    // is destroyed while a cleanup task is still running on the thread pool.
    std::shared_ptr<std::atomic<bool>> cleanup_in_progress =
      std::make_shared<std::atomic<bool>>(false);

    struct CleanupWork
    {
      std::filesystem::path snapshots_dir;
      std::optional<size_t> max_snapshots;

      std::filesystem::path ledger_dir;
      std::vector<std::filesystem::path> read_only_ledger_dirs;
      std::optional<size_t> max_committed_ledger_chunks;

      std::shared_ptr<std::atomic<bool>> cleanup_in_progress;
    };

    static void on_cleanup_work(uv_work_t* req)
    {
      auto* work = static_cast<CleanupWork*>(req->data);
      LOG_DEBUG_FMT("Files cleanup started");

      // Gather committed snapshots once - used by both snapshot cleanup
      // and as a watermark for ledger chunk cleanup.
      auto committed_snapshots_opt =
        files_cleanup::find_committed_snapshots(work->snapshots_dir);

      if (!committed_snapshots_opt.has_value())
      {
        // Snapshot listing failed. Skip both snapshot and ledger cleanup
        // to avoid deleting ledger chunks without a valid watermark.
        LOG_FAIL_FMT(
          "Skipping all file cleanup because committed snapshot listing "
          "failed");
        return;
      }

      auto& committed_snapshots = committed_snapshots_opt.value();

      if (work->max_snapshots.has_value())
      {
        files_cleanup::cleanup_old_snapshots(
          committed_snapshots, work->max_snapshots.value());
      }
      if (work->max_committed_ledger_chunks.has_value())
      {
        auto snapshot_watermark =
          files_cleanup::highest_committed_snapshot_seqno(committed_snapshots);
        files_cleanup::cleanup_old_ledger_chunks(
          work->ledger_dir,
          work->read_only_ledger_dirs,
          work->max_committed_ledger_chunks.value(),
          snapshot_watermark);
      }
    }

    static void on_cleanup_work_done(uv_work_t* req, int /*status*/)
    {
      auto* work = static_cast<CleanupWork*>(req->data);
      work->cleanup_in_progress->store(false);
      LOG_DEBUG_FMT("Files cleanup completed");
      delete work; // NOLINT(cppcoreguidelines-owning-memory)
      delete req; // NOLINT(cppcoreguidelines-owning-memory)
    }

  public:
    FilesCleanupImpl(
      const std::string& snapshots_dir_,
      std::optional<size_t> max_snapshots_,
      const std::string& ledger_dir_,
      const std::vector<std::string>& read_only_ledger_dirs_,
      std::optional<size_t> max_committed_ledger_chunks_) :
      snapshots_dir(snapshots_dir_),
      max_snapshots(max_snapshots_),
      ledger_dir(ledger_dir_),
      max_committed_ledger_chunks(max_committed_ledger_chunks_)
    {
      for (const auto& d : read_only_ledger_dirs_)
      {
        read_only_ledger_dirs.emplace_back(d);
      }

      if (max_snapshots.has_value() && max_snapshots.value() < 1)
      {
        throw std::logic_error(fmt::format(
          "files_cleanup.max_snapshots must be at least 1, got {}",
          max_snapshots.value()));
      }
      if (
        max_committed_ledger_chunks.has_value() &&
        read_only_ledger_dirs.empty())
      {
        throw std::logic_error(
          "files_cleanup.max_committed_ledger_chunks requires at least one "
          "ledger.read_only_directories entry. Committed ledger chunks are "
          "only deleted after verifying an identical copy exists in a "
          "read-only directory.");
      }
    }

    void on_timer()
    {
      bool expected = false;
      if (!cleanup_in_progress->compare_exchange_strong(expected, true))
      {
        LOG_FAIL_FMT(
          "Skipping files cleanup: previous cleanup task is still running");
        return;
      }

      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      auto* work = new CleanupWork{
        .snapshots_dir = snapshots_dir,
        .max_snapshots = max_snapshots,
        .ledger_dir = ledger_dir,
        .read_only_ledger_dirs = read_only_ledger_dirs,
        .max_committed_ledger_chunks = max_committed_ledger_chunks,
        .cleanup_in_progress = cleanup_in_progress};
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      auto* req = new uv_work_t;
      req->data = work;
      int rc = uv_queue_work(
        uv_default_loop(), req, &on_cleanup_work, &on_cleanup_work_done);
      if (rc < 0)
      {
        LOG_FAIL_FMT("Failed to queue files cleanup work: {}", uv_strerror(rc));
        cleanup_in_progress->store(false);
        delete work; // NOLINT(cppcoreguidelines-owning-memory)
        delete req; // NOLINT(cppcoreguidelines-owning-memory)
      }
    }
  };

  using FilesCleanupTimer = proxy_ptr<Timer<FilesCleanupImpl>>;
}
