// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/hash_provider.h"
#include "ccf/crypto/sha256_hash.h"
#include "ledger_filenames.h"
#include "snapshots/filenames.h"
#include "timer.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace asynchost
{
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

    struct CleanupWork
    {
      std::filesystem::path snapshots_dir;
      std::optional<size_t> max_snapshots;

      std::filesystem::path ledger_dir;
      std::vector<std::filesystem::path> read_only_ledger_dirs;
      std::optional<size_t> max_committed_ledger_chunks;
    };

    static void cleanup_old_snapshots(
      const std::filesystem::path& dir, size_t max_retained)
    {
      std::vector<std::filesystem::path> directories{dir};
      decltype(snapshots::find_committed_snapshots_in_directories(
        directories)) committed;
      try
      {
        committed =
          snapshots::find_committed_snapshots_in_directories(directories);
      }
      catch (const std::filesystem::filesystem_error& e)
      {
        LOG_FAIL_FMT(
          "Failed to list committed snapshots in {}: {}", dir, e.what());
        return;
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "Unexpected error while listing committed snapshots in {}: {}",
          dir,
          e.what());
        return;
      }

      if (committed.size() > max_retained)
      {
        // committed is sorted descending by snapshot index, so the
        // oldest are at the end
        for (auto it = committed.rbegin();
             it != committed.rend() - max_retained;
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

    // Returns committed ledger chunks in the given directory, sorted ascending
    // by start index. Each entry is (start_idx, path).
    static std::vector<std::pair<size_t, std::filesystem::path>>
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

        if (
          !is_ledger_file_name_committed(file_name) ||
          is_ledger_file_name_ignored(file_name) ||
          is_ledger_file_name_recovery(file_name))
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

    static constexpr size_t HASH_READ_CHUNK_SIZE = 64 * 1024; // 64 KB

    // Compute SHA-256 digest of a file by reading it in chunks, without
    // loading the entire file into memory.
    static std::optional<ccf::crypto::Sha256Hash> hash_file(
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

    static bool file_exists_with_matching_digest(
      const std::filesystem::path& local_path,
      const std::vector<std::filesystem::path>& read_only_dirs)
    {
      namespace fs = std::filesystem;

      auto local_hash = hash_file(local_path);
      if (!local_hash.has_value())
      {
        LOG_INFO_FMT(
          "Ledger chunk {} no longer exists or could not be read, skipping",
          local_path.filename());
        return false;
      }

      auto file_name = local_path.filename();

      for (const auto& ro_dir : read_only_dirs)
      {
        auto candidate = ro_dir / file_name;
        if (!fs::exists(candidate) || !fs::is_regular_file(candidate))
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
            return true;
          }
          else
          {
            LOG_FAIL_FMT(
              "Ledger chunk {} found in read-only directory {} but digest "
              "does not match (local: {}, read-only: {}). Skipping deletion.",
              file_name,
              ro_dir,
              local_hash.value().hex_str(),
              ro_hash.value().hex_str());
          }
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

      return false;
    }

    static void cleanup_old_ledger_chunks(
      const std::filesystem::path& main_dir,
      const std::vector<std::filesystem::path>& read_only_dirs,
      size_t max_retained)
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

      // committed is sorted ascending by start index; the oldest are at the
      // front. Delete from front, keeping the last max_retained entries.
      size_t to_delete = committed.size() - max_retained;
      for (size_t i = 0; i < to_delete; ++i)
      {
        const auto& path = committed[i].second;

        if (!file_exists_with_matching_digest(path, read_only_dirs))
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
          LOG_FAIL_FMT(
            "Failed to delete committed ledger chunk {}: {}",
            path.filename(),
            ec.message());
        }
      }
    }

    static void on_cleanup_work(uv_work_t* req)
    {
      auto* work = static_cast<CleanupWork*>(req->data);
      if (work->max_snapshots.has_value())
      {
        cleanup_old_snapshots(work->snapshots_dir, work->max_snapshots.value());
      }
      if (work->max_committed_ledger_chunks.has_value())
      {
        cleanup_old_ledger_chunks(
          work->ledger_dir,
          work->read_only_ledger_dirs,
          work->max_committed_ledger_chunks.value());
      }
    }

    static void on_cleanup_work_done(uv_work_t* req, int /*status*/)
    {
      auto* work = static_cast<CleanupWork*>(req->data);
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
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      auto* work = new CleanupWork{
        .snapshots_dir = snapshots_dir,
        .max_snapshots = max_snapshots,
        .ledger_dir = ledger_dir,
        .read_only_ledger_dirs = read_only_ledger_dirs,
        .max_committed_ledger_chunks = max_committed_ledger_chunks};
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      auto* req = new uv_work_t;
      req->data = work;
      int rc = uv_queue_work(
        uv_default_loop(), req, &on_cleanup_work, &on_cleanup_work_done);
      if (rc < 0)
      {
        LOG_FAIL_FMT("Failed to queue files cleanup work: {}", uv_strerror(rc));
        delete work; // NOLINT(cppcoreguidelines-owning-memory)
        delete req; // NOLINT(cppcoreguidelines-owning-memory)
      }
    }
  };

  using FilesCleanupTimer = proxy_ptr<Timer<FilesCleanupImpl>>;
}
