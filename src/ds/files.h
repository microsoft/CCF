// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <glob.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <fmt/ostream.h>

namespace files
{
  namespace fs = std::filesystem;
  static constexpr mode_t private_file_permissions = S_IRUSR | S_IWUSR;

  static int open_fd(
    const fs::path& file,
    int flags,
    mode_t permissions = private_file_permissions)
  {
    return ::open(file.c_str(), flags, permissions);
  }

  static FILE* open_file(
    const fs::path& file,
    int flags,
    const char* mode,
    mode_t permissions = private_file_permissions)
  {
    const auto fd = open_fd(file, flags, permissions);
    if (fd == -1)
    {
      return nullptr;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    auto* f = fdopen(fd, mode);
    if (f == nullptr)
    {
      auto saved_errno = errno;
      // Preserve the original fdopen() failure when it set errno, and only
      // fall back to close()'s errno if fdopen() did not.
      if (close(fd) != 0 && saved_errno == 0)
      {
        saved_errno = errno;
      }
      errno = saved_errno != 0 ? saved_errno : EIO;
    }

    return f;
  }

  /**
   * @brief Checks if a path exists
   *
   * @param file file to check
   * @return true if the file exists.
   */
  static bool exists(const std::string& file)
  {
    std::ifstream f(file.c_str());
    return f.good();
  }

  /**
   * @brief Tries to read a file as byte vector.
   *
   * @param file the path
   * @param optional determines behaviour in the case where the file does not
   * exist. If true, an empty vector is returned. If false, the process exits
   * @return vector<uint8_t> the file contents as bytes.
   */
  static std::vector<uint8_t> slurp(
    const std::string& file, bool optional = false)
  {
    std::ifstream f(file, std::ios::binary | std::ios::ate);

    if (!f)
    {
      if (optional)
      {
        return {};
      }
      std::cerr << "Could not open file " << file << std::endl;
      exit(-1); // NOLINT(concurrency-mt-unsafe)
    }

    auto size = f.tellg();
    f.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(size);
    f.read(reinterpret_cast<char*>(data.data()), size);

    if (!optional && !f)
    {
      std::cerr << "Could not read file " << file << std::endl;
      exit(-1); // NOLINT(concurrency-mt-unsafe)
    }
    return data;
  }

  /**
   * @brief Tries to read a file as string
   *
   * @param file the path
   * @param optional determines behaviour in the case where the file does not
   * exist. If true, an empty vector is returned. If false, the process exits
   * @return std::string the file contents as a string.
   */
  static std::string slurp_string(
    const std::string& file, bool optional = false)
  {
    auto v = slurp(file, optional);
    return {v.begin(), v.end()};
  }

  static std::optional<std::string> try_slurp_string(const std::string& file)
  {
    if (!fs::exists(file))
    {
      return std::nullopt;
    }
    return files::slurp_string(file);
  }

  /**
   * @brief Tries to read a file as JSON.
   *
   * @param file the path
   * @param optional determines behaviour in the case where the file does not
   * exist. If true, an empty JSON object is returned. If false, the process
   * exits
   * @return nlohmann::json JSON object containing the parsed file
   */
  static nlohmann::json slurp_json(
    const std::string& file, bool optional = false)
  {
    auto v = slurp(file, optional);
    if (v.empty())
    {
      return {};
    }

    return nlohmann::json::parse(v.begin(), v.end());
  }

  static void dump_bytes(
    std::span<const std::byte> data, const fs::path& file)
  {
    auto* f = open_file(file, O_WRONLY | O_CREAT | O_TRUNC, "wb");
    if (f == nullptr)
    {
      throw std::logic_error(fmt::format(
        "Failed to open file {} for writing: {}",
        file.string(),
        std::strerror(errno))); // NOLINT(concurrency-mt-unsafe)
    }

    const auto bytes_written =
      fwrite(data.data(), sizeof(std::byte), data.size(), f);
    const auto write_errno = errno;
    // Preserve any write-side errno before fclose() can overwrite it.
    errno = 0;
    const auto close_rc = fclose(f);
    const auto close_errno = errno;
    if (bytes_written != data.size() || close_rc != 0)
    {
      if (bytes_written != data.size())
      {
        errno = write_errno != 0 ? write_errno : EIO;
      }
      else
      {
        errno = close_errno != 0 ? close_errno : EIO;
      }
      throw std::logic_error(fmt::format(
        "Failed to write to file {}: {}",
        file.string(),
        std::strerror(errno))); // NOLINT(concurrency-mt-unsafe)
    }
  }

  /**
   * @brief Writes the content of a byte span to a file
   *
   * @param data bytes to write
   * @param file the path
   */
  static void dump(std::span<const uint8_t> data, const fs::path& file)
  {
    dump_bytes(std::as_bytes(data), file);
  }

  /**
   * @brief Writes the content of a string view to a file
   *
   * @param data string view to write
   * @param file the path
   */
  static void dump(std::string_view data, const fs::path& file)
  {
    dump_bytes(std::as_bytes(std::span(data)), file);
  }

  static void rename(const fs::path& src, const fs::path& dst)
  {
    std::error_code ec;
    fs::rename(src, dst, ec);
    if (ec)
    {
      throw std::logic_error(fmt::format(
        "Could not rename file {} to {}: {}",
        src.string(),
        dst.string(),
        ec.message()));
    }
  }

  static void create_directory(const fs::path& dir)
  {
    std::error_code ec;
    fs::create_directory(dir, ec);
    if (ec && ec != std::errc::file_exists)
    {
      throw std::logic_error(fmt::format(
        "Could not create directory {}: {}", dir.string(), ec.message()));
    }
  }
}
