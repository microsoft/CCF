// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#    define MERKLECPP_UNDEF_NOMINMAX
#  endif
#  include <windows.h>
#  ifdef MERKLECPP_UNDEF_NOMINMAX
#    undef MERKLECPP_UNDEF_NOMINMAX
#    undef NOMINMAX
#  endif
#else
#  include <fcntl.h>
#  include <unistd.h>
#endif

// Internal platform abstraction for durable file operations.

namespace merkle // NOLINT(modernize-concat-nested-namespaces)
{
  namespace pal
  {
#ifdef _WIN32
    using SystemError = DWORD;
#else
    using SystemError = int;
#endif

    static inline SystemError last_system_error()
    {
#ifdef _WIN32
      return GetLastError();
#else
      return errno;
#endif
    }

    template <typename... Args>
    std::string system_error_message(
      SystemError error,
      std::format_string<Args...> format_string,
      Args&&... args)
    {
      std::string message;
      std::format_to(
        std::back_inserter(message),
        format_string,
        std::forward<Args>(args)...);
#ifdef _WIN32
      std::format_to(std::back_inserter(message), ": error {}", error);
#else
      std::format_to(std::back_inserter(message), ": {}", std::strerror(error));
#endif
      return message;
    }

    static inline uint64_t process_id()
    {
#ifdef _WIN32
      return static_cast<uint64_t>(GetCurrentProcessId());
#else
      return static_cast<uint64_t>(::getpid());
#endif
    }

#ifndef _WIN32
    namespace detail
    {
      template <typename Operation>
      static inline int retry_on_eintr(const Operation& operation)
      {
        int result = 0;
        do
        {
          result = operation();
        } while (result == -1 && errno == EINTR);
        return result;
      }

    }
#endif

    static inline void require_write_progress(
      size_t written, const std::filesystem::path& path)
    {
      if (written == 0)
      {
        throw std::runtime_error(std::format("short write: {}", path.string()));
      }
    }

    static inline void remove_owned_file(
      const std::filesystem::path& path) noexcept
    {
      std::error_code ec;
      std::filesystem::remove(path, ec);
    }

    /// Writes and syncs a new file, failing if @p path already exists.
    /// A file created by this call is removed if a later operation fails.
    static inline void write_and_sync_file(
      const std::filesystem::path& path, const std::vector<uint8_t>& bytes)
    {
#ifdef _WIN32
      HANDLE handle = CreateFileW(
        path.wstring().c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
      if (handle == INVALID_HANDLE_VALUE)
      {
        const auto error = last_system_error();
        throw std::runtime_error(
          system_error_message(error, "cannot open file {}", path.string()));
      }
      bool close_handle = true;
      try
      {
        constexpr auto max_write_size =
          static_cast<size_t>(std::numeric_limits<DWORD>::max());
        size_t written = 0;
        while (written < bytes.size())
        {
          const auto remaining = bytes.size() - written;
          const auto chunk =
            static_cast<DWORD>(std::min(remaining, max_write_size));
          DWORD done = 0;
          if (!WriteFile(handle, bytes.data() + written, chunk, &done, nullptr))
          {
            const auto error = last_system_error();
            throw std::runtime_error(system_error_message(
              error, "error writing file {}", path.string()));
          }
          require_write_progress(static_cast<size_t>(done), path);
          written += done;
        }
        if (!FlushFileBuffers(handle))
        {
          const auto error = last_system_error();
          throw std::runtime_error(system_error_message(
            error, "error syncing file {}", path.string()));
        }
        if (!CloseHandle(handle))
        {
          const auto error = last_system_error();
          throw std::runtime_error(system_error_message(
            error, "error closing file {}", path.string()));
        }
        close_handle = false;
      }
      catch (...)
      {
        if (close_handle)
        {
          CloseHandle(handle);
        }
        remove_owned_file(path);
        throw;
      }
#else
      int flags = O_WRONLY | O_CREAT | O_EXCL;
#  ifdef O_CLOEXEC
      flags |= O_CLOEXEC;
#  endif
      int fd = ::open(path.c_str(), flags, 0666);
      if (fd < 0)
      {
        const auto error = last_system_error();
        throw std::runtime_error(
          system_error_message(error, "cannot open file {}", path.string()));
      }
      try
      {
        size_t written = 0;
        while (written < bytes.size())
        {
          const ssize_t done =
            ::write(fd, bytes.data() + written, bytes.size() - written);
          if (done < 0)
          {
            if (errno == EINTR)
            {
              continue;
            }
            const auto error = last_system_error();
            throw std::runtime_error(system_error_message(
              error, "error writing file {}", path.string()));
          }
          require_write_progress(static_cast<size_t>(done), path);
          written += static_cast<size_t>(done);
        }
        if (detail::retry_on_eintr([fd]() { return ::fsync(fd); }) != 0)
        {
          const auto error = last_system_error();
          throw std::runtime_error(system_error_message(
            error, "error syncing file {}", path.string()));
        }
        if (::close(fd) != 0)
        {
          const auto error = last_system_error();
          fd = -1;
          throw std::runtime_error(system_error_message(
            error, "error closing file {}", path.string()));
        }
        fd = -1;
      }
      catch (...)
      {
        if (fd >= 0)
        {
          ::close(fd);
        }
        remove_owned_file(path);
        throw;
      }
#endif
    }

    static inline void replace_file(
      const std::filesystem::path& tmp, const std::filesystem::path& path)
    {
#ifdef _WIN32
      if (!MoveFileExW(
            tmp.wstring().c_str(),
            path.wstring().c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
      {
        const auto error = last_system_error();
        throw std::runtime_error(system_error_message(
          error,
          "cannot rename temp file {} to {}",
          tmp.string(),
          path.string()));
      }
#else
      std::error_code ec;
      std::filesystem::rename(tmp, path, ec);
      if (ec)
      {
        throw std::runtime_error(std::format(
          "cannot rename temp file {} to {}: {}",
          tmp.string(),
          path.string(),
          ec.message()));
      }
#endif
    }

    static inline void sync_directory_on_disk(const std::filesystem::path& path)
    {
#ifndef _WIN32
      int flags = O_RDONLY;
#  ifdef O_DIRECTORY
      flags |= O_DIRECTORY;
#  endif
#  ifdef O_CLOEXEC
      flags |= O_CLOEXEC;
#  endif
      const int fd = ::open(path.c_str(), flags);
      if (fd < 0)
      {
        const auto error = last_system_error();
        throw std::runtime_error(system_error_message(
          error, "cannot open directory {}", path.string()));
      }
      if (detail::retry_on_eintr([fd]() { return ::fsync(fd); }) != 0)
      {
        const auto error = last_system_error();
        const std::string message = system_error_message(
          error, "error syncing directory {}", path.string());
        ::close(fd);
        throw std::runtime_error(message);
      }
      if (::close(fd) != 0)
      {
        const auto error = last_system_error();
        throw std::runtime_error(system_error_message(
          error, "error closing directory {}", path.string()));
      }
#else
      (void)path;
#endif
    }
  }
}
