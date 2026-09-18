// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "merklecpp.h"
#include "merklecpp_pal.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

// Tiled storage for merklecpp trees, following the full-tile geometry, payload,
// and path encoding of the C2SP tlog-tiles layout
// (https://c2sp.org/tlog-tiles). C2SP defines SHA-256 and 256-hash tiles.
// merklecpp uses that geometry by default, supports compile-time power-of-two
// tile widths as an extension, and separates each format under an
// algorithm-and-width-qualified directory such as sha256-256w or sha384-16w.
// Only complete, immutable tiles are stored. Their hash values are produced by
// the tree's existing HASH_FUNCTION, so tile-derived proofs are byte-identical
// to those produced by merkle::TreeT.
//
// Thread safety: types in this header do not synchronize access internally.
// Callers must serialize access to each shared object, including const proof
// operations that update the tile cache, and all writers sharing a store
// prefix. Independent store objects may read while the serialized writer
// publishes tiles atomically.

namespace merkle // NOLINT(modernize-concat-nested-namespaces)
{
  namespace tiles
  {
    /// @brief Default number of tree levels spanned by a single tile.
    static constexpr uint16_t DEFAULT_TILE_HEIGHT = 8;

    /// @brief Default number of hashes in a full tile.
    static constexpr uint16_t DEFAULT_TILE_WIDTH =
      uint16_t{1U << DEFAULT_TILE_HEIGHT};

    /// @brief Highest tile level permitted by the tlog-tiles layout.
    static constexpr uint8_t MAX_TILE_LEVEL = 63;

    // Leaf indices and counts follow two deliberate conventions. The storage
    // and proof layers below (TileRef, TileStoreT, TileWriterT, hash sources,
    // ProofEngineT, EntryBundleWriterT) index the on-disk log as uint64_t,
    // matching the tlog-tiles layout. TreeT and its TiledTreeT wrapper use
    // size_t, because those leaves are resident in memory. Conversions are
    // confined to the boundary between the two: widening size_t to uint64_t
    // must be lossless, while the reverse direction is range-checked before
    // narrowing (see ProofEngineT::inclusion_proof and
    // MemoryHashSourceT::subtree_root).
    static_assert(
      sizeof(size_t) <= sizeof(uint64_t),
      "tiled storage indexes leaves as uint64_t; a size_t wider than 64 bits "
      "would truncate when tree-level values cross into the tile layer");

    namespace detail
    {
      static constexpr std::string_view SHA256_ALGORITHM_SHORT_NAME = "sha256";
      static constexpr std::string_view SHA384_ALGORITHM_SHORT_NAME = "sha384";
      static constexpr std::string_view SHA512_ALGORITHM_SHORT_NAME = "sha512";
      static constexpr size_t ENTRY_LENGTH_PREFIX_SIZE = 2;
      static constexpr size_t MAX_ENTRY_SIZE = 0xFFFF;

      template <uint8_t TILE_HEIGHT_VALUE>
      struct TileGeometry
      {
        static_assert(
          TILE_HEIGHT_VALUE > 0,
          "tile height must be greater than zero");
        static_assert(
          TILE_HEIGHT_VALUE < std::numeric_limits<size_t>::digits,
          "tile width must fit in size_t");

        static constexpr uint8_t HEIGHT = TILE_HEIGHT_VALUE;
        static constexpr size_t WIDTH = size_t{1} << HEIGHT;
        static constexpr size_t MAX_ENCODED_ENTRY_SIZE =
          ENTRY_LENGTH_PREFIX_SIZE + MAX_ENTRY_SIZE;

        static_assert(
          WIDTH <=
            std::numeric_limits<size_t>::max() / MAX_ENCODED_ENTRY_SIZE,
          "maximum entry bundle size must fit in size_t");

        static constexpr size_t MAX_ENTRY_BUNDLE_SIZE =
          WIDTH * MAX_ENCODED_ENTRY_SIZE;
      };

      template <typename Present>
      uint64_t contiguous_prefix_length(uint64_t limit, const Present& present)
      {
        uint64_t length = 0;
        while (length < limit && present(length))
        {
          length++;
        }
        return length;
      }
    }

    /// @brief Encodes a tile index as tlog-tiles path elements.
    /// @param n The tile index
    /// @return The index as zero-padded, '/'-separated 3-digit groups, where
    /// all but the last group are prefixed with 'x'. For example, 1234067 is
    /// encoded as "x001/x234/067" and 5 as "005".
    static inline std::string encode_tile_index(uint64_t n)
    {
      std::vector<uint16_t> parts;
      do
      {
        parts.emplace_back(static_cast<uint16_t>(n % 1000));
        n /= 1000;
      } while (n > 0);

      std::string r;
      r.reserve(parts.size() * 5);
      for (size_t i = 0; i < parts.size(); i++)
      {
        const auto part = parts[parts.size() - 1 - i];
        std::format_to(
          std::back_inserter(r),
          "{}{}{:03}",
          i == 0 ? "" : "/",
          i + 1 < parts.size() ? "x" : "",
          part);
      }
      return r;
    }

    /// @brief Identifies a single (full) tile within a tiled log.
    /// @note Only full tiles of the associated store's width are produced and
    /// consumed; the incomplete frontier is never tiled.
    struct TileRef
    {
      /// @brief The level of the tile (0 == leaf hashes, maximum 63).
      uint8_t level = 0;

      /// @brief The index of the tile within its level.
      uint64_t index = 0;
    };

    template <
      size_t HASH_SIZE,
      void HASH_FUNCTION(
        const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&),
      uint8_t TILE_HEIGHT_VALUE = DEFAULT_TILE_HEIGHT>
    class TileWriterT;

    template <
      size_t HASH_SIZE,
      void HASH_FUNCTION(
        const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&),
      uint8_t TILE_HEIGHT_VALUE = DEFAULT_TILE_HEIGHT>
    class EntryBundleWriterT;

    template <
      size_t HASH_SIZE,
      void HASH_FUNCTION(
        const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&),
      uint8_t TILE_HEIGHT_VALUE>
    class TiledTreeT;

    /// @brief Reads and writes tlog-tiles tile files on a local filesystem.
    /// @tparam HASH_SIZE Size of each hash in bytes
    /// @tparam HASH_FUNCTION The tree's node hash function (carried for use by
    /// later components; tile I/O itself does not hash).
    /// @tparam TILE_HEIGHT_VALUE Number of tree levels represented by a tile;
    /// the tile width is 2**TILE_HEIGHT_VALUE. The default value 8 is the C2SP
    /// tlog-tiles geometry; other values are merklecpp extensions.
    /// @warning No internal synchronization is provided. Callers must serialize
    /// access to each store object and all writers sharing its prefix.
    /// Independent store objects may read while the serialized writer publishes
    /// tiles atomically.
    template <
      size_t HASH_SIZE,
      void HASH_FUNCTION(
        const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&),
      uint8_t TILE_HEIGHT_VALUE = DEFAULT_TILE_HEIGHT>
    class TileStoreT
    {
      friend class TileWriterT<
        HASH_SIZE,
        HASH_FUNCTION,
        TILE_HEIGHT_VALUE>;
      friend class EntryBundleWriterT<
        HASH_SIZE,
        HASH_FUNCTION,
        TILE_HEIGHT_VALUE>;
      friend class TiledTreeT<
        HASH_SIZE,
        HASH_FUNCTION,
        TILE_HEIGHT_VALUE>;

    public:
      /// @brief The type of hashes stored in tiles.
      using Hash = HashT<HASH_SIZE>;

      /// @brief The compile-time tile geometry.
      using Geometry = detail::TileGeometry<TILE_HEIGHT_VALUE>;

      /// @brief Number of tree levels represented by one tile.
      static constexpr uint8_t TILE_HEIGHT = Geometry::HEIGHT;

      /// @brief Number of hashes in one full tile.
      static constexpr size_t TILE_WIDTH = Geometry::WIDTH;

      static_assert(
        HASH_SIZE > 0 &&
          TILE_WIDTH <= std::numeric_limits<size_t>::max() / HASH_SIZE,
        "tile byte size must fit in size_t");

      /// @brief Constructs a tile store below an algorithm-qualified directory
      /// under @p prefix.
      /// @param prefix The directory under which the format directory lives
      /// @note Built-in SHA functions select sha256, sha384, or sha512.
      explicit TileStoreT(std::filesystem::path prefix) :
        TileStoreT(std::move(prefix), default_hash_algorithm_short_name())
      {}

      /// @brief Constructs a tile store for an explicitly named hash algorithm.
      /// @param prefix The directory under which the format directory lives
      /// @param hash_algorithm_short_name Lowercase algorithm short name
      TileStoreT(
        std::filesystem::path prefix,
        const std::string& hash_algorithm_short_name) :
        prefix(storage_root(std::move(prefix), hash_algorithm_short_name))
      {}

      /// @brief The algorithm-qualified root directory of the store.
      [[nodiscard]] const std::filesystem::path& root() const
      {
        return prefix;
      }

      /// @brief The format directory for @p hash_algorithm_short_name.
      /// @note The default geometry produces names such as sha256-256w.
      static std::string storage_directory_name(
        const std::string& hash_algorithm_short_name)
      {
        validate_hash_algorithm_short_name(hash_algorithm_short_name);
        return std::format("{}-{}w", hash_algorithm_short_name, TILE_WIDTH);
      }

      /// @brief Encodes a tile index (see encode_tile_index).
      static std::string encode_index(uint64_t n)
      {
        return encode_tile_index(n);
      }

      /// @brief The filesystem path of a tile.
      /// @throws std::runtime_error if the tile level exceeds 63
      [[nodiscard]] std::filesystem::path tile_path(const TileRef& ref) const
      {
        if (ref.level > MAX_TILE_LEVEL)
        {
          throw std::runtime_error("tile level out of range");
        }
        const auto relative_path = std::format(
          "tile/{}/{}",
          static_cast<unsigned>(ref.level),
          encode_tile_index(ref.index));
        return prefix / relative_path;
      }

      /// @brief The filesystem path of an entry bundle.
      [[nodiscard]] std::filesystem::path entries_path(uint64_t index) const
      {
        const auto relative_path =
          std::format("tile/entries/{}", encode_tile_index(index));
        return prefix / relative_path;
      }

      /// @brief Whether a full tile exists on disk.
      [[nodiscard]] bool has_full_tile(uint8_t level, uint64_t index) const
      {
        if (level > MAX_TILE_LEVEL)
        {
          return false;
        }
        std::error_code ec;
        const auto path = tile_path(TileRef{level, index});
        if (!std::filesystem::is_regular_file(path, ec) || ec)
        {
          return false;
        }
        return std::filesystem::file_size(path, ec) ==
          (uintmax_t)TILE_WIDTH * HASH_SIZE &&
          !ec;
      }

      /// @brief Writes a tile to disk atomically.
      /// @param ref The tile to write
      /// @param hashes The tile's hashes (exactly TILE_WIDTH of them)
      void write_tile(const TileRef& ref, const std::vector<Hash>& hashes)
      {
        if (hashes.size() != TILE_WIDTH)
        {
          throw std::runtime_error("tile width mismatch");
        }

        std::vector<uint8_t> bytes;
        bytes.reserve(hashes.size() * HASH_SIZE);
        for (const auto& h : hashes)
        {
          h.serialise(bytes);
        }

        write_file_atomically(tile_path(ref), bytes);
      }

      /// @brief Reads a tile from disk.
      /// @param ref The tile to read
      /// @return The tile's hashes (TILE_WIDTH of them)
      [[nodiscard]] std::vector<Hash> read_tile(const TileRef& ref) const
      {
        const size_t expected = (size_t)TILE_WIDTH * HASH_SIZE;
        const auto path = tile_path(ref);
        std::vector<uint8_t> bytes = read_file(path, expected);
        if (bytes.size() != expected)
        {
          throw std::runtime_error(
            std::format(
              "unexpected tile size for {}: expected {} bytes, got {}",
              path.string(),
              expected,
              bytes.size()));
        }

        std::vector<Hash> hashes;
        hashes.reserve(TILE_WIDTH);
        size_t position = 0;
        for (size_t i = 0; i < TILE_WIDTH; i++)
        {
          hashes.emplace_back(bytes, position);
        }
        return hashes;
      }

      /// @brief Whether a full entry bundle exists on disk.
      [[nodiscard]] bool has_entry_bundle(uint64_t index) const
      {
        std::error_code ec;
        const auto path = entries_path(index);
        if (!std::filesystem::is_regular_file(path, ec) || ec)
        {
          return false;
        }
        try
        {
          (void)decode_entries(
            read_file(path, Geometry::MAX_ENTRY_BUNDLE_SIZE), TILE_WIDTH);
          return true;
        }
        catch (const std::runtime_error&)
        {
          return false;
        }
      }

      /// @brief Writes a full entry bundle to disk atomically.
      /// @param index The bundle index
      /// @param entries The raw log entries (exactly TILE_WIDTH of them)
      /// @note Entries are stored in the tlog-tiles entry-bundle format: a
      /// sequence of big-endian uint16 length-prefixed byte strings.
      void write_entry_bundle(
        uint64_t index, const std::vector<std::vector<uint8_t>>& entries)
      {
        if (entries.size() != TILE_WIDTH)
        {
          throw std::runtime_error("entry bundle width mismatch");
        }
        write_file_atomically(entries_path(index), encode_entries(entries));
      }

      /// @brief Reads a full entry bundle from disk.
      /// @param index The bundle index
      /// @return The raw log entries (TILE_WIDTH of them)
      [[nodiscard]] std::vector<std::vector<uint8_t>> read_entry_bundle(
        uint64_t index) const
      {
        const auto path = entries_path(index);
        const auto bytes = read_file(path, Geometry::MAX_ENTRY_BUNDLE_SIZE);
        try
        {
          return decode_entries(bytes, TILE_WIDTH);
        }
        catch (const std::runtime_error& error)
        {
          throw std::runtime_error(
            std::format(
              "invalid entry bundle {}: {}", path.string(), error.what()));
        }
      }

      /// @brief Encodes log entries into the tlog-tiles entry-bundle format.
      static std::vector<uint8_t> encode_entries(
        const std::vector<std::vector<uint8_t>>& entries)
      {
        size_t encoded_size = 0;
        for (const auto& e : entries)
        {
          if (e.size() > detail::MAX_ENTRY_SIZE)
          {
            throw std::runtime_error(
              "entry too large for uint16 length prefix");
          }
          encoded_size += detail::ENTRY_LENGTH_PREFIX_SIZE + e.size();
        }

        std::vector<uint8_t> bytes;
        bytes.reserve(encoded_size);
        for (const auto& e : entries)
        {
          bytes.push_back((uint8_t)((e.size() >> 8) & 0xFF));
          bytes.push_back((uint8_t)(e.size() & 0xFF));
          bytes.insert(bytes.end(), e.begin(), e.end());
        }
        return bytes;
      }

      /// @brief Decodes @p count entries from the entry-bundle format.
      static std::vector<std::vector<uint8_t>> decode_entries(
        const std::vector<uint8_t>& bytes, size_t count)
      {
        if (count > bytes.size() / detail::ENTRY_LENGTH_PREFIX_SIZE)
        {
          throw std::runtime_error("truncated entry bundle");
        }
        std::vector<std::vector<uint8_t>> out;
        out.reserve(count);
        size_t pos = 0;
        for (size_t i = 0; i < count; i++)
        {
          if (bytes.size() - pos < 2)
          {
            throw std::runtime_error("truncated entry bundle");
          }
          const auto len =
            (uint16_t)(((uint16_t)bytes[pos] << 8) | bytes[pos + 1]);
          pos += 2;
          if (len > bytes.size() - pos)
          {
            throw std::runtime_error("truncated entry bundle");
          }
          out.emplace_back(
            bytes.begin() + static_cast<std::ptrdiff_t>(pos),
            bytes.begin() + static_cast<std::ptrdiff_t>(pos + len));
          pos += len;
        }
        if (pos != bytes.size())
        {
          throw std::runtime_error("trailing bytes in entry bundle");
        }
        return out;
      }

      /// @cond INTERNAL
    protected:
      using DirectorySync = std::function<void(const std::filesystem::path&)>;

      TileStoreT(std::filesystem::path prefix, DirectorySync directory_sync) :
        TileStoreT(
          std::move(prefix),
          default_hash_algorithm_short_name(),
          std::move(directory_sync))
      {}

      TileStoreT(
        std::filesystem::path prefix,
        const std::string& hash_algorithm_short_name,
        DirectorySync directory_sync) :
        prefix(storage_root(std::move(prefix), hash_algorithm_short_name)),
        directory_sync(std::move(directory_sync))
      {}

      /// @brief The algorithm-qualified root directory of the store.
      std::filesystem::path prefix;

      DirectorySync directory_sync;
      std::set<std::filesystem::path> durable_directory_entries;
      std::set<std::filesystem::path> durable_directory_contents;

      static std::string default_hash_algorithm_short_name()
      {
        if constexpr (HASH_SIZE == merkle::Tree::Hash::size_bytes)
        {
          if constexpr (HASH_FUNCTION == merkle::Tree::hash_function)
          {
            return std::string(detail::SHA256_ALGORITHM_SHORT_NAME);
          }
#ifdef HAVE_OPENSSL
          if constexpr (HASH_FUNCTION == sha256_openssl)
          {
            return std::string(detail::SHA256_ALGORITHM_SHORT_NAME);
          }
#endif
        }
#ifdef HAVE_OPENSSL
        else if constexpr (HASH_SIZE == merkle::Tree384::Hash::size_bytes)
        {
          if constexpr (HASH_FUNCTION == merkle::Tree384::hash_function)
          {
            return std::string(detail::SHA384_ALGORITHM_SHORT_NAME);
          }
        }
        else if constexpr (HASH_SIZE == merkle::Tree512::Hash::size_bytes)
        {
          if constexpr (HASH_FUNCTION == merkle::Tree512::hash_function)
          {
            return std::string(detail::SHA512_ALGORITHM_SHORT_NAME);
          }
        }
#endif
        throw std::runtime_error(
          "TileStoreT requires a hash algorithm short name");
      }

      static void validate_hash_algorithm_short_name(
        const std::string& hash_algorithm_short_name)
      {
        if (
          hash_algorithm_short_name.empty() ||
          hash_algorithm_short_name.front() == '-' ||
          hash_algorithm_short_name.back() == '-')
        {
          throw std::runtime_error("invalid hash algorithm short name");
        }
        for (const char c : hash_algorithm_short_name)
        {
          if ((c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-')
          {
            throw std::runtime_error("invalid hash algorithm short name");
          }
        }
      }

      static std::filesystem::path storage_root(
        std::filesystem::path prefix,
        const std::string& hash_algorithm_short_name)
      {
        if (
          (hash_algorithm_short_name == detail::SHA256_ALGORITHM_SHORT_NAME &&
           HASH_SIZE != merkle::Hash::size_bytes) ||
          (hash_algorithm_short_name == detail::SHA384_ALGORITHM_SHORT_NAME &&
           HASH_SIZE != merkle::Hash384::size_bytes) ||
          (hash_algorithm_short_name == detail::SHA512_ALGORITHM_SHORT_NAME &&
           HASH_SIZE != merkle::Hash512::size_bytes))
        {
          throw std::runtime_error(
            "hash algorithm short name does not match hash size");
        }
        prefix = std::filesystem::absolute(prefix);
        prefix /= storage_directory_name(hash_algorithm_short_name);
        return prefix;
      }

      [[nodiscard]] bool confirm_full_tile(uint8_t level, uint64_t index)
      {
        const auto path = tile_path(TileRef{level, index});
        if (!has_full_tile(level, index))
        {
          return false;
        }
        confirm_file_durable(path);
        return true;
      }

      [[nodiscard]] bool confirm_entry_bundle(uint64_t index)
      {
        const auto path = entries_path(index);
        if (!has_entry_bundle(index))
        {
          return false;
        }
        confirm_file_durable(path);
        return true;
      }

      void begin_write_attempt()
      {
        durable_directory_contents.clear();
      }

      /// @brief Reads an entire file into a byte vector.
      static std::vector<uint8_t> read_file(
        const std::filesystem::path& path, size_t max_size)
      {
        std::ifstream f(path, std::ios::binary);
        if (!f.good())
        {
          throw std::runtime_error(
            std::format("cannot open file: {}", path.string()));
        }

        std::vector<uint8_t> bytes;
        std::array<uint8_t, 4096> buffer{};
        while (f)
        {
          const size_t remaining = max_size - bytes.size();
          const size_t request =
            remaining < buffer.size() ? remaining + 1 : buffer.size();
          f.read(
            reinterpret_cast<char*>(buffer.data()),
            static_cast<std::streamsize>(request));
          const auto count = static_cast<size_t>(f.gcount());
          if (count == 0)
          {
            break;
          }
          if (count > remaining)
          {
            throw std::runtime_error(
              std::format("file exceeds maximum size: {}", path.string()));
          }
          bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + count);
        }
        if (f.bad())
        {
          throw std::runtime_error(
            std::format("error reading file: {}", path.string()));
        }
        return bytes;
      }

      /// @brief Writes a file atomically via a synced temporary file.
      /// @note Uses unique temp names, cleans them up on errors, and syncs the
      /// file before publishing it with an atomic replace. POSIX builds also
      /// confirm each directory entry in the path and sync the destination
      /// directory after rename. Existing files are only reused after these
      /// syncs are re-confirmed by the current write attempt.
      void write_file_atomically(
        const std::filesystem::path& path, const std::vector<uint8_t>& bytes)
      {
        create_directories_durably(path.parent_path());

        const std::filesystem::path tmp = temp_path(path);
        TempFileGuard guard(tmp);
        merkle::pal::write_and_sync_file(tmp, bytes);
        guard.arm();
        const auto parent = directory_or_dot(path.parent_path());
        durable_directory_contents.erase(parent);
        merkle::pal::replace_file(tmp, path);
        sync_directory_contents(parent);
        guard.dismiss();
      }

      static std::filesystem::path directory_or_dot(
        const std::filesystem::path& directory)
      {
        return directory.empty() ? std::filesystem::path(".") : directory;
      }

      void create_directories_durably(
        const std::filesystem::path& requested_directory)
      {
        const auto directory = directory_or_dot(requested_directory);
        if (durable_directory_entries.contains(directory))
        {
          return;
        }

        auto parent = directory_or_dot(directory.parent_path());
        if (parent != directory)
        {
          create_directories_durably(parent);
        }

        std::error_code ec;
        const bool exists = std::filesystem::exists(directory, ec);
        if (ec)
        {
          throw std::runtime_error(
            std::format(
              "cannot inspect directory {}: {}",
              directory.string(),
              ec.message()));
        }
        if (exists)
        {
          const bool is_directory =
            std::filesystem::is_directory(directory, ec);
          if (ec)
          {
            throw std::runtime_error(
              std::format(
                "cannot inspect directory {}: {}",
                directory.string(),
                ec.message()));
          }
          if (!is_directory)
          {
            throw std::runtime_error(
              std::format(
                "cannot create directory {}: path exists and is not a "
                "directory",
                directory.string()));
          }
        }
        else
        {
          const bool created = std::filesystem::create_directory(directory, ec);
          if (ec)
          {
            throw std::runtime_error(
              std::format(
                "cannot create directory {}: {}",
                directory.string(),
                ec.message()));
          }
          if (!created && !std::filesystem::is_directory(directory, ec))
          {
            throw std::runtime_error(
              ec ?
                std::format(
                  "cannot create directory {}: {}",
                  directory.string(),
                  ec.message()) :
                std::format("cannot create directory {}", directory.string()));
          }
        }

        if (parent != directory)
        {
          sync_directory_for_durability(parent);
          durable_directory_contents.insert(parent);
        }
        durable_directory_entries.insert(directory);
      }

      void confirm_file_durable(const std::filesystem::path& path)
      {
        const auto parent = directory_or_dot(path.parent_path());
        create_directories_durably(parent);
        sync_directory_contents(parent);
      }

      void sync_directory_contents(const std::filesystem::path& directory)
      {
        const auto path = directory_or_dot(directory);
        if (durable_directory_contents.contains(path))
        {
          return;
        }
        sync_directory_for_durability(path);
        durable_directory_contents.insert(path);
      }

      class TempFileGuard
      {
      public:
        explicit TempFileGuard(std::filesystem::path path) :
          path(std::move(path))
        {}

        ~TempFileGuard()
        {
          if (active)
          {
            std::error_code ec;
            std::filesystem::remove(path, ec);
          }
        }

        void arm()
        {
          active = true;
        }

        void dismiss()
        {
          active = false;
        }

      private:
        std::filesystem::path path;
        bool active = false;
      };

      static std::filesystem::path temp_path(const std::filesystem::path& path)
      {
        static std::atomic<uint64_t> counter{0};
        const auto stamp =
          std::chrono::steady_clock::now().time_since_epoch().count();
        std::filesystem::path tmp = path;
        tmp += std::format(
          ".tmp.{}.{}.{}",
          merkle::pal::process_id(),
          (uint64_t)stamp,
          counter.fetch_add(1, std::memory_order_relaxed));
        return tmp;
      }

      void sync_directory_for_durability(const std::filesystem::path& path)
      {
        if (directory_sync)
        {
          directory_sync(path);
          return;
        }
        merkle::pal::sync_directory_on_disk(path);
      }
      /// @endcond
    };

    namespace detail
    {
      template <
        size_t HASH_SIZE,
        void HASH_FUNCTION(
          const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&)>
      HashT<HASH_SIZE> perfect_root_range(
        const std::vector<HashT<HASH_SIZE>>& hashes,
        size_t offset,
        size_t count)
      {
        if (count == 1)
        {
          return hashes[offset];
        }
        const size_t half = count / 2;
        const auto left =
          perfect_root_range<HASH_SIZE, HASH_FUNCTION>(hashes, offset, half);
        const auto right = perfect_root_range<HASH_SIZE, HASH_FUNCTION>(
          hashes, offset + half, half);
        HashT<HASH_SIZE> out;
        HASH_FUNCTION(left, right, out);
        return out;
      }
    }

    /// @brief Computes the Merkle Tree Hash of a perfect (balanced) subtree.
    /// @param leaves The subtree's leaves; the count MUST be a power of two.
    /// @return The subtree root, computed with the tree's HASH_FUNCTION.
    /// @note This is exactly a merkle::TreeT full-node hash, which is why tile
    /// entries (such roots) are immutable: an unbalanced subtree would still
    /// change as leaves are added and must therefore never be tiled.
    template <
      size_t HASH_SIZE,
      void HASH_FUNCTION(
        const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&)>
    inline HashT<HASH_SIZE> perfect_root(
      const std::vector<HashT<HASH_SIZE>>& leaves)
    {
      if (leaves.empty())
      {
        throw std::runtime_error("perfect_root requires at least one leaf");
      }
      if ((leaves.size() & (leaves.size() - 1)) != 0)
      {
        throw std::runtime_error(
          "perfect_root requires a power-of-two number of leaves");
      }

      return detail::perfect_root_range<HASH_SIZE, HASH_FUNCTION>(
        leaves, 0, leaves.size());
    }

    /// @brief Computes and persists tlog-tiles tiles for a growing tree.
    /// @tparam HASH_SIZE Size of each hash in bytes
    /// @tparam HASH_FUNCTION The tree's node hash function
    /// @tparam TILE_HEIGHT_VALUE Number of tree levels represented by a tile
    /// @note Only balanced subtrees are tiled: a level-L entry is the root of a
    /// complete 2**(TILE_HEIGHT_VALUE*L)-leaf subtree. Only full tiles are
    /// written. Tiles in a caller-validated prefix are immutable; repair() may
    /// replace files beyond that prefix. Entries beyond the last full-tile
    /// boundary remain in memory until a later flush completes the next tile.
    /// @warning No internal synchronization is provided. Callers must serialize
    /// access to a writer and its store.
    /// @warning An ordinary writer trusts existing full tiles as output from the
    /// same tree and hash function. repair() trusts only its explicit prefix and
    /// replaces later tiles. Callers must establish prefix ownership and restore
    /// the matching tree state.
    template <
      size_t HASH_SIZE,
      void HASH_FUNCTION(
        const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&),
      uint8_t TILE_HEIGHT_VALUE>
    class TileWriterT
    {
      friend class TiledTreeT<HASH_SIZE, HASH_FUNCTION, TILE_HEIGHT_VALUE>;

    public:
      /// @brief The type of hashes stored in tiles.
      using Hash = HashT<HASH_SIZE>;

      /// @brief The associated tile store type.
      using Store =
        TileStoreT<HASH_SIZE, HASH_FUNCTION, TILE_HEIGHT_VALUE>;

      /// @brief The compile-time tile geometry.
      using Geometry = typename Store::Geometry;

      /// @brief Number of tree levels represented by one tile.
      static constexpr uint8_t TILE_HEIGHT = Geometry::HEIGHT;

      /// @brief Number of hashes in one full tile.
      static constexpr size_t TILE_WIDTH = Geometry::WIDTH;

      /// @brief Supplies the level-0 leaf hash for a given leaf index.
      using LeafFn = std::function<const Hash&(uint64_t)>;

      /// @brief Counts of work performed by a write_up_to call.
      struct Stats
      {
        /// @brief Number of full tiles written.
        uint64_t full_written = 0;
      };

      /// @brief Constructs a writer over @p store.
      explicit TileWriterT(Store& store) : store(store) {}

      /// @brief Constructs a writer that repairs a store after a trusted prefix.
      /// @param store The store to populate or repair
      /// @param trusted_size Caller-validated, tile-aligned leaf count below
      /// which every required full tile is already durable and correct
      /// @return A writer that preserves the trusted prefix and replaces every
      /// existing full tile beyond it as write_up_to() reaches that tile
      /// @note The returned writer owns no store. It may be used independently
      /// of a TiledTree, including on a background thread, while the caller
      /// serializes all writers sharing the namespace.
      [[nodiscard]] static TileWriterT repair(
        Store& store, uint64_t trusted_size)
      {
        return TileWriterT(store, trusted_size);
      }

      /// @brief Writes all newly-complete full tiles for a tree of @p size
      /// leaves.
      /// @param size The current tree size
      /// @param leaf_at Returns the level-0 leaf hash for a leaf index in
      /// [0, size); only ever queried for leaves of complete subtrees.
      /// @return Counts of tiles written
      /// @note Incremental: an ordinary writer reuses full tiles already on disk
      /// once validated and confirmed durable. A repair writer preserves only
      /// its trusted prefix and replaces later tiles. Malformed files are
      /// replaced. Entries that do not complete a tile are not written.
      /// Tiles are always rolled up through MAX_TILE_LEVEL, so the on-disk set
      /// always contains the higher-level roll-ups that proof generation relies
      /// on.
      Stats write_up_to(uint64_t size, const LeafFn& leaf_at)
      {
        Stats stats;
        store.begin_write_attempt();

        // The loop stops early once a level has no complete entries (see the
        // entries == 0 break below).
        for (uint8_t level = 0; level <= MAX_TILE_LEVEL; level++)
        {
          // Number of complete (balanced) level-L entries available; this
          // deliberately excludes the incomplete frontier subtree.
          const uint64_t entries = entries_at_level(size, level);
          if (entries == 0)
          {
            break;
          }
          ensure_level(level);

          const uint64_t full_tiles = entries / TILE_WIDTH;

          if (cursor_inited[level] == 0)
          {
            next_full[level] =
              trust_existing_tiles ? full_prefix_length(level, full_tiles) : 0;
            cursor_inited[level] = 1;
          }

          for (uint64_t n = next_full[level]; n < full_tiles; n++)
          {
            if (trust_existing_tiles && store.confirm_full_tile(level, n))
            {
              next_full[level] = n + 1;
              continue;
            }
            store.write_tile(
              TileRef{level, n},
              collect(level, n * TILE_WIDTH, TILE_WIDTH, leaf_at));
            stats.full_written++;
            next_full[level] = n + 1;
          }
        }

        return stats;
      }

    protected:
      /// @brief The tile store written to.
      // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
      Store& store;

      /// @brief Per-level index of the next full tile to write.
      std::vector<uint64_t> next_full;

      /// @brief Per-level flag indicating next_full has been initialised.
      std::vector<uint8_t> cursor_inited;

      /// @brief Whether correctly-sized files at and beyond next_full may be
      /// adopted rather than replaced.
      bool trust_existing_tiles = true;

      /// @brief Constructs a writer after a caller-validated tile prefix.
      /// Files beyond @p trusted_size are replaced before they become readable.
      TileWriterT(Store& store, uint64_t trusted_size) : store(store)
      {
        reset_trusted_size(trusted_size);
      }

      /// @brief Resets this writer after a caller-validated tile prefix.
      void reset_trusted_size(uint64_t trusted_size)
      {
        if (trusted_size % TILE_WIDTH != 0)
        {
          throw std::runtime_error(
            "TileWriter::repair: trusted size is not tile-aligned");
        }

        std::vector<uint64_t> restored_next_full;
        std::vector<uint8_t> restored_cursor_inited;
        for (uint8_t level = 0; level <= MAX_TILE_LEVEL; level++)
        {
          const uint64_t entries = entries_at_level(trusted_size, level);
          if (entries == 0)
          {
            break;
          }
          const size_t needed = (size_t)level + 1;
          restored_next_full.resize(needed, 0);
          restored_cursor_inited.resize(needed, 0);
          restored_next_full[level] = entries / TILE_WIDTH;
          restored_cursor_inited[level] = 1;
        }
        next_full = std::move(restored_next_full);
        cursor_inited = std::move(restored_cursor_inited);
        trust_existing_tiles = false;
      }

      /// @brief Rebinds a moved writer to its destination store.
      // members are moved individually so the store reference can be rebound.
      // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
      TileWriterT(Store& store, TileWriterT&& other) noexcept :
        store(store),
        next_full(std::move(other.next_full)),
        cursor_inited(std::move(other.cursor_inited)),
        trust_existing_tiles(other.trust_existing_tiles)
      {
        if (trust_existing_tiles)
        {
          next_full.clear();
          cursor_inited.clear();
        }
      }

      /// @brief Number of complete level-@p level entries for a tree of @p
      /// size.
      static uint64_t entries_at_level(uint64_t size, uint8_t level)
      {
        const unsigned shift =
          static_cast<unsigned>(TILE_HEIGHT) * static_cast<unsigned>(level);
        return shift >= 64 ? 0 : (size >> shift);
      }

      /// @brief Ensures per-level bookkeeping vectors cover @p level.
      void ensure_level(uint8_t level)
      {
        const size_t needed = (size_t)level + 1;
        if (next_full.size() < needed)
        {
          next_full.resize(needed, 0);
          cursor_inited.resize(needed, 0);
        }
      }

      /// @brief Length of the confirmed contiguous prefix, bounded by @p limit.
      [[nodiscard]] uint64_t full_prefix_length(uint8_t level, uint64_t limit)
      {
        return detail::contiguous_prefix_length(limit, [&](uint64_t index) {
          return store.confirm_full_tile(level, index);
        });
      }

      /// @brief Collects @p count consecutive level-@p level entries, each the
      /// root of a complete (balanced) subtree.
      std::vector<Hash> collect(
        uint8_t level,
        uint64_t first_entry,
        uint64_t count,
        const LeafFn& leaf_at)
      {
        std::vector<Hash> out;
        out.reserve(count);
        for (uint64_t i = 0; i < count; i++)
        {
          const uint64_t g = first_entry + i;
          if (level == 0)
          {
            out.push_back(leaf_at(g));
          }
          else
          {
            // Roll up the complete child full tile.
            out.push_back(
              perfect_root<HASH_SIZE, HASH_FUNCTION>(
                store.read_tile(TileRef{(uint8_t)(level - 1), g})));
          }
        }
        return out;
      }
    };

    /// @brief Abstract source of Merkle subtree roots for proof generation.
    /// @note Implementations resolve the root of a complete (balanced) subtree
    /// from tiles, from an in-memory tree, or from a combination of the two.
    template <
      size_t HASH_SIZE,
      void HASH_FUNCTION(
        const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&)>
    struct HashSourceT
    {
      /// @brief The type of hashes resolved.
      using Hash = HashT<HASH_SIZE>;

      virtual ~HashSourceT() = default;

      /// @brief Resolves MTH(D[index << level : (index + 1) << level]).
      /// @param level The subtree height (the subtree spans 2**level leaves)
      /// @param index The subtree index at that height
      /// @param out Set to the subtree root on success
      /// @return Whether the complete, balanced subtree could be resolved
      virtual bool subtree_root(
        uint8_t level, uint64_t index, Hash& out) const = 0;

      /// @brief Resolves the level-0 leaf hash at @p index.
      virtual bool leaf(uint64_t index, Hash& out) const
      {
        return subtree_root(0, index, out);
      }
    };

    /// @brief Resolves subtree roots from tlog-tiles tile files.
    /// @tparam HASH_SIZE Size of each hash in bytes
    /// @tparam HASH_FUNCTION The tree's node hash function
    /// @tparam TILE_HEIGHT_VALUE Number of tree levels represented by a tile
    /// @note @p available_size is rounded down to a whole number of full tiles:
    /// only complete, durably-written full tiles are read. A complete subtree
    /// within that full-tile prefix is resolvable; anything reaching into the
    /// incomplete frontier yields false so that a proof builder can fall back
    /// to another source (e.g. an in-memory tree).
    /// @warning No internal synchronization is provided. Even const operations
    /// update the internal LRU cache, so callers must serialize all access to a
    /// shared source.
    template <
      size_t HASH_SIZE,
      void HASH_FUNCTION(
        const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&),
      uint8_t TILE_HEIGHT_VALUE = DEFAULT_TILE_HEIGHT>
    class TileHashSourceT : public HashSourceT<HASH_SIZE, HASH_FUNCTION>
    {
    public:
      using Hash = HashT<HASH_SIZE>;
      using Store =
        TileStoreT<HASH_SIZE, HASH_FUNCTION, TILE_HEIGHT_VALUE>;

      /// @brief The compile-time tile geometry.
      using Geometry = typename Store::Geometry;

      /// @brief Number of tree levels represented by one tile.
      static constexpr uint8_t TILE_HEIGHT = Geometry::HEIGHT;

      /// @brief Number of hashes in one full tile.
      static constexpr size_t TILE_WIDTH = Geometry::WIDTH;

      /// @brief Constructs a source over @p store for trees up to
      /// @p available_size leaves. @p available_size is rounded down to a whole
      /// number of full tiles, since only full tiles are durable.
      TileHashSourceT(const Store& store, uint64_t available_size) :
        store(store), available_size((available_size / TILE_WIDTH) * TILE_WIDTH)
      {
        tile_cache.reserve(TILE_CACHE_SIZE);
      }

      bool subtree_root(uint8_t level, uint64_t index, Hash& out) const override
      {
        // The subtree covers leaves [index << level, (index + 1) << level). It
        // is resolvable only when it lies entirely within the full-tile-covered
        // prefix; the incomplete frontier is served from another source.
        if (level >= 64 || index >= (available_size >> level))
        {
          return false;
        }
        resolve(level, index, out);
        return true;
      }

    protected:
      // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
      const Store& store;
      uint64_t available_size; // full-tile prefix length (a multiple of WIDTH)

      /// @brief Combines the @p span entries at @p off of @p tile into a root.
      static Hash roll_up(
        const std::vector<Hash>& tile, uint64_t off, uint64_t span)
      {
        if (
          span == 0 || span > TILE_WIDTH || (span & (span - 1)) != 0 ||
          off > tile.size() || span > tile.size() - off)
        {
          throw std::runtime_error("invalid tile roll-up range");
        }
        return detail::perfect_root_range<HASH_SIZE, HASH_FUNCTION>(
          tile, static_cast<size_t>(off), static_cast<size_t>(span));
      }

      /// @brief Resolves a complete subtree known to lie within the full-tile
      /// prefix, reading the highest-level full tile that holds it (and rolling
      /// up); descends to lower full tiles when a higher-level full tile has
      /// not completed. Terminates because full level-0 tiles always cover the
      /// prefix.
      void resolve(uint8_t level, uint64_t index, Hash& out) const
      {
        if (level <= TILE_HEIGHT)
        {
          // Spans 2**level <= TILE_WIDTH leaves: held by one level-0 tile.
          const uint64_t span = (uint64_t)1 << level;
          const uint64_t start = index << level;
          const std::vector<Hash>& tile =
            read_tile(TileRef{0, start / TILE_WIDTH});
          out = roll_up(tile, start % TILE_WIDTH, span);
          return;
        }

        const uint8_t L = level / TILE_HEIGHT;
        const uint8_t r = level % TILE_HEIGHT;
        const uint64_t first = index << r; // first level-L entry
        const uint64_t n = first / TILE_WIDTH; // level-L tile index
        const unsigned full_shift =
          static_cast<unsigned>(TILE_HEIGHT) * (static_cast<unsigned>(L) + 1U);
        const uint64_t full_tiles =
          full_shift >= 64 ? 0 : (available_size >> full_shift);

        if (n < full_tiles)
        {
          // One full level-L tile holds all 2**r entries of this subtree.
          const std::vector<Hash>& tile = read_tile(TileRef{L, n});
          out = roll_up(tile, first % TILE_WIDTH, (uint64_t)1 << r);
          return;
        }

        // No full level-L tile here: split into two level-(level-1) subtrees.
        Hash lo;
        Hash hi;
        resolve((uint8_t)(level - 1), index * 2, lo);
        resolve((uint8_t)(level - 1), index * 2 + 1, hi);
        HASH_FUNCTION(lo, hi, out);
      }

      struct TileCacheEntry
      {
        TileRef ref;
        std::vector<Hash> hashes;
      };

      static constexpr size_t DEFAULT_TILE_CACHE_SIZE = 64;
      static constexpr size_t TILE_CACHE_HASH_BUDGET =
        DEFAULT_TILE_CACHE_SIZE * DEFAULT_TILE_WIDTH;
      static constexpr size_t TILE_CACHE_SIZE = std::clamp(
        TILE_CACHE_HASH_BUDGET / TILE_WIDTH,
        size_t{1},
        DEFAULT_TILE_CACHE_SIZE);
      mutable std::vector<TileCacheEntry> tile_cache;

      const std::vector<Hash>& read_tile(const TileRef& ref) const
      {
        for (auto it = tile_cache.begin(); it != tile_cache.end(); it++)
        {
          if (it->ref.level == ref.level && it->ref.index == ref.index)
          {
            TileCacheEntry entry = std::move(*it);
            tile_cache.erase(it);
            tile_cache.push_back(std::move(entry));
            return tile_cache.back().hashes;
          }
        }

        if (tile_cache.size() >= TILE_CACHE_SIZE)
        {
          tile_cache.erase(tile_cache.begin());
        }
        tile_cache.push_back(TileCacheEntry{ref, store.read_tile(ref)});
        return tile_cache.back().hashes;
      }
    };

    /// @brief Builds and verifies inclusion and consistency proofs.
    /// @note Proofs are assembled from a HashSourceT using the tree's
    /// HASH_FUNCTION, so an inclusion proof is byte-identical to the one
    /// produced by merkle::TreeT::path()/past_path() and verifies with
    /// PathT::verify().
    /// @warning Thread safety is inherited from the supplied HashSourceT.
    /// Callers must serialize operations when the source is shared.
    template <
      size_t HASH_SIZE,
      void HASH_FUNCTION(
        const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&)>
    class ProofEngineT
    {
    public:
      using Hash = HashT<HASH_SIZE>;
      using Path = PathT<HASH_SIZE, HASH_FUNCTION>;
      using Source = HashSourceT<HASH_SIZE, HASH_FUNCTION>;

      explicit ProofEngineT(const Source& source) : source(source) {}

      /// @brief The Merkle root of a tree of @p size leaves.
      Hash root(uint64_t size) const
      {
        if (size == 0)
        {
          throw std::runtime_error("empty tree has no root");
        }
        Hash out;
        if (!mth_range(0, size, out))
        {
          throw std::runtime_error("unresolved subtree while computing root");
        }
        return out;
      }

      /// @brief Inclusion proof for leaf @p index in a tree of @p size leaves.
      /// @note Equivalent to TreeT::path(index) when size == num_leaves(), and
      /// to TreeT::past_path(index, size - 1) otherwise.
      std::shared_ptr<Path> inclusion_proof(uint64_t index, uint64_t size) const
      {
        if (index >= size)
        {
          throw std::runtime_error("leaf index out of bounds");
        }
        if (
          index > std::numeric_limits<size_t>::max() ||
          size - 1 > std::numeric_limits<size_t>::max())
        {
          throw std::runtime_error("inclusion proof exceeds PathT index range");
        }

        std::list<typename Path::Element> elements; // leaf -> root order
        uint64_t lo = 0;
        uint64_t hi = size;
        while (hi - lo > 1)
        {
          const uint64_t k = largest_pow2_lt(hi - lo);
          typename Path::Element e;
          if (index - lo < k)
          {
            if (!mth_range(lo + k, hi, e.hash))
            {
              throw std::runtime_error("unresolved subtree in inclusion proof");
            }
            e.direction = Path::PATH_RIGHT;
            hi = lo + k;
          }
          else
          {
            if (!mth_range(lo, lo + k, e.hash))
            {
              throw std::runtime_error("unresolved subtree in inclusion proof");
            }
            e.direction = Path::PATH_LEFT;
            lo = lo + k;
          }
          elements.push_front(std::move(e));
        }

        Hash leaf;
        if (!source.leaf(index, leaf))
        {
          throw std::runtime_error("unresolved leaf in inclusion proof");
        }
        return std::make_shared<Path>(
          leaf,
          static_cast<size_t>(index),
          std::move(elements),
          static_cast<size_t>(size - 1));
      }

      /// @brief Consistency proof that a tree of @p m leaves is a prefix of a
      /// tree of @p n leaves (RFC 6962).
      std::vector<Hash> consistency_proof(uint64_t m, uint64_t n) const
      {
        if (m == 0 || m > n)
        {
          throw std::runtime_error("invalid consistency proof sizes");
        }
        std::vector<Hash> proof;
        if (m == n)
        {
          return proof;
        }
        subproof(m, 0, n, true, proof);
        return proof;
      }

      /// @brief Consistency proof between the trees whose last leaves are at
      /// indices @p first_index and @p second_index (first_index <=
      /// second_index).
      /// @note Equivalent to consistency_proof(first_index + 1,
      /// second_index + 1): it proves the tree of the first first_index + 1
      /// leaves is a prefix of the tree of the first second_index + 1 leaves.
      std::vector<Hash> consistency_proof_from_indices(
        uint64_t first_index, uint64_t second_index) const
      {
        if (
          first_index == std::numeric_limits<uint64_t>::max() ||
          second_index == std::numeric_limits<uint64_t>::max())
        {
          throw std::runtime_error("consistency proof index out of bounds");
        }
        return consistency_proof(first_index + 1, second_index + 1);
      }

      /// @brief Verifies an RFC 6962 consistency proof reconciling the roots of
      /// trees of @p m and @p n leaves.
      static bool verify_consistency(
        uint64_t m,
        uint64_t n,
        const Hash& first_hash,
        const Hash& second_hash,
        const std::vector<Hash>& proof)
      {
        if (m > n)
        {
          return false;
        }
        if (m == n)
        {
          return proof.empty() && first_hash == second_hash;
        }
        if (m == 0)
        {
          return proof.empty();
        }

        size_t proof_index = 0;
        Hash fr = first_hash;
        Hash sr = first_hash;
        if (!is_pow2(m))
        {
          if (proof.empty())
          {
            return false;
          }
          fr = proof[0];
          sr = proof[0];
          proof_index = 1;
        }

        uint64_t fn = m - 1;
        uint64_t sn = n - 1;
        while ((fn & 1) != 0)
        {
          fn >>= 1;
          sn >>= 1;
        }

        for (size_t i = proof_index; i < proof.size(); i++)
        {
          if (sn == 0)
          {
            return false;
          }
          const Hash& c = proof[i];
          if ((fn & 1) != 0 || fn == sn)
          {
            HASH_FUNCTION(c, fr, fr);
            HASH_FUNCTION(c, sr, sr);
            if ((fn & 1) == 0)
            {
              while ((fn & 1) == 0 && fn != 0)
              {
                fn >>= 1;
                sn >>= 1;
              }
            }
          }
          else
          {
            HASH_FUNCTION(sr, c, sr);
          }
          fn >>= 1;
          sn >>= 1;
        }

        return fr == first_hash && sr == second_hash && sn == 0;
      }

    protected:
      // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
      const Source& source;

      static bool is_pow2(uint64_t n)
      {
        return n != 0 && (n & (n - 1)) == 0;
      }

      static uint64_t largest_pow2_lt(uint64_t n)
      {
        uint64_t k = 1;
        while (k <= (n - 1) / 2)
        {
          k <<= 1;
        }
        return k;
      }

      static uint8_t log2_exact(uint64_t n)
      {
        uint8_t r = 0;
        while (n > 1)
        {
          n >>= 1;
          r++;
        }
        return r;
      }

      /// @brief MTH(D[a:b]) via the source; falls back to splitting when a
      /// perfect subtree cannot be resolved directly.
      bool mth_range(uint64_t a, uint64_t b, Hash& out) const
      {
        const uint64_t w = b - a;
        if (w == 0)
        {
          return false;
        }
        if (w == 1)
        {
          return source.leaf(a, out);
        }
        if (is_pow2(w) && (a % w == 0))
        {
          if (source.subtree_root(log2_exact(w), a / w, out))
          {
            return true;
          }
        }
        const uint64_t k = largest_pow2_lt(w);
        Hash left;
        Hash right;
        if (!mth_range(a, a + k, left) || !mth_range(a + k, b, right))
        {
          return false;
        }
        HASH_FUNCTION(left, right, out);
        return true;
      }

      void subproof(
        uint64_t m,
        uint64_t lo,
        uint64_t hi,
        bool complete,
        std::vector<Hash>& proof) const
      {
        if (m == hi - lo)
        {
          if (!complete)
          {
            Hash h;
            if (!mth_range(lo, hi, h))
            {
              throw std::runtime_error(
                "unresolved subtree in consistency proof");
            }
            proof.push_back(h);
          }
          return;
        }
        const uint64_t k = largest_pow2_lt(hi - lo);
        Hash h;
        if (m <= k)
        {
          subproof(m, lo, lo + k, complete, proof);
          if (!mth_range(lo + k, hi, h))
          {
            throw std::runtime_error("unresolved subtree in consistency proof");
          }
        }
        else
        {
          subproof(m - k, lo + k, hi, false, proof);
          if (!mth_range(lo, lo + k, h))
          {
            throw std::runtime_error("unresolved subtree in consistency proof");
          }
        }
        proof.push_back(h);
      }
    };

    /// @brief Resolves subtree roots from an in-memory merkle::TreeT.
    /// @note Resolves only complete subtrees that are fully resident (not
    /// flushed), returning false otherwise so that a builder can fall back to
    /// another source. It may materialize pending nodes and compute dirty
    /// hashes but does not change logical contents or hashing semantics.
    template <
      size_t HASH_SIZE,
      void HASH_FUNCTION(
        const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&)>
    class MemoryHashSourceT : public HashSourceT<HASH_SIZE, HASH_FUNCTION>
    {
    public:
      using Hash = HashT<HASH_SIZE>;
      using Tree = TreeT<HASH_SIZE, HASH_FUNCTION>;

      explicit MemoryHashSourceT(Tree& tree) : tree(tree) {}

      bool subtree_root(uint8_t level, uint64_t index, Hash& out) const override
      {
        if (index > std::numeric_limits<size_t>::max())
        {
          return false;
        }
        const auto root = tree.subtree_root(level, static_cast<size_t>(index));
        if (!root)
        {
          return false;
        }
        out = *root;
        return true;
      }

    protected:
      // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
      Tree& tree;
    };

    /// @brief Resolves subtree roots from a primary source, falling back to a
    /// secondary source.
    /// @note Used to combine an in-memory tree (primary: no I/O, serves the
    /// resident frontier) with tile files (secondary: serve the flushed past).
    template <
      size_t HASH_SIZE,
      void HASH_FUNCTION(
        const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&)>
    class CombinedHashSourceT : public HashSourceT<HASH_SIZE, HASH_FUNCTION>
    {
    public:
      using Hash = HashT<HASH_SIZE>;
      using Source = HashSourceT<HASH_SIZE, HASH_FUNCTION>;

      CombinedHashSourceT(const Source& primary, const Source& secondary) :
        primary(primary), secondary(secondary)
      {}

      bool subtree_root(uint8_t level, uint64_t index, Hash& out) const override
      {
        return primary.subtree_root(level, index, out) ||
          secondary.subtree_root(level, index, out);
      }

    protected:
      // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
      const Source& primary;
      // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
      const Source& secondary;
    };

    /// @brief A merkle tree backed by tlog-tiles storage.
    /// @tparam HASH_SIZE Size of each hash in bytes
    /// @tparam HASH_FUNCTION The tree's node hash function
    /// @tparam TILE_HEIGHT_VALUE Number of tree levels represented by a tile
    /// @note Appends grow an in-memory tree; flush() durably writes only full
    /// (balanced) tiles, so the incomplete frontier is never tiled and stays
    /// resident in memory. Compaction (dropping from memory the leaves already
    /// covered by a full tile) is optional: enable it per flush with
    /// Config::compact_on_flush, or call compact() explicitly; it never drops
    /// the un-tiled frontier. Proofs are served from the combination of the
    /// resident tree (frontier) and the full tiles (compacted past).
    /// @note TiledTree constructors create a new tiled tree and atomically claim
    /// a previously absent tile namespace. from_frontier() restores logical tree
    /// state while trusting no tiles, so a separate writer can populate or
    /// repair the namespace before adopt_tile_prefix(). resume() combines those
    /// steps when a validated tile prefix already exists.
    /// @warning No internal synchronization is provided. Callers must serialize
    /// all access to a shared tree, including proof operations.
    template <
      size_t HASH_SIZE,
      void HASH_FUNCTION(
        const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&),
      uint8_t TILE_HEIGHT_VALUE = DEFAULT_TILE_HEIGHT>
    class TiledTreeT
    {
    public:
      using Hash = HashT<HASH_SIZE>;
      using Tree = TreeT<HASH_SIZE, HASH_FUNCTION>;
      using Path = PathT<HASH_SIZE, HASH_FUNCTION>;
      using Store =
        TileStoreT<HASH_SIZE, HASH_FUNCTION, TILE_HEIGHT_VALUE>;
      using Writer =
        TileWriterT<HASH_SIZE, HASH_FUNCTION, TILE_HEIGHT_VALUE>;
      using Stats = typename Writer::Stats;
      using Geometry = typename Store::Geometry;

      /// @brief Number of tree levels represented by one tile.
      static constexpr uint8_t TILE_HEIGHT = Geometry::HEIGHT;

      /// @brief Number of hashes in one full tile.
      static constexpr size_t TILE_WIDTH = Geometry::WIDTH;

      // This wrapper mirrors the core tree's index type on its own public
      // surface, so leaf counts and indices pass through untouched and cross
      // conventions only when they reach the tile layer.
      static_assert(
        std::is_same_v<decltype(Tree().num_leaves()), size_t>,
        "TiledTreeT exposes TreeT's leaf counts and indices as size_t; adjust "
        "its public surface if TreeT changes index type");

      /// @brief Configuration for a tiled tree.
      struct Config
      {
        /// @brief Root directory for the tiled tree.
        /// @note Fresh construction requires the algorithm-qualified tile
        /// subdirectory to be absent; resume() requires it to exist.
        /// from_frontier() does not inspect or create it.
        std::filesystem::path prefix;

        /// @brief Number of most-recent leaves to keep resident when
        /// compacting (i.e. a minimum never dropped from memory).
        /// @note Tile alignment may retain up to TILE_WIDTH - 1 additional
        /// tiled leaves. A zero margin retains one tiled boundary leaf so
        /// rollback to exactly immutable_size() remains possible.
        size_t retention_margin = 0;

        /// @brief If set, flush() compacts after writing tiles, dropping
        /// from memory the leaves already covered by a full tile. Off by
        /// default: tiles are written but the tree keeps every leaf resident.
        bool compact_on_flush = false;
      };

      /// @brief Restores logical tree state without trusting any tile files.
      /// @param config Runtime configuration, including the tile prefix
      /// @param hash_algorithm_short_name Lowercase hash algorithm namespace
      /// @param serialised_tree Serialized merkle::TreeT state
      /// @return A tree with flushed_size() and immutable_size() equal to zero
      /// @note This does not inspect, create, or claim the tile namespace.
      /// Existing files remain untrusted. Root computation and appends are
      /// available immediately, but tile-dependent proofs and flushes of
      /// non-resident history throw until a complete prefix is adopted.
      /// @warning The caller must establish exclusive ownership of the
      /// configured namespace.
      [[nodiscard]] static TiledTreeT from_frontier(
        Config config,
        const std::string& hash_algorithm_short_name,
        const std::vector<uint8_t>& serialised_tree)
      {
        return TiledTreeT(
          FrontierTag{},
          std::move(config),
          hash_algorithm_short_name,
          serialised_tree);
      }

      /// @brief Resumes a tiled tree from serialized tree state and an existing
      /// tile namespace.
      /// @param config Runtime configuration, including the tile prefix
      /// @param hash_algorithm_short_name Lowercase hash algorithm namespace
      /// @param serialised_tree Serialized merkle::TreeT state
      /// @param full_tile_boundary Number of leaves covered by a complete,
      /// durable tile prefix
      /// @return A tiled tree whose tile reads are capped at
      /// @p full_tile_boundary
      /// @note The serialized tree is deserialized by this call. At every tile
      /// level, all full tiles below @p full_tile_boundary must already exist,
      /// be durable, and belong to the same tree. Existing files beyond that
      /// boundary are not trusted and are replaced when a later flush reaches
      /// them.
      [[nodiscard]] static TiledTreeT resume(
        Config config,
        const std::string& hash_algorithm_short_name,
        const std::vector<uint8_t>& serialised_tree,
        size_t full_tile_boundary)
      {
        return resume(
          std::move(config),
          hash_algorithm_short_name,
          serialised_tree,
          full_tile_boundary,
          full_tile_boundary);
      }

      /// @brief Resumes a tiled tree after an interrupted flush.
      /// @param config Runtime configuration, including the tile prefix
      /// @param hash_algorithm_short_name Lowercase hash algorithm namespace
      /// @param serialised_tree Serialized merkle::TreeT state
      /// @param flushed_tile_boundary Number of leaves covered by the last
      /// complete, durable tile prefix
      /// @param immutable_boundary Rollback seal for tiles that may have been
      /// published by an interrupted flush
      /// @return A tiled tree whose proof reads are capped at
      /// @p flushed_tile_boundary and whose rollback seal is
      /// @p immutable_boundary
      /// @note The complete prefix is verified against the serialized frontier.
      /// Tiles between the two boundaries remain untrusted and are replaced by
      /// the next flush.
      [[nodiscard]] static TiledTreeT resume(
        Config config,
        const std::string& hash_algorithm_short_name,
        const std::vector<uint8_t>& serialised_tree,
        size_t flushed_tile_boundary,
        size_t immutable_boundary)
      {
        return TiledTreeT(
          ResumeTag{},
          std::move(config),
          hash_algorithm_short_name,
          serialised_tree,
          flushed_tile_boundary,
          immutable_boundary);
      }

      explicit TiledTreeT(Config config) :
        config(std::move(config)), store(this->config.prefix), writer(store)
      {
        claim_tile_namespace();
      }

      /// @brief Constructs a tiled tree with an explicit storage namespace.
      /// @note Required for custom hash functions whose algorithm name cannot
      /// be inferred by TileStoreT.
      TiledTreeT(Config config, const std::string& hash_algorithm_short_name) :
        config(std::move(config)),
        store(this->config.prefix, hash_algorithm_short_name),
        writer(store)
      {
        claim_tile_namespace();
      }

      TiledTreeT(const TiledTreeT&) = delete;
      TiledTreeT& operator=(const TiledTreeT&) = delete;

      /// @brief Moves a tiled tree, rebinding its writer to the moved store.
      TiledTreeT(TiledTreeT&& other) noexcept :
        config(std::move(other.config)),
        store(std::move(other.store)),
        writer(store, std::move(other.writer)),
        tree(std::move(other.tree)),
        tiles_size(std::exchange(other.tiles_size, 0)),
        sealed_size(std::exchange(other.sealed_size, 0))
      {}

      TiledTreeT& operator=(TiledTreeT&&) = delete;

      /// @brief Appends a leaf hash.
      void append(const Hash& leaf_hash)
      {
        tree.insert(leaf_hash);
      }

      /// @brief The number of leaves (including flushed ones).
      [[nodiscard]] size_t size() const
      {
        return tree.num_leaves();
      }

      /// @brief The current Merkle root.
      Hash root()
      {
        return tree.root();
      }

      /// @brief The number of leaves covered by the last fully successful
      /// flush.
      /// @note This is always a multiple of TILE_WIDTH. It advances only after
      /// every required tile level has been written successfully, and controls
      /// proof reads and compaction.
      [[nodiscard]] size_t flushed_size() const
      {
        return tiles_size;
      }

      /// @brief The rollback seal for ranges a flush may have published.
      /// @note A flush seals its full-tile boundary before writing. If the
      /// write fails, this may exceed flushed_size(); keep the same tree
      /// contents and retry the flush.
      [[nodiscard]] size_t immutable_size() const
      {
        return sealed_size;
      }

      /// @brief Access to the underlying tree.
      /// @warning Mutating the tree directly bypasses tiled-tree bookkeeping.
      /// In particular, direct retraction can make flushed_size() and
      /// immutable_size() exceed size() and can make flushed_size() regress.
      /// Use TiledTreeT operations whenever they are available.
      Tree& tree_ref()
      {
        return tree;
      }

      /// @brief Access to the underlying tile store.
      /// @warning Files changed within flushed_size() are used by proofs without
      /// checking that their hashes match this tree. Mismatched files can
      /// silently invalidate proofs after compaction.
      Store& store_ref()
      {
        return store;
      }

      /// @brief Adopts a complete, durable tile prefix produced independently.
      /// @param full_tile_boundary Tile-aligned number of covered leaves
      /// @note The caller must quiesce every writer for this namespace before
      /// calling. Every required full tile below the boundary is verified
      /// against the serialized frontier. Adoption is monotonic, does not
      /// compact, and keeps files beyond the new boundary untrusted so later
      /// flushes replace them.
      void adopt_tile_prefix(size_t full_tile_boundary)
      {
        if (full_tile_boundary < sealed_size)
        {
          throw std::runtime_error(
            "TiledTree::adopt_tile_prefix: boundary precedes immutable tiles");
        }
        validate_tile_prefix(full_tile_boundary);
        writer.reset_trusted_size(
          static_cast<uint64_t>(full_tile_boundary));
        tiles_size = full_tile_boundary;
        sealed_size = full_tile_boundary;
      }

      /// @brief Writes newly-complete full tiles to disk; compacts only if
      /// Config::compact_on_flush is set.
      /// @return Counts of the full tiles written by this flush
      /// @note The full-tile boundary is made immutable before any tile write.
      /// Only after every required tile level succeeds does flushed_size()
      /// advance to that boundary. On failure, immutable_size() may advance
      /// while flushed_size() does not; the tree remains resident and the flush
      /// can be retried without rewriting finalized tiles.
      Stats flush()
      {
        return flush_up_to(tree.num_leaves());
      }

      /// @brief Writes newly-complete full tiles within a committed prefix.
      /// @param leaf_count Number of leaves in the prefix that may be made
      /// immutable
      /// @return Counts of the full tiles written by this flush
      /// @note This never writes or seals a complete tile beyond
      /// @p leaf_count, even when the logical tree contains more leaves.
      /// Requests below flushed_size() are monotonic no-ops. Compaction, when
      /// configured, only drops leaves covered by the resulting flushed_size().
      Stats flush_up_to(size_t leaf_count)
      {
        Stats stats;
        const size_t n = tree.num_leaves();
        if (leaf_count > n)
        {
          throw std::runtime_error(
            "TiledTree::flush_up_to: leaf count exceeds tree size");
        }

        const size_t covered = (leaf_count / TILE_WIDTH) * TILE_WIDTH;
        if (covered < tiles_size)
        {
          return stats;
        }
        if (!has_complete_history())
        {
          throw std::runtime_error(
            "TiledTree::flush_up_to: tile prefix does not overlap the "
            "resident tree");
        }
        if (covered > sealed_size)
        {
          sealed_size = covered;
        }

        stats =
          writer.write_up_to(leaf_count, [this](uint64_t i) -> const Hash& {
            if (i < tree.min_index())
            {
              throw std::runtime_error(std::format(
                "TiledTree::flush_up_to: cannot regenerate a missing or "
                "malformed tile from non-resident leaf {}",
                i));
            }
            return tree.leaf((size_t)i);
          });
        tiles_size = covered;

        if (config.compact_on_flush)
        {
          compact();
        }
        return stats;
      }

      /// @brief Drops old leaves covered by durably-written full tiles, keeping
      /// at least retention_margin recent leaves and a tiled boundary leaf.
      /// @return The new minimum (smallest still-resident) leaf index
      /// @note Only leaves covered by a full tile are dropped, so the un-tiled
      /// frontier is always retained in memory and inclusion/consistency proofs
      /// remain available (the past from tiles, the frontier from memory). The
      /// leaf at flushed_size() - 1 also remains resident so retract_to() can
      /// represent a tree whose size is exactly immutable_size(). Has no effect
      /// until tiling has produced full tiles.
      size_t compact()
      {
        const size_t covered = (tiles_size / TILE_WIDTH) * TILE_WIDTH;
        const size_t target = compaction_target(covered);
        if (target > tree.min_index())
        {
          tree.flush_to(target);
        }
        return tree.min_index();
      }

      /// @brief Rolls the tree back so that @p index becomes the last leaf,
      /// removing all leaves after it (same semantics as TreeT::retract_to).
      /// @note Only full tiles are immutable: this throws if the resulting size
      /// would be smaller than immutable_size(). A failed flush may advance
      /// immutable_size() without advancing flushed_size().
      void retract_to(size_t index)
      {
        if (sealed_size > 0 && index < sealed_size - 1)
        {
          throw std::runtime_error(
            "TiledTree::retract_to: cannot roll back entries sealed for "
            "immutable tiles (resulting size < immutable size)");
        }
        tree.retract_to(index);
      }

      /// @brief Inclusion proof for @p index in a tree of @p proof_size leaves.
      /// @note Served from tiles (flushed past) combined with the resident tree
      /// (recent frontier); @p proof_size may exceed flushed_size().
      std::shared_ptr<Path> inclusion_proof(size_t index, size_t proof_size)
      {
        if (proof_size > size())
        {
          throw std::runtime_error(
            "inclusion proof size exceeds current tree size");
        }
        return with_engine([&](const auto& engine) {
          return engine.inclusion_proof(index, proof_size);
        });
      }

      /// @brief Consistency proof between tree sizes @p m and @p n.
      std::vector<Hash> consistency_proof(size_t m, size_t n)
      {
        if (n > size())
        {
          throw std::runtime_error(
            "consistency proof size exceeds current tree size");
        }
        return with_engine(
          [&](const auto& engine) { return engine.consistency_proof(m, n); });
      }

      /// @brief Consistency proof between the trees whose last leaves are at
      /// indices @p first_index and @p second_index (first_index <=
      /// second_index).
      /// @note Equivalent to consistency_proof(first_index + 1,
      /// second_index + 1).
      std::vector<Hash> consistency_proof_from_indices(
        size_t first_index, size_t second_index)
      {
        if (first_index >= size() || second_index >= size())
        {
          throw std::runtime_error(
            "consistency proof index exceeds current tree size");
        }
        if (first_index > second_index)
        {
          throw std::runtime_error(
            "first consistency proof index exceeds second index");
        }
        return with_engine([&](const auto& engine) {
          return engine.consistency_proof_from_indices(
            first_index, second_index);
        });
      }

    protected:
      struct FrontierTag
      {};

      struct ResumeTag
      {};

      Config config;
      Store store;
      Writer writer;
      Tree tree;
      size_t tiles_size = 0;
      size_t sealed_size = 0;

      TiledTreeT(
        [[maybe_unused]] FrontierTag tag,
        Config config,
        const std::string& hash_algorithm_short_name,
        const std::vector<uint8_t>& serialised_tree) :
        config(std::move(config)),
        store(this->config.prefix, hash_algorithm_short_name),
        writer(store, 0),
        tree(deserialise_tree(serialised_tree))
      {
        validate_frontier();
      }

      TiledTreeT(
        [[maybe_unused]] ResumeTag tag,
        Config config,
        const std::string& hash_algorithm_short_name,
        const std::vector<uint8_t>& serialised_tree,
        size_t flushed_tile_boundary,
        size_t immutable_boundary) :
        TiledTreeT(
          FrontierTag{},
          std::move(config),
          hash_algorithm_short_name,
          serialised_tree)
      {
        restore_tile_boundaries(flushed_tile_boundary, immutable_boundary);
      }

      static Tree deserialise_tree(const std::vector<uint8_t>& serialised_tree)
      {
        size_t position = 0;
        Tree restored(serialised_tree, position);
        if (position != serialised_tree.size())
        {
          throw std::runtime_error(
            "TiledTree: trailing bytes in serialized tree");
        }
        return restored;
      }

      void validate_frontier()
      {
        if (!tree.invariant())
        {
          throw std::runtime_error(
            "TiledTree: deserialized tree invariant failed");
        }
      }

      void validate_tile_prefix(size_t full_tile_boundary)
      {
        validate_frontier();
        const auto tile_root = store.root() / "tile";
        std::error_code ec;
        if (!std::filesystem::is_directory(tile_root, ec) || ec)
        {
          throw std::runtime_error(std::format(
            "TiledTree: tile namespace does not exist: {}",
            tile_root.string()));
        }
        if (full_tile_boundary % TILE_WIDTH != 0)
        {
          throw std::runtime_error(
            "TiledTree: tile boundary is not aligned");
        }
        if (full_tile_boundary > tree.num_leaves())
        {
          throw std::runtime_error(
            "TiledTree: tile boundary exceeds tree size");
        }
        if (full_tile_boundary == 0)
        {
          if (tree.min_index() != 0)
          {
            throw std::runtime_error(
              "TiledTree: compacted tree has no tile "
              "coverage");
          }
          return;
        }
        const size_t required_resident_leaves =
          std::min(config.retention_margin, full_tile_boundary);
        const size_t latest_resident_start =
          full_tile_boundary -
          std::max(required_resident_leaves, size_t{1});
        if (tree.min_index() > latest_resident_start)
        {
          throw std::runtime_error(
            "TiledTree: tree does not satisfy the configured "
            "retention margin");
        }

        store.begin_write_attempt();
        for (uint8_t level = 0; level <= MAX_TILE_LEVEL; level++)
        {
          const uint64_t entries = Writer::entries_at_level(
            static_cast<uint64_t>(full_tile_boundary), level);
          if (entries == 0)
          {
            break;
          }

          const uint64_t full_tiles = entries / TILE_WIDTH;
          for (uint64_t tile_index = 0; tile_index < full_tiles; tile_index++)
          {
            const auto hashes = read_required_tile(level, tile_index);
            if (level == 0)
            {
              continue;
            }

            const uint64_t first_child = tile_index * TILE_WIDTH;
            for (uint64_t offset = 0; offset < TILE_WIDTH; offset++)
            {
              const auto child =
                read_required_tile((uint8_t)(level - 1), first_child + offset);
              const auto expected =
                perfect_root<HASH_SIZE, HASH_FUNCTION>(child);
              if (hashes[(size_t)offset] != expected)
              {
                throw std::runtime_error(std::format(
                  "TiledTree: tile roll-up mismatch at "
                  "level {}, index {}, entry {}",
                  static_cast<unsigned>(level),
                  tile_index,
                  offset));
              }
            }
          }
        }

        TileHashSourceT<HASH_SIZE, HASH_FUNCTION, TILE_HEIGHT_VALUE> tile_source(
          store, static_cast<uint64_t>(full_tile_boundary));
        ProofEngineT<HASH_SIZE, HASH_FUNCTION> engine(tile_source);
        const Hash tile_root_hash =
          engine.root(static_cast<uint64_t>(full_tile_boundary));
        const Hash frontier_root_hash =
          *tree.past_root(full_tile_boundary - 1);
        if (tile_root_hash != frontier_root_hash)
        {
          throw std::runtime_error(
            "TiledTree: tile prefix root does not match "
            "the serialized frontier");
        }
      }

      [[nodiscard]] std::vector<Hash> read_required_tile(
        uint8_t level, uint64_t index)
      {
        if (!store.confirm_full_tile(level, index))
        {
          throw std::runtime_error(std::format(
            "TiledTree: missing or malformed tile at "
            "level {}, index {}",
            static_cast<unsigned>(level),
            index));
        }
        return store.read_tile(TileRef{level, index});
      }

      void restore_tile_boundaries(
        size_t flushed_tile_boundary, size_t immutable_boundary)
      {
        if (immutable_boundary % TILE_WIDTH != 0)
        {
          throw std::runtime_error(
            "TiledTree::resume: immutable boundary is not tile-aligned");
        }
        if (immutable_boundary < flushed_tile_boundary)
        {
          throw std::runtime_error(
            "TiledTree::resume: immutable boundary precedes flushed tiles");
        }
        const size_t covered =
          (tree.num_leaves() / TILE_WIDTH) * TILE_WIDTH;
        if (immutable_boundary > covered)
        {
          throw std::runtime_error(
            "TiledTree::resume: immutable boundary exceeds tree size");
        }

        validate_tile_prefix(flushed_tile_boundary);
        writer.reset_trusted_size(
          static_cast<uint64_t>(flushed_tile_boundary));
        tiles_size = flushed_tile_boundary;
        sealed_size = immutable_boundary;
      }

      [[nodiscard]] bool has_complete_history() const
      {
        return tree.min_index() == 0 || tiles_size > tree.min_index();
      }

      [[nodiscard]] size_t compaction_target(size_t covered) const
      {
        size_t target = covered > config.retention_margin ?
          covered - config.retention_margin :
          0;
        target = (target / TILE_WIDTH) * TILE_WIDTH;
        // TreeT cannot retract below min_index(). Keep the final tiled leaf
        // resident so rollback to a size of exactly immutable_size() remains
        // representable after compaction.
        if (covered > 0 && target == covered)
        {
          target--;
        }
        return target;
      }

      void claim_tile_namespace() const
      {
        const auto tile_root = store.root() / "tile";
        std::error_code ec;
        std::filesystem::create_directories(tile_root.parent_path(), ec);
        if (ec)
        {
          throw std::runtime_error(std::format(
            "TiledTree: cannot create tile namespace parent {}: {}",
            tile_root.parent_path().string(),
            ec.message()));
        }
        const bool claimed = std::filesystem::create_directory(tile_root, ec);
        if (ec)
        {
          throw std::runtime_error(std::format(
            "TiledTree: cannot claim tile namespace {}: {}",
            tile_root.string(),
            ec.message()));
        }
        if (!claimed)
        {
          throw std::runtime_error(
            "TiledTree: tile namespace already exists; reopening or sharing "
            "a tiled tree is not supported");
        }
      }

      /// @brief Builds a proof engine over the combined resident-tree
      /// (frontier) and full-tile (flushed past) source, and invokes @p fn with
      /// it.
      /// @note The sources and engine are stack-local; @p fn must consume the
      /// engine before returning (proofs are returned by value, holding hash
      /// copies, so the result outlives the engine).
      template <typename Fn>
      auto with_engine(Fn fn)
      {
        if (!has_complete_history())
        {
          throw std::runtime_error(
            "TiledTree: tile prefix does not overlap the resident tree");
        }
        MemoryHashSourceT<HASH_SIZE, HASH_FUNCTION> mem(tree);
        TileHashSourceT<HASH_SIZE, HASH_FUNCTION, TILE_HEIGHT_VALUE> tile_src(
          store, tiles_size);
        CombinedHashSourceT<HASH_SIZE, HASH_FUNCTION> combined(mem, tile_src);
        ProofEngineT<HASH_SIZE, HASH_FUNCTION> engine(combined);
        return fn(engine);
      }
    };

    /// @brief Writes tlog-tiles entry bundles (raw log entries) for a growing
    /// log.
    /// @tparam HASH_SIZE Size of each hash in bytes
    /// @tparam HASH_FUNCTION The tree's node hash function
    /// @tparam TILE_HEIGHT_VALUE Number of tree levels represented by a bundle
    /// @note Entry bundles are level-0 only and application-owned: merklecpp
    /// stores leaf hashes, while the raw entries (and the leaf-hash derivation
    /// linking each entry to its level-0 tile hash) are the application's
    /// responsibility. Only full bundles (TILE_WIDTH entries) are written; they
    /// are immutable and written exactly once. The incomplete tail stays with
    /// the application until it grows into a full bundle, mirroring the
    /// un-tiled Merkle frontier.
    /// @warning No internal synchronization is provided. Callers must serialize
    /// access to a writer and its store.
    template <
      size_t HASH_SIZE,
      void HASH_FUNCTION(
        const HashT<HASH_SIZE>&, const HashT<HASH_SIZE>&, HashT<HASH_SIZE>&),
      uint8_t TILE_HEIGHT_VALUE>
    class EntryBundleWriterT
    {
    public:
      using Store =
        TileStoreT<HASH_SIZE, HASH_FUNCTION, TILE_HEIGHT_VALUE>;
      using Geometry = typename Store::Geometry;

      /// @brief Number of tree levels represented by one bundle.
      static constexpr uint8_t TILE_HEIGHT = Geometry::HEIGHT;

      /// @brief Number of entries in one full bundle.
      static constexpr size_t TILE_WIDTH = Geometry::WIDTH;

      /// @brief Supplies the raw bytes of the log entry at a given index.
      using EntryFn = std::function<std::vector<uint8_t>(uint64_t)>;

      /// @brief Counts of work performed by a write_up_to call.
      struct Stats
      {
        /// @brief Number of full bundles written.
        uint64_t full_written = 0;
      };

      explicit EntryBundleWriterT(Store& store) : store(store) {}

      /// @brief Writes all newly-complete full bundles for a log of @p size
      /// entries.
      /// @param size The current number of entries
      /// @param entry_at Returns the raw bytes of the entry at an index in
      /// [0, size); only ever queried for entries of complete bundles.
      /// @return Counts of bundles written
      /// @note Incremental: full bundles already on disk are immutable and are
      /// never rewritten once validated and confirmed durable. Malformed files
      /// are replaced. The incomplete tail is never bundled.
      Stats write_up_to(uint64_t size, const EntryFn& entry_at)
      {
        Stats stats;
        store.begin_write_attempt();
        const uint64_t full = size / TILE_WIDTH;

        if (!cursor_inited)
        {
          next_full = full_prefix_length(full);
          cursor_inited = true;
        }

        for (uint64_t n = next_full; n < full; n++)
        {
          if (store.confirm_entry_bundle(n))
          {
            continue; // immutable: never rewrite an existing full bundle
          }
          store.write_entry_bundle(
            n, collect(n * TILE_WIDTH, TILE_WIDTH, entry_at));
          stats.full_written++;
        }
        if (full > next_full)
        {
          next_full = full;
        }
        return stats;
      }

    protected:
      // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
      Store& store;
      uint64_t next_full = 0;
      bool cursor_inited = false;

      std::vector<std::vector<uint8_t>> collect(
        uint64_t first, uint64_t count, const EntryFn& entry_at)
      {
        std::vector<std::vector<uint8_t>> out;
        out.reserve(count);
        for (uint64_t i = 0; i < count; i++)
        {
          out.push_back(entry_at(first + i));
        }
        return out;
      }

      [[nodiscard]] uint64_t full_prefix_length(uint64_t limit)
      {
        return detail::contiguous_prefix_length(limit, [&](uint64_t index) {
          return store.confirm_entry_bundle(index);
        });
      }
    };

    /// @brief Default tile store (SHA256, default hash function).
    using TileStore =
      TileStoreT<
        merkle::Tree::Hash::size_bytes,
        merkle::Tree::hash_function,
        DEFAULT_TILE_HEIGHT>;

    /// @brief Default tile writer (SHA256, default hash function).
    using TileWriter =
      TileWriterT<
        merkle::Tree::Hash::size_bytes,
        merkle::Tree::hash_function,
        DEFAULT_TILE_HEIGHT>;

    /// @brief Default abstract hash source (SHA256, default hash function).
    using HashSource =
      HashSourceT<merkle::Tree::Hash::size_bytes, merkle::Tree::hash_function>;

    /// @brief Default tile-backed hash source (SHA256, default hash function).
    using TileHashSource = TileHashSourceT<
      merkle::Tree::Hash::size_bytes,
      merkle::Tree::hash_function,
      DEFAULT_TILE_HEIGHT>;

    /// @brief Default proof engine (SHA256, default hash function).
    using ProofEngine =
      ProofEngineT<merkle::Tree::Hash::size_bytes, merkle::Tree::hash_function>;

    /// @brief Default in-memory hash source (SHA256, default hash function).
    using MemoryHashSource = MemoryHashSourceT<
      merkle::Tree::Hash::size_bytes,
      merkle::Tree::hash_function>;

    /// @brief Default combined hash source (SHA256, default hash function).
    using CombinedHashSource = CombinedHashSourceT<
      merkle::Tree::Hash::size_bytes,
      merkle::Tree::hash_function>;

    /// @brief Default tiled tree (SHA256, default hash function).
    using TiledTree =
      TiledTreeT<
        merkle::Tree::Hash::size_bytes,
        merkle::Tree::hash_function,
        DEFAULT_TILE_HEIGHT>;

    /// @brief Default entry-bundle writer (SHA256, default hash function).
    using EntryBundleWriter = EntryBundleWriterT<
      merkle::Tree::Hash::size_bytes,
      merkle::Tree::hash_function,
      DEFAULT_TILE_HEIGHT>;

#ifdef HAVE_OPENSSL
    /// @brief SHA384 tile store.
    using TileStore384 =
      TileStoreT<48, sha384_openssl, DEFAULT_TILE_HEIGHT>;

    /// @brief SHA512 tile store.
    using TileStore512 =
      TileStoreT<64, sha512_openssl, DEFAULT_TILE_HEIGHT>;

    /// @brief SHA384 tile writer.
    using TileWriter384 =
      TileWriterT<48, sha384_openssl, DEFAULT_TILE_HEIGHT>;

    /// @brief SHA512 tile writer.
    using TileWriter512 =
      TileWriterT<64, sha512_openssl, DEFAULT_TILE_HEIGHT>;

    /// @brief SHA384 hash source, tile-backed source and proof engine.
    using HashSource384 = HashSourceT<48, sha384_openssl>;
    using TileHashSource384 =
      TileHashSourceT<48, sha384_openssl, DEFAULT_TILE_HEIGHT>;
    using ProofEngine384 = ProofEngineT<48, sha384_openssl>;

    /// @brief SHA512 hash source, tile-backed source and proof engine.
    using HashSource512 = HashSourceT<64, sha512_openssl>;
    using TileHashSource512 =
      TileHashSourceT<64, sha512_openssl, DEFAULT_TILE_HEIGHT>;
    using ProofEngine512 = ProofEngineT<64, sha512_openssl>;

    /// @brief SHA384 memory/combined sources and tiled tree.
    using MemoryHashSource384 = MemoryHashSourceT<48, sha384_openssl>;
    using CombinedHashSource384 = CombinedHashSourceT<48, sha384_openssl>;
    using TiledTree384 =
      TiledTreeT<48, sha384_openssl, DEFAULT_TILE_HEIGHT>;

    /// @brief SHA512 memory/combined sources and tiled tree.
    using MemoryHashSource512 = MemoryHashSourceT<64, sha512_openssl>;
    using CombinedHashSource512 = CombinedHashSourceT<64, sha512_openssl>;
    using TiledTree512 =
      TiledTreeT<64, sha512_openssl, DEFAULT_TILE_HEIGHT>;

    /// @brief SHA384/512 entry-bundle writers.
    using EntryBundleWriter384 =
      EntryBundleWriterT<48, sha384_openssl, DEFAULT_TILE_HEIGHT>;
    using EntryBundleWriter512 =
      EntryBundleWriterT<64, sha512_openssl, DEFAULT_TILE_HEIGHT>;
#endif
  }
}
