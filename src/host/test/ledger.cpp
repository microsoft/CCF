// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "host/ledger.h"

#include "ds/serialized.h"
#include "host/snapshots.h"
#include "kv/serialised_entry_format.h"

#include <doctest/doctest.h>
#include <random>
#include <string>

using namespace asynchost;

std::chrono::nanoseconds asynchost::TimeBoundLogger::default_max_time(
  10'000'000);

// Used throughout
using frame_header_type = uint32_t;
static constexpr size_t frame_header_size = sizeof(frame_header_type);
static constexpr auto ledger_dir = "ledger_dir";
static constexpr auto ledger_dir_read_only = "ledger_dir_ro";
static constexpr auto snapshot_dir = "snapshot_dir";

static const auto dummy_snapshot = std::vector<uint8_t>(128, 42);
static const auto dummy_receipt = std::vector<uint8_t>(64, 1);

constexpr auto buffer_size = 1024;
auto in_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
auto out_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
ringbuffer::Circuit eio(in_buffer->bd, out_buffer->bd);

auto wf = ringbuffer::WriterFactory(eio);

void move_all_from_to(
  const std::string& from, const std::string& to, const std::string& suffix)
{
  for (auto const& f : fs::directory_iterator(from))
  {
    if (nonstd::ends_with(f.path().filename(), suffix))
    {
      fs::copy_file(f.path(), fs::path(to) / f.path().filename());
      fs::remove(f.path());
    }
  }
}

struct AutoDeleteFolder
{
  std::string name;

  AutoDeleteFolder(const std::string& name) : name(name) {}

  ~AutoDeleteFolder()
  {
    fs::remove_all(name);
  }
};

// Ledger entry type
template <typename T>
struct LedgerEntry
{
  T value_ = 0;

  auto value() const
  {
    return value_;
  }

  auto set_value(T v)
  {
    value_ = v;
  }

  LedgerEntry() = default;
  LedgerEntry(T v) : value_(v) {}
  LedgerEntry(const uint8_t* data, size_t size)
  {
    value_ = serialized::read<T>(data, size);
  }
};
using TestLedgerEntry = LedgerEntry<uint32_t>;

size_t number_of_files_in_ledger_dir()
{
  size_t file_count = 0;
  for (auto const& f : fs::directory_iterator(ledger_dir))
  {
    file_count++;
  }
  return file_count;
}

size_t number_of_committed_files_in_ledger_dir()
{
  size_t committed_file_count = 0;
  for (auto const& f : fs::directory_iterator(ledger_dir))
  {
    if (is_ledger_file_committed(f.path().string()))
    {
      committed_file_count++;
    }
  }

  return committed_file_count;
}

void verify_framed_entries_range(
  const std::vector<uint8_t>& framed_entries, size_t from, size_t to)
{
  size_t idx = from;
  for (size_t pos = 0; pos < framed_entries.size();)
  {
    const uint8_t* data = &framed_entries[pos];
    size_t size = framed_entries.size() - pos;

    auto header = serialized::read<kv::SerialisedEntryHeader>(data, size);
    auto header_size = header.size;
    REQUIRE(header_size == sizeof(TestLedgerEntry));

    REQUIRE(TestLedgerEntry(data, size).value() == idx);
    pos += kv::serialised_entry_header_size + sizeof(TestLedgerEntry);
    idx++;
  }

  REQUIRE(idx == to + 1);
}

void read_entry_from_ledger(Ledger& ledger, size_t idx)
{
  auto framed_entry = ledger.read_entry(idx);
  REQUIRE(framed_entry.has_value());

  auto& entry = framed_entry.value();
  const uint8_t* data = entry.data();
  auto size = entry.size();
  auto header = serialized::read<kv::SerialisedEntryHeader>(data, size);
  auto header_size = header.size;
  REQUIRE(header_size == sizeof(TestLedgerEntry));

  REQUIRE(TestLedgerEntry(data, size).value() == idx);
}

void read_entries_range_from_ledger(Ledger& ledger, size_t from, size_t to)
{
  auto entries = ledger.read_framed_entries(from, to);
  if (!entries.has_value())
  {
    throw std::logic_error(
      fmt::format("Failed to read ledger entries from {} to {}", from, to));
  }
  verify_framed_entries_range(entries.value(), from, to);
}

// Keeps track of ledger entries written to the ledger.
// An entry submitted at index i has for value i so that it is easy to verify
// that the ledger entry read from the ledger at a specific index is right.
class TestEntrySubmitter
{
private:
  Ledger& ledger;
  size_t last_idx;

public:
  TestEntrySubmitter(Ledger& ledger, size_t initial_last_idx = 0) :
    ledger(ledger),
    last_idx(initial_last_idx)
  {}

  size_t get_last_idx()
  {
    return last_idx;
  }

  void write(bool is_committable, bool force_chunk = false)
  {
    auto e = TestLedgerEntry(++last_idx);
    std::vector<uint8_t> framed_entry(
      kv::serialised_entry_header_size + sizeof(TestLedgerEntry));
    auto data = framed_entry.data();
    auto size = framed_entry.size();

    kv::SerialisedEntryHeader header;
    header.set_size(sizeof(TestLedgerEntry));

    serialized::write(data, size, header);
    serialized::write(data, size, e);
    REQUIRE(
      ledger.write_entry(
        framed_entry.data(),
        framed_entry.size(),
        is_committable,
        force_chunk) == last_idx);
  }

  void truncate(size_t idx)
  {
    ledger.truncate(idx);

    // Check that we can read until truncated entry but cannot read after it
    if (idx > 0)
    {
      read_entries_range_from_ledger(ledger, 1, idx);
    }
    REQUIRE_FALSE(ledger.read_framed_entries(1, idx + 1).has_value());

    if (idx < last_idx)
    {
      last_idx = idx;
    }
  }
};

size_t get_entries_per_chunk(size_t chunk_threshold)
{
  // The number of entries per chunk is a function of the threshold (minus the
  // size of the fixes space for the offset at the size of each file) and the
  // size of each entry
  return ceil(
    (static_cast<float>(chunk_threshold - sizeof(size_t))) /
    (kv::serialised_entry_header_size + sizeof(TestLedgerEntry)));
}

// Assumes that no entries have been written yet
size_t initialise_ledger(
  TestEntrySubmitter& entry_submitter,
  size_t chunk_threshold,
  size_t chunk_count)
{
  size_t end_of_first_chunk_idx = 0;
  bool is_committable = true;
  size_t entries_per_chunk = get_entries_per_chunk(chunk_threshold);

  for (int i = 0; i < entries_per_chunk * chunk_count; i++)
  {
    entry_submitter.write(is_committable);
  }

  REQUIRE(number_of_files_in_ledger_dir() == chunk_count);

  return entries_per_chunk;
}

TEST_CASE("Regular chunking")
{
  auto dir = AutoDeleteFolder(ledger_dir);

  INFO("Cannot create a ledger with a chunk threshold of 0");
  {
    size_t chunk_threshold = 0;
    REQUIRE_THROWS(Ledger(ledger_dir, wf, chunk_threshold));
  }

  size_t chunk_threshold = 30;
  size_t entries_per_chunk = get_entries_per_chunk(chunk_threshold);
  Ledger ledger(ledger_dir, wf, chunk_threshold);
  TestEntrySubmitter entry_submitter(ledger);

  size_t end_of_first_chunk_idx = 0;
  bool is_committable = true;

  INFO("Not quite enough entries before chunk threshold");
  {
    is_committable = true;
    for (int i = 0; i < entries_per_chunk - 1; i++)
    {
      entry_submitter.write(is_committable);
    }

    // Writing committable entries without reaching the chunk threshold
    // does not create new ledger files
    REQUIRE(number_of_files_in_ledger_dir() == 1);
  }

  INFO("Additional non-committable entries do not trigger chunking");
  {
    is_committable = false;
    entry_submitter.write(is_committable);
    entry_submitter.write(is_committable);
    REQUIRE(number_of_files_in_ledger_dir() == 1);
  }

  INFO("Additional committable entry triggers chunking");
  {
    is_committable = true;
    entry_submitter.write(is_committable);
    REQUIRE(number_of_files_in_ledger_dir() == 1);

    // Threshold is passed, a new ledger file should be created
    entry_submitter.write(false);
    end_of_first_chunk_idx = entry_submitter.get_last_idx() - 1;
    REQUIRE(number_of_files_in_ledger_dir() == 2);
  }

  INFO(
    "Submitting more committable entries trigger chunking at regular interval");
  {
    size_t chunk_count = 10;
    size_t number_of_files_before = number_of_files_in_ledger_dir();
    for (int i = 0; i < entries_per_chunk * chunk_count; i++)
    {
      entry_submitter.write(is_committable);
    }
    REQUIRE(
      number_of_files_in_ledger_dir() == chunk_count + number_of_files_before);
  }

  INFO("Forcing early chunk from a committable entry");
  {
    size_t number_of_files_before = number_of_files_in_ledger_dir();

    // Write committable entries until a new chunk with one entry is created
    is_committable = true;
    while (number_of_files_in_ledger_dir() == number_of_files_before)
    {
      entry_submitter.write(is_committable);
    }

    size_t number_of_files_after = number_of_files_in_ledger_dir();

    // Write a new committable entry that forces a new ledger chunk
    is_committable = true;
    bool force_new_chunk = true;
    entry_submitter.write(is_committable, force_new_chunk);
    REQUIRE(number_of_files_in_ledger_dir() == number_of_files_after);

    // Because of forcing a new chunk, the next entry will create a new chunk
    is_committable = false;
    entry_submitter.write(is_committable);

    // A new chunk is created as the entry is committable _and_ forced
    REQUIRE(number_of_files_in_ledger_dir() == number_of_files_after + 1);

    is_committable = true;
    force_new_chunk = true;
    entry_submitter.write(is_committable, force_new_chunk);
    // No new chunk is created as the entry is committable but doesn't force a
    // new chunk
    REQUIRE(number_of_files_in_ledger_dir() == number_of_files_after + 1);
  }

  INFO("Reading entries across all chunks");
  {
    is_committable = false;
    entry_submitter.write(is_committable);
    auto last_idx = entry_submitter.get_last_idx();

    // Reading the last entry succeeds
    read_entry_from_ledger(ledger, last_idx);

    // Reading in the future fails
    REQUIRE_FALSE(ledger.read_entry(last_idx + 1).has_value());

    // Reading at 0 fails
    REQUIRE_FALSE(ledger.read_entry(0).has_value());

    // Reading in the past succeeds
    read_entry_from_ledger(ledger, 1);
    read_entry_from_ledger(ledger, end_of_first_chunk_idx);
    read_entry_from_ledger(ledger, end_of_first_chunk_idx + 1);
    read_entry_from_ledger(ledger, last_idx);
  }

  INFO("Reading range of entries across all chunks");
  {
    // Note: only testing write cache as no chunk has yet been committed
    auto last_idx = entry_submitter.get_last_idx();

    // Reading from 0 fails
    REQUIRE_FALSE(
      ledger.read_framed_entries(0, end_of_first_chunk_idx).has_value());

    // Reading in the future fails
    REQUIRE_FALSE(ledger.read_framed_entries(1, last_idx + 1).has_value());
    REQUIRE_FALSE(
      ledger.read_framed_entries(last_idx, last_idx + 1).has_value());

    // Reading from the start to any valid index succeeds
    read_entries_range_from_ledger(ledger, 1, 1);
    read_entries_range_from_ledger(
      ledger, end_of_first_chunk_idx - 1, end_of_first_chunk_idx);
    read_entries_range_from_ledger(ledger, 1, end_of_first_chunk_idx);
    read_entries_range_from_ledger(ledger, 1, end_of_first_chunk_idx + 1);
    read_entries_range_from_ledger(ledger, 1, last_idx - 1);
    read_entries_range_from_ledger(ledger, 1, last_idx);

    // Reading from just before/after a chunk succeeds
    read_entries_range_from_ledger(
      ledger, end_of_first_chunk_idx, end_of_first_chunk_idx + 1);
    read_entries_range_from_ledger(
      ledger, end_of_first_chunk_idx, last_idx - 1);
    read_entries_range_from_ledger(ledger, end_of_first_chunk_idx, last_idx);
    read_entries_range_from_ledger(
      ledger, end_of_first_chunk_idx + 1, last_idx);
    read_entries_range_from_ledger(
      ledger, end_of_first_chunk_idx + 1, last_idx - 1);
  }
}

TEST_CASE("Truncation")
{
  auto dir = AutoDeleteFolder(ledger_dir);

  size_t chunk_threshold = 30;
  Ledger ledger(ledger_dir, wf, chunk_threshold);
  TestEntrySubmitter entry_submitter(ledger);

  size_t chunk_count = 3;
  size_t end_of_first_chunk_idx =
    initialise_ledger(entry_submitter, chunk_threshold, chunk_count);

  // Write another entry to create a new chunk
  entry_submitter.write(true);

  size_t chunks_so_far = number_of_files_in_ledger_dir();
  auto last_idx = entry_submitter.get_last_idx();

  INFO("Truncating latest index has no effect");
  {
    entry_submitter.truncate(last_idx);
    REQUIRE(number_of_files_in_ledger_dir() == chunks_so_far);
  }

  INFO("Truncating last entry in penultimate chunk closes latest file");
  {
    entry_submitter.truncate(last_idx - 1);
    REQUIRE(number_of_files_in_ledger_dir() == chunks_so_far - 1);

    // New file gets open when one more entry gets submitted
    entry_submitter.write(true);
    REQUIRE(number_of_files_in_ledger_dir() == chunks_so_far);
    entry_submitter.write(true);
    REQUIRE(number_of_files_in_ledger_dir() == chunks_so_far);
  }

  INFO("Truncating any entry in penultimate chunk closes latest file");
  {
    entry_submitter.truncate(last_idx - 2);
    REQUIRE(number_of_files_in_ledger_dir() == chunks_so_far - 1);

    // New file gets opened when two more entries are submitted
    entry_submitter.write(true);
    REQUIRE(number_of_files_in_ledger_dir() == chunks_so_far - 1);
    entry_submitter.write(true);
    REQUIRE(number_of_files_in_ledger_dir() == chunks_so_far);
  }

  INFO("Truncating entry at the start of second chunk");
  {
    entry_submitter.truncate(end_of_first_chunk_idx + 1);
    REQUIRE(number_of_files_in_ledger_dir() == 2);
  }

  INFO("Truncating entry at the end of first chunk");
  {
    entry_submitter.truncate(end_of_first_chunk_idx);
    REQUIRE(number_of_files_in_ledger_dir() == 1);
    entry_submitter.write(true);
  }

  INFO("Truncating very first entry");
  {
    entry_submitter.truncate(1);
    REQUIRE(number_of_files_in_ledger_dir() == 1);
  }

  INFO("Truncating all the things");
  {
    entry_submitter.truncate(0);
    REQUIRE(number_of_files_in_ledger_dir() == 0);
    entry_submitter.write(true);
  }
}

TEST_CASE("Commit")
{
  auto dir = AutoDeleteFolder(ledger_dir);

  size_t chunk_threshold = 30;
  Ledger ledger(ledger_dir, wf, chunk_threshold);
  TestEntrySubmitter entry_submitter(ledger);

  size_t chunk_count = 3;
  size_t end_of_first_chunk_idx =
    initialise_ledger(entry_submitter, chunk_threshold, chunk_count);

  entry_submitter.write(true);
  size_t last_idx = entry_submitter.get_last_idx();
  REQUIRE(number_of_committed_files_in_ledger_dir() == 0);

  INFO("Comitting end of first chunk");
  {
    ledger.commit(end_of_first_chunk_idx);
    REQUIRE(number_of_committed_files_in_ledger_dir() == 1);

    read_entries_range_from_ledger(ledger, 1, end_of_first_chunk_idx + 1);
  }

  INFO("Comitting in the middle on complete chunk");
  {
    ledger.commit(end_of_first_chunk_idx + 1);
    REQUIRE(number_of_committed_files_in_ledger_dir() == 1); // No effect
    ledger.commit(2 * end_of_first_chunk_idx - 1); // No effect
    REQUIRE(number_of_committed_files_in_ledger_dir() == 1);
  }

  INFO("Comitting at the end of a complete chunk");
  {
    ledger.commit(2 * end_of_first_chunk_idx);
    REQUIRE(number_of_committed_files_in_ledger_dir() == 2);
    read_entries_range_from_ledger(ledger, 1, 2 * end_of_first_chunk_idx + 1);
  }

  INFO("Comitting at the end of last complete chunk");
  {
    ledger.commit(last_idx - 1);
    REQUIRE(number_of_committed_files_in_ledger_dir() == 3);
    read_entries_range_from_ledger(ledger, 1, last_idx);
  }

  INFO("Comitting incomplete chunk");
  {
    ledger.commit(last_idx); // No effect
    REQUIRE(number_of_committed_files_in_ledger_dir() == 3);
  }

  INFO("Complete latest chunk and commit");
  {
    entry_submitter.write(true);
    entry_submitter.write(true);
    last_idx = entry_submitter.get_last_idx();
    ledger.commit(last_idx);
    REQUIRE(number_of_committed_files_in_ledger_dir() == 4);
    read_entries_range_from_ledger(ledger, 1, last_idx);
  }

  INFO("Ledger cannot be truncated earlier than commit");
  {
    ledger.truncate(1); // No effect
    read_entries_range_from_ledger(ledger, 1, last_idx);

    ledger.truncate(2 * end_of_first_chunk_idx); // No effect
    read_entries_range_from_ledger(ledger, 1, last_idx);

    // Write and truncate a new entry past commit
    entry_submitter.write(true);
    last_idx = entry_submitter.get_last_idx();
    ledger.truncate(last_idx - 1); // Deletes entry at last_idx
    read_entries_range_from_ledger(ledger, 1, last_idx - 1);
    REQUIRE_FALSE(ledger.read_framed_entries(1, last_idx).has_value());
  }
}

TEST_CASE("Restore existing ledger")
{
  auto dir = AutoDeleteFolder(ledger_dir);

  size_t chunk_threshold = 30;
  size_t last_idx = 0;
  size_t end_of_first_chunk_idx = 0;
  size_t chunk_count = 3;
  size_t number_of_ledger_files = 0;

  SUBCASE("Restoring uncommitted chunks")
  {
    INFO("Initialise first ledger with complete chunks");
    {
      Ledger ledger(ledger_dir, wf, chunk_threshold);
      TestEntrySubmitter entry_submitter(ledger);

      end_of_first_chunk_idx =
        initialise_ledger(entry_submitter, chunk_threshold, chunk_count);
      number_of_ledger_files = number_of_files_in_ledger_dir();
      last_idx = chunk_count * end_of_first_chunk_idx;
    }

    Ledger ledger2(ledger_dir, wf, chunk_threshold);
    read_entries_range_from_ledger(ledger2, 1, last_idx);

    // Restored ledger can be written to
    TestEntrySubmitter entry_submitter(ledger2, last_idx);
    entry_submitter.write(true);
    // On restore, we write a new file as all restored chunks were complete
    REQUIRE(number_of_files_in_ledger_dir() == number_of_ledger_files + 1);
    entry_submitter.write(true);
    entry_submitter.write(true);

    // Restored ledger can be truncated
    entry_submitter.truncate(end_of_first_chunk_idx + 1);
    entry_submitter.truncate(end_of_first_chunk_idx);
    entry_submitter.truncate(1);
  }

  SUBCASE("Restoring truncated ledger")
  {
    INFO("Initialise first ledger with truncation");
    {
      Ledger ledger(ledger_dir, wf, chunk_threshold);
      TestEntrySubmitter entry_submitter(ledger);

      end_of_first_chunk_idx =
        initialise_ledger(entry_submitter, chunk_threshold, chunk_count);

      entry_submitter.truncate(end_of_first_chunk_idx + 1);
      last_idx = entry_submitter.get_last_idx();
      number_of_ledger_files = number_of_files_in_ledger_dir();
    }

    Ledger ledger2(ledger_dir, wf, chunk_threshold);
    read_entries_range_from_ledger(ledger2, 1, last_idx);

    TestEntrySubmitter entry_submitter(ledger2, last_idx);
    entry_submitter.write(true);
    // On restore, we write at the end of the last file is that file is not
    // complete
    REQUIRE(number_of_files_in_ledger_dir() == number_of_ledger_files);
  }

  SUBCASE("Restoring some committed chunks")
  {
    // This is the scenario on recovery
    size_t committed_idx = 0;
    INFO("Initialise first ledger with committed chunks");
    {
      Ledger ledger(ledger_dir, wf, chunk_threshold);
      TestEntrySubmitter entry_submitter(ledger);

      end_of_first_chunk_idx =
        initialise_ledger(entry_submitter, chunk_threshold, chunk_count);

      committed_idx = 2 * end_of_first_chunk_idx + 1;
      entry_submitter.write(true);
      last_idx = entry_submitter.get_last_idx();
      ledger.commit(committed_idx);
    }

    Ledger ledger2(ledger_dir, wf, chunk_threshold);
    read_entries_range_from_ledger(ledger2, 1, last_idx);

    // Restored ledger cannot be truncated before last idx of last committed
    // chunk
    TestEntrySubmitter entry_submitter(ledger2, last_idx);
    entry_submitter.truncate(committed_idx - 1); // Successful

    ledger2.truncate(committed_idx - 2); // Unsuccessful
    read_entries_range_from_ledger(ledger2, 1, end_of_first_chunk_idx);
  }

  SUBCASE("Restoring ledger with different chunking threshold")
  {
    INFO("Initialise first ledger with committed chunks");
    {
      Ledger ledger(ledger_dir, wf, chunk_threshold);
      TestEntrySubmitter entry_submitter(ledger);

      end_of_first_chunk_idx =
        initialise_ledger(entry_submitter, chunk_threshold, chunk_count);

      entry_submitter.write(true);
      last_idx = entry_submitter.get_last_idx();
    }

    INFO("Restore new ledger with twice the chunking threshold");
    {
      Ledger ledger2(ledger_dir, wf, 2 * chunk_threshold);
      read_entries_range_from_ledger(ledger2, 1, last_idx);

      TestEntrySubmitter entry_submitter(ledger2, last_idx);

      size_t orig_number_files = number_of_files_in_ledger_dir();
      while (number_of_files_in_ledger_dir() == orig_number_files)
      {
        entry_submitter.write(true);
      }
      last_idx = entry_submitter.get_last_idx();
    }

    INFO("Restore new ledger with half the chunking threshold");
    {
      Ledger ledger2(ledger_dir, wf, chunk_threshold / 2);
      read_entries_range_from_ledger(ledger2, 1, last_idx);

      TestEntrySubmitter entry_submitter(ledger2, last_idx);

      size_t orig_number_files = number_of_files_in_ledger_dir();
      while (number_of_files_in_ledger_dir() == orig_number_files)
      {
        entry_submitter.write(true);
      }
    }
  }
}

size_t number_open_fd()
{
  size_t fd_count = 0;
  for (auto const& f : fs::directory_iterator("/proc/self/fd"))
  {
    fd_count++;
  }
  return fd_count;
}

TEST_CASE("Limit number of open files")
{
  auto dir = AutoDeleteFolder(ledger_dir);

  size_t chunk_threshold = 30;
  size_t chunk_count = 5;
  size_t max_read_cache_size = 2;
  Ledger ledger(ledger_dir, wf, chunk_threshold, max_read_cache_size);
  TestEntrySubmitter entry_submitter(ledger);

  size_t initial_number_fd = number_open_fd();
  size_t last_idx = 0;

  size_t end_of_first_chunk_idx =
    initialise_ledger(entry_submitter, chunk_threshold, chunk_count);
  REQUIRE(number_open_fd() == initial_number_fd + chunk_count);

  INFO("Writing a new chunk opens a new file");
  {
    entry_submitter.write(true);
    last_idx = entry_submitter.get_last_idx();
    REQUIRE(number_open_fd() == initial_number_fd + chunk_count + 1);
  }

  INFO("Commit closes files and reading committed chunks opens those");
  {
    ledger.commit(1); // No file committed
    REQUIRE(number_open_fd() == initial_number_fd + chunk_count + 1);

    ledger.commit(end_of_first_chunk_idx); // One file now committed
    REQUIRE(number_open_fd() == initial_number_fd + chunk_count);
    read_entry_from_ledger(ledger, 1);
    read_entries_range_from_ledger(ledger, 1, end_of_first_chunk_idx);
    // Committed file is open in read cache
    REQUIRE(number_open_fd() == initial_number_fd + chunk_count + 1);

    ledger.commit(2 * end_of_first_chunk_idx); // Two files now committed
    REQUIRE(number_open_fd() == initial_number_fd + chunk_count);
    read_entries_range_from_ledger(ledger, 1, 2 * end_of_first_chunk_idx);
    // Two committed files open in read cache
    REQUIRE(number_open_fd() == initial_number_fd + chunk_count + 1);

    ledger.commit(last_idx); // All but one file committed
    // One file open for write, two files open for read
    REQUIRE(number_open_fd() == initial_number_fd + 3);

    read_entries_range_from_ledger(ledger, 1, last_idx);
    // Number of open files is capped by size of read cache
    REQUIRE(number_open_fd() == initial_number_fd + 1 + max_read_cache_size);

    // Reading out of order succeeds
    read_entries_range_from_ledger(ledger, 1, end_of_first_chunk_idx);
    read_entries_range_from_ledger(
      ledger, 2 * end_of_first_chunk_idx, 3 * end_of_first_chunk_idx);
    read_entries_range_from_ledger(ledger, 1, last_idx);
    read_entries_range_from_ledger(
      ledger, 3 * end_of_first_chunk_idx, last_idx - 1);
    read_entries_range_from_ledger(ledger, 1, end_of_first_chunk_idx);
  }

  INFO("Close and commit latest file");
  {
    entry_submitter.write(true);
    entry_submitter.write(true);
    entry_submitter.write(true);
    last_idx = entry_submitter.get_last_idx();
    ledger.commit(last_idx);

    read_entries_range_from_ledger(ledger, 1, last_idx);
    REQUIRE(number_open_fd() == initial_number_fd + max_read_cache_size);
  }

  INFO("Still possible to recover a new ledger");
  {
    initial_number_fd = number_open_fd();
    Ledger ledger2(ledger_dir, wf, chunk_threshold, max_read_cache_size);

    // Committed files are not open for write
    REQUIRE(number_open_fd() == initial_number_fd);

    read_entries_range_from_ledger(ledger2, 1, last_idx);
    REQUIRE(number_open_fd() == initial_number_fd + max_read_cache_size);
  }
}

TEST_CASE("Multiple ledger paths")
{
  static constexpr auto ledger_dir_2 = "ledger_dir_2";
  static constexpr auto empty_write_ledger_dir = "ledger_dir_empty";

  auto dir = AutoDeleteFolder(ledger_dir);
  auto dir2 = AutoDeleteFolder(ledger_dir_2);
  auto dir3 = AutoDeleteFolder(empty_write_ledger_dir);

  size_t max_read_cache_size = 2;
  size_t chunk_threshold = 30;
  size_t chunk_count = 5;

  size_t last_committed_idx = 0;
  size_t last_idx = 0;

  INFO("Write many entries on first ledger");
  {
    Ledger ledger(ledger_dir, wf, chunk_threshold);
    TestEntrySubmitter entry_submitter(ledger);

    // Writing some committed chunks...
    initialise_ledger(entry_submitter, chunk_threshold, chunk_count);
    last_committed_idx = entry_submitter.get_last_idx();
    ledger.commit(last_committed_idx);

    // ... and an uncommitted suffix
    bool is_committable = true;
    entry_submitter.write(is_committable);
    entry_submitter.write(is_committable);
    last_idx = entry_submitter.get_last_idx();
  }

  INFO("Copy uncommitted suffix from initial ledger directory");
  {
    fs::create_directory(ledger_dir_2);
    for (auto const& f : fs::directory_iterator(ledger_dir))
    {
      if (!is_ledger_file_committed(f.path().filename()))
      {
        fs::copy(f.path(), ledger_dir_2);
      }
    }
  }

  INFO("Restored ledger cannot read past uncommitted files");
  {
    Ledger ledger(ledger_dir_2, wf, chunk_threshold);

    for (size_t i = 1; i <= last_committed_idx; i++)
    {
      REQUIRE_FALSE(ledger.read_entry(i).has_value());
    }

    read_entry_from_ledger(ledger, last_idx);
  }

  INFO("Restore ledger with previous directory");
  {
    Ledger ledger(
      ledger_dir_2, wf, chunk_threshold, max_read_cache_size, {ledger_dir});

    for (size_t i = 1; i <= last_committed_idx; i++)
    {
      read_entry_from_ledger(ledger, i);
    }

    // Read framed entries across both directories
    read_entries_range_from_ledger(ledger, 1, last_idx);
  }

  INFO("Only committed files can be read from read-only directory");
  {
    Ledger ledger(
      empty_write_ledger_dir,
      wf,
      chunk_threshold,
      max_read_cache_size,
      {ledger_dir});

    for (size_t i = 1; i <= last_committed_idx; i++)
    {
      read_entry_from_ledger(ledger, i);
    }

    // Even though the ledger file for last_idx is in ledger_dir, the entry
    // cannot be read
    REQUIRE_FALSE(ledger.read_entry(last_idx).has_value());
  }
}

TEST_CASE("Recover from read-only ledger directory only")
{
  static constexpr auto ledger_dir_2 = "ledger_dir_2";

  auto dir = AutoDeleteFolder(ledger_dir);
  auto dir2 = AutoDeleteFolder(ledger_dir_2);

  size_t max_read_cache_size = 2;
  size_t chunk_threshold = 30;
  size_t chunk_count = 5;

  size_t entries_per_chunk = 0;
  size_t last_idx = 0;

  INFO("Write many entries on first ledger");
  {
    Ledger ledger(ledger_dir, wf, chunk_threshold);
    TestEntrySubmitter entry_submitter(ledger);

    // Writing some committed chunks
    entries_per_chunk =
      initialise_ledger(entry_submitter, chunk_threshold, chunk_count);
    last_idx = entry_submitter.get_last_idx();
    ledger.commit(last_idx);
  }

  INFO("Recover from read-only ledger entry only");
  {
    Ledger ledger(
      ledger_dir_2, wf, chunk_threshold, max_read_cache_size, {ledger_dir});

    read_entries_range_from_ledger(ledger, 1, last_idx);

    TestEntrySubmitter entry_submitter(ledger, last_idx);

    for (size_t i = 0; i < entries_per_chunk; i++)
    {
      entry_submitter.write(true);
    }

    read_entries_range_from_ledger(ledger, 1, entry_submitter.get_last_idx());
  }
}

TEST_CASE("Invalid ledger file resilience")
{
  auto dir = AutoDeleteFolder(ledger_dir);

  size_t max_read_cache_size = 2;
  size_t chunk_threshold = 30;
  size_t chunk_count = 5;

  size_t entries_per_chunk = 0;
  size_t last_idx = 0;

  INFO("Write many entries on first ledger");
  {
    Ledger ledger(ledger_dir, wf, chunk_threshold);
    TestEntrySubmitter entry_submitter(ledger);

    // Writing some committed chunks
    entries_per_chunk =
      initialise_ledger(entry_submitter, chunk_threshold, chunk_count);
    last_idx = entry_submitter.get_last_idx();
    ledger.commit(last_idx);
  }

  INFO("Restart with invalid ledger files");
  {
    std::vector<std::string> invalid_ledger_file_names = {
      "invalid_file",
      "invalid_ledger_file",
      "ledger_invalid",
      fmt::format("ledger_{}_invalid", last_idx + 1)};

    // Valid file names but empty ledger files
    invalid_ledger_file_names.emplace_back(
      fmt::format("ledger_{}-{}", last_idx + 1, last_idx + 2));
    invalid_ledger_file_names.emplace_back(fmt::format("ledger_{}", last_idx));

    for (auto const& f : invalid_ledger_file_names)
    {
      std::ofstream output(fs::path(ledger_dir) / fs::path(f));
      Ledger ledger(ledger_dir, wf, chunk_threshold, max_read_cache_size);

      // Restarted ledger can read and write entries
      read_entries_range_from_ledger(ledger, 1, last_idx);
      TestEntrySubmitter entry_submitter(ledger, last_idx);
      for (size_t i = 0; i < entries_per_chunk; i++)
      {
        entry_submitter.write(true);
      }
      last_idx = entry_submitter.get_last_idx();
      ledger.commit(last_idx);
      read_entries_range_from_ledger(ledger, 1, last_idx);
    }
  }
}

TEST_CASE("Delete committed file from main directory")
{
  // Used to temporarily copy committed ledger files
  static constexpr auto ledger_dir_tmp = "ledger_dir_tmp";

  auto dir = AutoDeleteFolder(ledger_dir);
  auto dir2 = AutoDeleteFolder(ledger_dir_read_only);
  auto dir3 = AutoDeleteFolder(ledger_dir_tmp);

  size_t chunk_threshold = 30;
  size_t chunk_count = 5;

  // Worst-case scenario: do not keep any committed file in cache
  size_t max_read_cache_size = 0;

  size_t entries_per_chunk = 0;
  size_t last_idx = 0;
  size_t last_committed_idx = 0;

  fs::create_directory(ledger_dir_read_only);
  fs::create_directory(ledger_dir_tmp);

  Ledger ledger(
    ledger_dir,
    wf,
    chunk_threshold,
    max_read_cache_size,
    {ledger_dir_read_only});
  TestEntrySubmitter entry_submitter(ledger);

  INFO("Write many entries on ledger");
  {
    entries_per_chunk =
      initialise_ledger(entry_submitter, chunk_threshold, chunk_count);
    last_committed_idx = entry_submitter.get_last_idx();
    ledger.commit(last_committed_idx);

    entry_submitter.write(true);
    entry_submitter.write(true);
    last_idx = entry_submitter.get_last_idx();

    // Read all entries from ledger, filling up read cache
    read_entries_range_from_ledger(ledger, 1, last_idx);
  }

  // Move all committed files to temporary directory
  move_all_from_to(ledger_dir, ledger_dir_tmp, ledger_committed_suffix);

  INFO("Only non-committed entries can be read");
  {
    read_entries_range_from_ledger(ledger, last_idx - 1, last_idx);
    REQUIRE_FALSE(
      ledger.read_framed_entries(1, last_committed_idx).has_value());
  }

  INFO("Move committed files back to read-only ledger directory");
  {
    move_all_from_to(
      ledger_dir_tmp, ledger_dir_read_only, ledger_committed_suffix);

    read_entries_range_from_ledger(ledger, 1, last_idx);
  }
}

TEST_CASE("Snapshot file name" * doctest::test_suite("snapshot"))
{
  std::random_device rd;
  std::mt19937 rgen(rd());

  std::vector<size_t> snapshot_idx_interval_ranges = {
    10, 1000, 10000, std::numeric_limits<size_t>::max() - 2};

  for (auto const& snapshot_idx_interval_range : snapshot_idx_interval_ranges)
  {
    std::uniform_int_distribution<size_t> dist(1, snapshot_idx_interval_range);
    size_t snapshot_idx = dist(rgen);
    size_t evidence_idx = snapshot_idx + 1;
    size_t commit_idx = evidence_idx + 1;

    auto snap = fmt::format("snapshot_{}_{}", snapshot_idx, evidence_idx);
    auto snap_committed = fmt::format("{}.committed", snap);
    auto snap_committed_1_x = fmt::format("{}.committed_{}", snap, commit_idx);
    auto snapshot_invalid_suffix =
      fmt::format("{}invalidsuffix", snap_committed_1_x);

    LOG_DEBUG_FMT("Snapshot file name: {}", snap_committed_1_x);

    INFO("Identify snapshot files");
    {
      REQUIRE(is_snapshot_file(snap));
      REQUIRE(is_snapshot_file(snap_committed));
      REQUIRE(is_snapshot_file(snap_committed_1_x));
      REQUIRE_FALSE(is_snapshot_file("ledger_1-2"));
      REQUIRE_FALSE(is_snapshot_file("ledger_1-2.committed"));
    }

    INFO("Identify committed files");
    {
      REQUIRE_FALSE(is_snapshot_file_committed(snap));
      REQUIRE(is_snapshot_file_committed(snap_committed));
      REQUIRE(is_snapshot_file_committed(snap_committed_1_x));
    }

    INFO("Identify 1.x files");
    {
      REQUIRE_THROWS(
        is_snapshot_file_1_x(snap)); // Snapshot is not yet committed
      REQUIRE_FALSE(is_snapshot_file_1_x(snap_committed));
      REQUIRE(is_snapshot_file_1_x(snap_committed_1_x));
    }

    INFO("Get 1.x evidence commit idx");
    {
      REQUIRE_THROWS(get_evidence_commit_idx_from_file_name(
        snap)); // Snapshot is not yet committed
      REQUIRE_FALSE(get_evidence_commit_idx_from_file_name(snap_committed)
                      .has_value()); // 2.x
      auto evidence_commit_idx_1_x =
        get_evidence_commit_idx_from_file_name(snap_committed_1_x);
      REQUIRE(evidence_commit_idx_1_x.has_value());
      REQUIRE(evidence_commit_idx_1_x.value() == commit_idx);

      REQUIRE_THROWS(
        get_evidence_commit_idx_from_file_name(snapshot_invalid_suffix));
    }

    INFO("Get snapshot idx");
    {
      REQUIRE(get_snapshot_idx_from_file_name(snap) == snapshot_idx);
      REQUIRE(get_snapshot_idx_from_file_name(snap_committed) == snapshot_idx);
      REQUIRE(
        get_snapshot_idx_from_file_name(snap_committed_1_x) == snapshot_idx);
      REQUIRE(
        get_snapshot_idx_from_file_name(snapshot_invalid_suffix) ==
        snapshot_idx);
    }

    INFO("Get evidence idx");
    {
      REQUIRE(get_snapshot_evidence_idx_from_file_name(snap) == evidence_idx);
      REQUIRE(
        get_snapshot_evidence_idx_from_file_name(snap_committed) ==
        evidence_idx);
      REQUIRE(
        get_snapshot_evidence_idx_from_file_name(snap_committed_1_x) ==
        evidence_idx);
      REQUIRE(
        get_snapshot_evidence_idx_from_file_name(snapshot_invalid_suffix) ==
        evidence_idx);
    }
  }
}

TEST_CASE("Generate and commit snapshots" * doctest::test_suite("snapshot"))
{
  auto dir = AutoDeleteFolder(ledger_dir);
  auto snap_dir = AutoDeleteFolder(snapshot_dir);

  Ledger ledger(ledger_dir, wf, 1);
  SnapshotManager snapshots(snapshot_dir, ledger);

  size_t snapshot_interval = 5;
  size_t snapshot_count = 5;

  INFO("Generate snapshots");
  {
    for (size_t i = 1; i < snapshot_interval * snapshot_count;
         i += snapshot_interval)
    {
      // Note: Evidence is assumed to be at snapshot idx + 1
      snapshots.write_snapshot(
        i, i + 1, dummy_snapshot.data(), dummy_snapshot.size());
    }

    REQUIRE_FALSE(snapshots.find_latest_committed_snapshot().has_value());
  }

  INFO("Commit snapshots");
  {
    for (size_t i = 1; i < snapshot_interval * snapshot_count;
         i += snapshot_interval)
    {
      // Note: Evidence is assumed to be at snapshot idx + 1
      snapshots.commit_snapshot(i, dummy_receipt.data(), dummy_receipt.size());

      auto latest_committed_snapshot =
        snapshots.find_latest_committed_snapshot();
      REQUIRE(latest_committed_snapshot.has_value());
      const auto& snapshot = latest_committed_snapshot.value();
      REQUIRE(get_snapshot_idx_from_file_name(snapshot) == i);
      REQUIRE(get_snapshot_evidence_idx_from_file_name(snapshot) == i + 1);
      REQUIRE_FALSE(
        get_evidence_commit_idx_from_file_name(snapshot).has_value());
    }
  }
}

std::string generate_1_x_snapshot(
  const std::string& snapshot_dir, size_t snapshot_idx, bool committed)
{
  auto snapshot_file_name = fmt::format(
    "{}{}{}{}{}",
    snapshot_file_prefix,
    snapshot_idx_delimiter,
    snapshot_idx,
    snapshot_idx_delimiter,
    snapshot_idx + 1);

  if (committed)
  {
    snapshot_file_name =
      fmt::format("{}.committed_{}", snapshot_file_name, snapshot_idx + 2);
  }
  auto full_snapshot_path =
    fs::path(snapshot_dir) / fs::path(snapshot_file_name);

  std::ofstream snapshot_file(
    full_snapshot_path, std::ios::out | std::ios::binary);
  snapshot_file.write(
    reinterpret_cast<const char*>(dummy_snapshot.data()),
    dummy_snapshot.size());

  return snapshot_file_name;
}

std::optional<std::string> commit_1_x_snapshot(
  const std::string& snapshot_dir, size_t snapshot_idx)
{
  for (auto const& f : fs::directory_iterator(snapshot_dir))
  {
    auto file_name = f.path().filename().string();
    if (
      !is_snapshot_file_committed(file_name) &&
      get_snapshot_idx_from_file_name(file_name) == snapshot_idx)
    {
      const auto committed_file_name = fmt::format(
        "{}{}_{}", file_name, snapshot_committed_suffix, snapshot_idx + 2);

      fs::rename(
        fs::path(snapshot_dir) / fs::path(file_name),
        fs::path(snapshot_dir) / fs::path(committed_file_name));

      return committed_file_name;
    }
  }
  return std::nullopt;
}

TEST_CASE(
  "Backwards compatibility with 1.x snapshots" *
  doctest::test_suite("snapshot"))
{
  // To be removed as part of https://github.com/microsoft/CCF/issues/2981
  auto dir = AutoDeleteFolder(ledger_dir);
  auto snap_dir = AutoDeleteFolder(snapshot_dir);

  Ledger ledger(ledger_dir, wf, 1);
  TestEntrySubmitter entry_submitter(ledger);
  initialise_ledger(entry_submitter, 10, 10);
  SnapshotManager snapshots(snapshot_dir, ledger);

  size_t snapshot_interval = 5;
  size_t snapshot_count = 5;

  size_t latest_committed_snapshot_idx = 0;

  INFO("Populate snapshot directory with 1.x snapshots");
  {
    for (size_t i = 1; i < snapshot_interval * snapshot_count;
         i += snapshot_interval)
    {
      bool committed = (i < ((snapshot_interval / 2) * snapshot_count));

      auto file_name = generate_1_x_snapshot(snapshot_dir, i, committed);
      REQUIRE(get_snapshot_idx_from_file_name(file_name) == i);
      REQUIRE(get_snapshot_evidence_idx_from_file_name(file_name) == i + 1);
      if (committed)
      {
        latest_committed_snapshot_idx = i;
        REQUIRE(get_evidence_commit_idx_from_file_name(file_name) == i + 2);
      }

      auto latest_committed_snapshot =
        snapshots.find_latest_committed_snapshot();
      REQUIRE(latest_committed_snapshot.has_value());
      const auto& snapshot = latest_committed_snapshot.value();
      REQUIRE(
        get_snapshot_idx_from_file_name(snapshot) ==
        latest_committed_snapshot_idx);
      REQUIRE(
        get_snapshot_evidence_idx_from_file_name(snapshot) ==
        latest_committed_snapshot_idx + 1);
      REQUIRE(get_evidence_commit_idx_from_file_name(snapshot).has_value());
      REQUIRE(
        get_evidence_commit_idx_from_file_name(snapshot).value() ==
        latest_committed_snapshot_idx + 2);
    }
  }

  size_t snapshot_2_x_start_idx = snapshot_interval * snapshot_count;
  size_t snapshot_2_x_end_idx = 2 * snapshot_2_x_start_idx;

  INFO("Generate 2.x snapshots");
  {
    for (size_t i = snapshot_2_x_start_idx; i < snapshot_2_x_end_idx;
         i += snapshot_interval)
    {
      snapshots.write_snapshot(
        i, i + 1, dummy_snapshot.data(), dummy_snapshot.size());

      // 2.x snapshot isn't yet committed
      auto latest_committed_snapshot =
        snapshots.find_latest_committed_snapshot();
      REQUIRE(latest_committed_snapshot.has_value());
      REQUIRE(
        get_snapshot_idx_from_file_name(latest_committed_snapshot.value()) ==
        latest_committed_snapshot_idx);
    }
  }

  INFO("Commit 2.x snapshots");
  {
    for (size_t i = snapshot_2_x_start_idx; i < snapshot_2_x_end_idx;
         i += snapshot_interval)
    {
      snapshots.commit_snapshot(i, dummy_receipt.data(), dummy_receipt.size());

      // 2.x snapshot isn't yet committed
      auto latest_committed_snapshot =
        snapshots.find_latest_committed_snapshot();
      REQUIRE(latest_committed_snapshot.has_value());
      REQUIRE_FALSE(is_snapshot_file_1_x(latest_committed_snapshot.value()));
      REQUIRE(
        get_snapshot_idx_from_file_name(latest_committed_snapshot.value()) ==
        i);
      REQUIRE(
        get_snapshot_evidence_idx_from_file_name(
          latest_committed_snapshot.value()) == i + 1);
      REQUIRE_FALSE(get_evidence_commit_idx_from_file_name(
                      latest_committed_snapshot.value())
                      .has_value());
    }
  }
}

TEST_CASE(
  "Find latest snapshot with corresponding ledger chunk (1.x only)" *
  doctest::test_suite("snapshot"))
{
  auto dir = AutoDeleteFolder(ledger_dir);
  auto snap_dir = AutoDeleteFolder(snapshot_dir);

  size_t chunk_threshold = 30;
  size_t chunk_count = 5;
  size_t last_idx = 0;

  Ledger ledger(ledger_dir, wf, chunk_threshold);
  TestEntrySubmitter entry_submitter(ledger);

  SnapshotManager snapshots(snapshot_dir, ledger);

  INFO("Write many entries on first ledger");
  {
    // Writing some committed chunks
    initialise_ledger(entry_submitter, chunk_threshold, chunk_count);
    last_idx = entry_submitter.get_last_idx();
    ledger.commit(last_idx);
  }

  INFO("Create, commit and retrieve latest snapshot");
  {
    size_t snapshot_idx = last_idx / 2;
    // Assumes evidence idx and evidence commit idx as next indices
    size_t snapshot_evidence_idx = snapshot_idx + 1;
    size_t snapshot_evidence_commit_idx = snapshot_evidence_idx + 1;

    generate_1_x_snapshot(snapshot_dir, snapshot_idx, false);

    // Snapshot is not yet committed
    REQUIRE_FALSE(snapshots.find_latest_committed_snapshot().has_value());

    auto snapshot_file_name = commit_1_x_snapshot(snapshot_dir, snapshot_idx);

    LOG_DEBUG_FMT("{}", snapshot_file_name.value());

    REQUIRE(snapshot_file_name.has_value());
    REQUIRE(
      snapshots.find_latest_committed_snapshot().value() ==
      snapshot_file_name.value());

    fs::remove(fmt::format("{}/{}", snapshot_dir, snapshot_file_name.value()));
  }

  INFO("Snapshot evidence commit past last ledger index");
  {
    // Snapshot evidence commit idx is past last ledger idx
    size_t snapshot_idx = last_idx - 1;
    size_t snapshot_evidence_idx = snapshot_idx + 1; // Still covered by ledger
    size_t snapshot_evidence_commit_idx = snapshot_evidence_idx + 1;

    auto snapshot_file_name =
      generate_1_x_snapshot(snapshot_dir, snapshot_idx, true);

    // Even though snapshot is committed, evidence commit is past last ledger
    // index
    REQUIRE_FALSE(snapshots.find_latest_committed_snapshot().has_value());

    // Add another entry to ledger, so that ledger's last idx ==
    // snapshot_evidence_commit_idx
    entry_submitter.write(true); // note: is_committable flag does not matter

    // Snapshot is now valid
    auto latest_committed_snapshot = snapshots.find_latest_committed_snapshot();
    REQUIRE(latest_committed_snapshot.has_value());
    REQUIRE(latest_committed_snapshot.value() == snapshot_file_name);
  }
}
