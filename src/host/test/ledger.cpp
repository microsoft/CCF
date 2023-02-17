// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "host/ledger.h"

#include "ccf/ds/logger.h"
#include "ds/serialized.h"
#include "host/snapshots.h"
#include "kv/serialised_entry_format.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#include <random>
#include <string>

using namespace asynchost;

std::chrono::microseconds asynchost::TimeBoundLogger::default_max_time(10'000);

// Used throughout
using frame_header_type = uint32_t;
static constexpr size_t frame_header_size = sizeof(frame_header_type);
static constexpr auto ledger_dir = "ledger_dir";
static constexpr auto ledger_dir_read_only = "ledger_dir_ro";
static constexpr auto snapshot_dir = "snapshot_dir";
static constexpr auto snapshot_dir_read_only = "snapshot_dir_ro";

static const auto dummy_snapshot = std::vector<uint8_t>(128, 42);
static const auto dummy_receipt = std::vector<uint8_t>(64, 1);

constexpr auto buffer_size = 1024;
auto in_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
auto out_buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
ringbuffer::Circuit eio(in_buffer->bd, out_buffer->bd);

auto wf = ringbuffer::WriterFactory(eio);

void move_all_from_to(
  const std::string& from,
  const std::string& to,
  const std::optional<std::string>& suffix = std::nullopt,
  bool move = true)
{
  for (auto const& f : fs::directory_iterator(from))
  {
    if (
      !suffix.has_value() ||
      std::string_view(f.path().filename().c_str()).ends_with(suffix.value()))
    {
      fs::copy_file(f.path(), fs::path(to) / f.path().filename());
      if (move)
      {
        fs::remove(f.path());
      }
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

size_t number_of_committed_files_in_ledger_dir(bool allow_recovery = false)
{
  size_t committed_file_count = 0;
  for (auto const& f : fs::directory_iterator(ledger_dir))
  {
    auto file_name = f.path().string();
    if (
      (allow_recovery && is_ledger_file_name_recovery(file_name) &&
       file_name.find(ledger_committed_suffix) != std::string::npos) ||
      is_ledger_file_name_committed(file_name))
    {
      committed_file_count++;
    }
  }

  return committed_file_count;
}

size_t number_of_recovery_files_in_ledger_dir()
{
  size_t recovery_file_count = 0;
  for (auto const& f : fs::directory_iterator(ledger_dir))
  {
    if (is_ledger_file_name_recovery(f.path()))
    {
      recovery_file_count++;
    }
  }

  return recovery_file_count;
}

void verify_framed_entries_range(
  const asynchost::LedgerReadResult& read_result, size_t from, size_t to)
{
  REQUIRE(read_result.end_idx <= to);

  const auto& framed_entries = read_result.data;
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

  REQUIRE(idx == read_result.end_idx + 1);
}

void read_entry_from_ledger(Ledger& ledger, size_t idx)
{
  auto framed_entry = ledger.read_entry(idx);
  REQUIRE(framed_entry.has_value());

  auto& entry = framed_entry->data;
  const uint8_t* data = entry.data();
  auto size = entry.size();
  auto header = serialized::read<kv::SerialisedEntryHeader>(data, size);
  auto header_size = header.size;
  REQUIRE(header_size == sizeof(TestLedgerEntry));

  REQUIRE(TestLedgerEntry(data, size).value() == idx);
}

void read_entries_range_from_ledger(
  Ledger& ledger,
  size_t from,
  size_t to,
  std::optional<size_t> max_entries_size = std::nullopt)
{
  auto entries = ledger.read_entries(from, to, max_entries_size);
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

  void write(bool is_committable, uint8_t header_flags = 0)
  {
    auto e = TestLedgerEntry(++last_idx);
    std::vector<uint8_t> framed_entry(
      kv::serialised_entry_header_size + sizeof(TestLedgerEntry));
    auto data = framed_entry.data();
    auto size = framed_entry.size();

    kv::SerialisedEntryHeader header;
    header.set_size(sizeof(TestLedgerEntry));
    header.flags = header_flags;

    serialized::write(data, size, header);
    serialized::write(data, size, e);
    REQUIRE(
      ledger.write_entry(
        framed_entry.data(), framed_entry.size(), is_committable) == last_idx);
  }

  void truncate(size_t idx)
  {
    ledger.truncate(idx);

    // Check that we can read until truncated entry but cannot read after it
    if (idx > 0)
    {
      read_entries_range_from_ledger(ledger, 1, idx);
    }
    REQUIRE_FALSE(ledger.read_entries(1, idx + 1).has_value());

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
    entry_submitter.write(is_committable, kv::FORCE_LEDGER_CHUNK_AFTER);
    REQUIRE(number_of_files_in_ledger_dir() == number_of_files_after);

    // Because of forcing a new chunk, the next entry will create a new chunk
    is_committable = false;
    entry_submitter.write(is_committable);

    // A new chunk is created as the previous entry was committable _and_ forced
    REQUIRE(number_of_files_in_ledger_dir() == number_of_files_after + 1);

    is_committable = true;
    entry_submitter.write(is_committable, kv::FORCE_LEDGER_CHUNK_BEFORE);
    // A new chunk is created before, as the entry is committable and forced
    REQUIRE(number_of_files_in_ledger_dir() == number_of_files_after + 2);
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
    REQUIRE_FALSE(ledger.read_entries(0, end_of_first_chunk_idx).has_value());

    // Reading in the future fails
    REQUIRE_FALSE(ledger.read_entries(1, last_idx + 1).has_value());
    REQUIRE_FALSE(ledger.read_entries(last_idx, last_idx + 1).has_value());

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

    // Non strict
    bool strict = false;
    auto entries = ledger.read_entries(1, last_idx, strict);
    verify_framed_entries_range(entries.value(), 1, last_idx);

    entries = ledger.read_entries(1, last_idx + 1, strict);
    verify_framed_entries_range(entries.value(), 1, last_idx);

    entries = ledger.read_entries(end_of_first_chunk_idx, 2 * last_idx, strict);
    verify_framed_entries_range(
      entries.value(), end_of_first_chunk_idx, last_idx);
  }

  INFO("Read range of entries with size limit");
  {
    auto last_idx = entry_submitter.get_last_idx();

    // Reading entries larger than the max entries size fails
    REQUIRE_FALSE(
      ledger.read_entries(1, 1, 0 /* max_entries_size */).has_value());
    REQUIRE_FALSE(
      ledger.read_entries(1, end_of_first_chunk_idx + 1, 0).has_value());

    // Reading entries larger than max entries size returns some entries
    size_t max_entries_size = chunk_threshold / entries_per_chunk;

    auto e = ledger.read_entries(1, end_of_first_chunk_idx, max_entries_size);
    REQUIRE(e.has_value());
    verify_framed_entries_range(e.value(), 1, 1);

    e = ledger.read_entries(1, end_of_first_chunk_idx + 1, max_entries_size);
    REQUIRE(e.has_value());
    verify_framed_entries_range(e.value(), 1, 1);

    // Even over chunk boundaries
    e = ledger.read_entries(
      end_of_first_chunk_idx, end_of_first_chunk_idx + 1, max_entries_size);
    REQUIRE(e.has_value());
    verify_framed_entries_range(
      e.value(), end_of_first_chunk_idx, end_of_first_chunk_idx + 1);

    max_entries_size = 2 * chunk_threshold;

    // All entries are returned
    read_entries_range_from_ledger(
      ledger, 1, end_of_first_chunk_idx, max_entries_size);
    read_entries_range_from_ledger(
      ledger,
      end_of_first_chunk_idx + 1,
      2 * end_of_first_chunk_idx + 1,
      max_entries_size);
    read_entries_range_from_ledger(
      ledger, last_idx - 1, last_idx, max_entries_size);

    // Only some entries are returned
    e = ledger.read_entries(1, 2 * end_of_first_chunk_idx, max_entries_size);
    REQUIRE(e.has_value());
    verify_framed_entries_range(e.value(), 1, end_of_first_chunk_idx + 1);

    e = ledger.read_entries(
      end_of_first_chunk_idx + 1, last_idx, max_entries_size);
    REQUIRE(e.has_value());
    verify_framed_entries_range(
      e.value(), end_of_first_chunk_idx + 1, 2 * end_of_first_chunk_idx + 1);
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

  INFO("Committing end of first chunk");
  {
    ledger.commit(end_of_first_chunk_idx);
    REQUIRE(number_of_committed_files_in_ledger_dir() == 1);

    read_entries_range_from_ledger(ledger, 1, end_of_first_chunk_idx + 1);
  }

  INFO("Committing in the middle on complete chunk");
  {
    ledger.commit(end_of_first_chunk_idx + 1);
    REQUIRE(number_of_committed_files_in_ledger_dir() == 1); // No effect
    ledger.commit(2 * end_of_first_chunk_idx - 1); // No effect
    REQUIRE(number_of_committed_files_in_ledger_dir() == 1);
  }

  INFO("Committing at the end of a complete chunk");
  {
    ledger.commit(2 * end_of_first_chunk_idx);
    REQUIRE(number_of_committed_files_in_ledger_dir() == 2);
    read_entries_range_from_ledger(ledger, 1, 2 * end_of_first_chunk_idx + 1);
  }

  INFO("Committing at the end of last complete chunk");
  {
    ledger.commit(last_idx - 1);
    REQUIRE(number_of_committed_files_in_ledger_dir() == 3);
    read_entries_range_from_ledger(ledger, 1, last_idx);
  }

  INFO("Committing incomplete chunk");
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

  INFO("Commit past last idx");
  {
    ledger.commit(last_idx + 1); // No effect
    REQUIRE(number_of_committed_files_in_ledger_dir() == 4);
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
    REQUIRE_FALSE(ledger.read_entries(1, last_idx).has_value());
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
      if (!is_ledger_file_name_committed(f.path().filename()))
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

void corrupt_ledger_file(
  const std::string& ledger_file,
  bool corrupt_table_offset = false,
  bool corrupt_first_hdr = false,
  bool corrupt_last_entry = false)
{
  auto file = fopen(ledger_file.c_str(), "r+b");
  REQUIRE(file);
  fseeko(file, 0, SEEK_SET);
  size_t table_offset = 0;

  if (corrupt_table_offset)
  {
    table_offset = 0xffffffff;
    REQUIRE(fwrite(&table_offset, sizeof(table_offset), 1, file) == 1);
  }
  else if (corrupt_first_hdr)
  {
    REQUIRE(fread(&table_offset, sizeof(table_offset), 1, file) == 1);
    kv::SerialisedEntryHeader entry_header = {.size = 0xffffffff};
    fwrite(&entry_header, sizeof(entry_header), 1, file);
  }
  else if (corrupt_last_entry)
  {
    REQUIRE(fread(&table_offset, sizeof(table_offset), 1, file) == 1);
    std::vector<uint8_t> last_entry = {};
    while (true)
    {
      kv::SerialisedEntryHeader entry_header = {};
      if (fread(&entry_header, sizeof(entry_header), 1, file) != 1)
      {
        break;
      }
      last_entry.resize(entry_header.size);
      REQUIRE(fread(last_entry.data(), entry_header.size, 1, file) == 1);
    }

    REQUIRE(fflush(file) == 0);
    REQUIRE(
      ftruncate(fileno(file), ftello(file) - (last_entry.size() / 2)) == 0);
  }
  REQUIRE(fflush(file) == 0);
  LOG_DEBUG_FMT("Corrupted ledger file {}", ledger_file);
}

TEST_CASE("Recovery resilience")
{
  auto dir = AutoDeleteFolder(ledger_dir);
  fs::remove_all(ledger_dir);

  size_t max_read_cache_size = 2;
  size_t chunk_threshold = 50;
  size_t chunk_count = 1;

  size_t last_idx = 0;
  Ledger ledger(ledger_dir, wf, chunk_threshold);
  TestEntrySubmitter entry_submitter(ledger);

  INFO("Write many entries on first ledger");
  {
    // Writing some committed chunks
    initialise_ledger(entry_submitter, chunk_threshold, chunk_count);
    last_idx = entry_submitter.get_last_idx();
    ledger.commit(last_idx);
  }

  SUBCASE("Corrupt table offset in committed chunk")
  {
    REQUIRE(number_of_files_in_ledger_dir() == 1);
    for (auto const& f : fs::directory_iterator(ledger_dir))
    {
      corrupt_ledger_file(f.path(), true /* corrupt_table_offset */);
    }

    // Corrupted ledger file is ignored
    Ledger new_ledger(ledger_dir, wf, chunk_threshold);
    TestEntrySubmitter entry_submitter(new_ledger);
    entry_submitter.write(true);
    REQUIRE(entry_submitter.get_last_idx() == 1);
  }

  SUBCASE("Corrupt first entry header in uncommitted chunk")
  {
    // Create new uncommitted ledger chunk
    entry_submitter.write(true);
    REQUIRE(number_of_files_in_ledger_dir() == 2);

    for (auto const& f : fs::directory_iterator(ledger_dir))
    {
      if (!asynchost::is_ledger_file_name_committed(f.path().filename()))
      {
        corrupt_ledger_file(f.path(), false, true /* corrupt_first_hdr */);
      }
    }

    // Uncommitted ledger file with no valid entry is deleted
    Ledger new_ledger(ledger_dir, wf, chunk_threshold);
    REQUIRE(number_of_files_in_ledger_dir() == 1);
    TestEntrySubmitter entry_submitter(new_ledger, new_ledger.get_last_idx());
    entry_submitter.write(true);
  }

  SUBCASE("Corrupt last entry")
  {
    // Create new uncommitted ledger chunk with two entries
    entry_submitter.write(true);
    entry_submitter.write(true);
    size_t last_idx = entry_submitter.get_last_idx();

    REQUIRE(number_of_files_in_ledger_dir() == 2);

    for (auto const& f : fs::directory_iterator(ledger_dir))
    {
      if (!asynchost::is_ledger_file_name_committed(f.path().filename()))
      {
        corrupt_ledger_file(
          f.path(), false, false, true /* corrupt_last_entry */);
      }
    }

    // Uncommitted ledger file with no valid entry is deleted
    Ledger new_ledger(ledger_dir, wf, chunk_threshold);
    // Corrupted entry has been discarded
    REQUIRE(new_ledger.get_last_idx() == last_idx - 1);
    REQUIRE(number_of_files_in_ledger_dir() == 2);

    TestEntrySubmitter entry_submitter(new_ledger, new_ledger.get_last_idx());
    entry_submitter.write(true);
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
    REQUIRE_FALSE(ledger.read_entries(1, last_committed_idx).has_value());
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

    auto snap = fmt::format("snapshot_{}_{}", snapshot_idx, evidence_idx);
    auto snap_committed = fmt::format("{}.committed", snap);

    INFO("Identify snapshot files");
    {
      REQUIRE(is_snapshot_file(snap));
      REQUIRE(is_snapshot_file(snap_committed));
      REQUIRE_FALSE(is_snapshot_file("ledger_1-2"));
      REQUIRE_FALSE(is_snapshot_file("ledger_1-2.committed"));
    }

    INFO("Identify committed files");
    {
      REQUIRE_FALSE(is_snapshot_file_committed(snap));
      REQUIRE(is_snapshot_file_committed(snap_committed));
    }

    INFO("Get snapshot idx");
    {
      REQUIRE(get_snapshot_idx_from_file_name(snap) == snapshot_idx);
      REQUIRE(get_snapshot_idx_from_file_name(snap_committed) == snapshot_idx);
    }

    INFO("Get evidence idx");
    {
      REQUIRE(get_snapshot_evidence_idx_from_file_name(snap) == evidence_idx);
      REQUIRE(
        get_snapshot_evidence_idx_from_file_name(snap_committed) ==
        evidence_idx);
    }
  }
}

TEST_CASE("Generate and commit snapshots" * doctest::test_suite("snapshot"))
{
  auto snap_dir = AutoDeleteFolder(snapshot_dir);
  auto snap_ro_dir = AutoDeleteFolder(snapshot_dir_read_only);
  fs::create_directory(snapshot_dir_read_only);

  SnapshotManager snapshots(snapshot_dir, snapshot_dir_read_only);

  size_t snapshot_interval = 5;
  size_t snapshot_count = 5;
  size_t last_snapshot_idx = 0;

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
      const auto& snapshot = latest_committed_snapshot->second;
      REQUIRE(get_snapshot_idx_from_file_name(snapshot) == i);
      last_snapshot_idx = i;
      REQUIRE(get_snapshot_evidence_idx_from_file_name(snapshot) == i + 1);
      REQUIRE_FALSE(
        get_evidence_commit_idx_from_file_name(snapshot).has_value());
    }
  }

  INFO("Move committed snapshots to ro directory");
  {
    for (auto const& f : fs::directory_iterator(snapshot_dir))
    {
      fs::copy(f.path(), snapshot_dir_read_only);
      fs::remove(f.path());
    }

    auto latest_committed_snapshot = snapshots.find_latest_committed_snapshot();
    REQUIRE(latest_committed_snapshot.has_value());
    const auto& snapshot = latest_committed_snapshot->second;
    REQUIRE(get_snapshot_idx_from_file_name(snapshot) == last_snapshot_idx);
  }

  INFO("Commit and retrieve new snapshot");
  {
    size_t new_snapshot_idx = last_snapshot_idx + 1;
    snapshots.write_snapshot(
      new_snapshot_idx,
      new_snapshot_idx + 1,
      dummy_snapshot.data(),
      dummy_snapshot.size());
    snapshots.commit_snapshot(
      new_snapshot_idx, dummy_receipt.data(), dummy_receipt.size());

    auto latest_committed_snapshot = snapshots.find_latest_committed_snapshot();
    REQUIRE(latest_committed_snapshot.has_value());
    const auto& snapshot = latest_committed_snapshot->second;
    REQUIRE(get_snapshot_idx_from_file_name(snapshot) == new_snapshot_idx);
  }
}

TEST_CASE("Chunking according to entry header flag")
{
  auto dir = AutoDeleteFolder(ledger_dir);

  size_t chunk_threshold = 30;
  size_t entries_per_chunk = get_entries_per_chunk(chunk_threshold);
  Ledger ledger(ledger_dir, wf, chunk_threshold);
  TestEntrySubmitter entry_submitter(ledger);

  bool is_committable = true;

  INFO("Add a few entries");
  {
    for (int i = 0; i < entries_per_chunk / 2; i++)
    {
      entry_submitter.write(is_committable);
    }

    // Up to here everything should be in one ledger file
    REQUIRE(number_of_files_in_ledger_dir() == 1);
  }

  INFO("Write an entry with the ledger chunking after header flag enabled");
  {
    entry_submitter.write(
      is_committable, kv::EntryFlags::FORCE_LEDGER_CHUNK_AFTER);

    REQUIRE(number_of_files_in_ledger_dir() == 1);

    // New entry is written in a new chunk
    entry_submitter.write(false);
    REQUIRE(number_of_files_in_ledger_dir() == 2);
  }

  INFO("Add more entries to trigger normal chunking");
  {
    for (int i = 0; i < entries_per_chunk; i++)
    {
      entry_submitter.write(is_committable);
    }

    REQUIRE(number_of_files_in_ledger_dir() == 3);
  }

  INFO("Write an entry with the ledger chunking before header flag enabled");
  {
    auto ledger_files_count = number_of_files_in_ledger_dir();
    entry_submitter.write(
      is_committable, kv::EntryFlags::FORCE_LEDGER_CHUNK_BEFORE);

    // Forcing a new chunk before creating a new chunk to store this entry
    REQUIRE(number_of_files_in_ledger_dir() == ledger_files_count + 1);
  }
}

TEST_CASE("Recovery")
{
  auto dir = AutoDeleteFolder(ledger_dir);

  size_t chunk_threshold = 30;
  size_t entries_per_chunk = get_entries_per_chunk(chunk_threshold);

  SUBCASE("Enable and complete recovery")
  {
    Ledger ledger(ledger_dir, wf, chunk_threshold);
    TestEntrySubmitter entry_submitter(ledger);
    size_t pre_recovery_last_idx = 0;

    INFO("Write many entries on ledger");
    {
      size_t chunk_count = 5;
      initialise_ledger(entry_submitter, chunk_threshold, chunk_count);
      pre_recovery_last_idx = entry_submitter.get_last_idx();
      ledger.commit(pre_recovery_last_idx);
    }

    INFO("Enable recovery");
    {
      REQUIRE(number_of_recovery_files_in_ledger_dir() == 0);
      ledger.set_recovery_start_idx(pre_recovery_last_idx);

      entry_submitter.write(true);
      REQUIRE(number_of_recovery_files_in_ledger_dir() == 1);
    }

    INFO("Truncation does not affect recovery mode");
    {
      entry_submitter.truncate(pre_recovery_last_idx);
      REQUIRE(number_of_recovery_files_in_ledger_dir() == 0);
      entry_submitter.write(true);
      REQUIRE(number_of_recovery_files_in_ledger_dir() == 1);
    }

    INFO("Create and commit more recovery chunks");
    {
      for (size_t i = 0; i < entries_per_chunk; i++)
      {
        entry_submitter.write(true);
      }
      REQUIRE(number_of_recovery_files_in_ledger_dir() == 2);

      // Reading from uncommitted recovery chunks is OK
      read_entries_range_from_ledger(ledger, 1, entry_submitter.get_last_idx());

      // Committed files are also marked .recovery
      auto initial_number_committed_files =
        number_of_committed_files_in_ledger_dir(true);
      ledger.commit(entry_submitter.get_last_idx());
      REQUIRE(number_of_recovery_files_in_ledger_dir() == 2);
      REQUIRE(
        number_of_committed_files_in_ledger_dir(true) ==
        initial_number_committed_files + 1);

      // Reading from committed recovery chunks is OK
      read_entries_range_from_ledger(ledger, 1, entry_submitter.get_last_idx());
    }

    INFO("Finally open the ledger");
    {
      ledger.complete_recovery();

      // All recovery chunks are gone
      REQUIRE(number_of_recovery_files_in_ledger_dir() == 0);

      // Further chunks are not marked as recovery
      for (size_t i = 0; i < entries_per_chunk; i++)
      {
        entry_submitter.write(true);
      }
      REQUIRE(number_of_recovery_files_in_ledger_dir() == 0);

      // Even ones that are committed
      ledger.commit(entry_submitter.get_last_idx());
      REQUIRE(number_of_recovery_files_in_ledger_dir() == 0);
    }
  }

  SUBCASE("Recover ledger with recovery chunks")
  {
    Ledger ledger(ledger_dir, wf, chunk_threshold);
    TestEntrySubmitter entry_submitter(ledger);
    size_t pre_recovery_last_idx = 0;
    size_t last_idx = 0;

    INFO("Write many entries on ledger");
    {
      size_t chunk_count = 5;
      initialise_ledger(entry_submitter, chunk_threshold, chunk_count);
      pre_recovery_last_idx = entry_submitter.get_last_idx();
      ledger.commit(pre_recovery_last_idx);
    }

    INFO("Enable recovery");
    {
      REQUIRE(number_of_recovery_files_in_ledger_dir() == 0);
      ledger.set_recovery_start_idx(pre_recovery_last_idx);

      for (size_t i = 0; i < entries_per_chunk + 1; i++)
      {
        entry_submitter.write(true);
      }
      REQUIRE(number_of_recovery_files_in_ledger_dir() == 2);
      last_idx = entry_submitter.get_last_idx();
    }

    INFO("New ledger recovery in read-only ledger directory");
    {
      auto new_ledger_dir = "new_ledger_dir";
      Ledger new_ledger(
        new_ledger_dir,
        wf,
        chunk_threshold,
        ledger_max_read_cache_files_default,
        {ledger_dir});

      // Recovery files in read-only ledger directory are ignored on startup
      REQUIRE(number_of_recovery_files_in_ledger_dir() == 2);
      REQUIRE_THROWS(read_entries_range_from_ledger(new_ledger, 1, last_idx));

      // Entries pre-recovery can still be read
      read_entries_range_from_ledger(new_ledger, 1, pre_recovery_last_idx);
    }

    INFO("New ledger recovery in main ledger directory");
    {
      Ledger new_ledger(ledger_dir, wf, chunk_threshold);

      // Recovery files in main ledger directory are automatically deleted on
      // ledger creation
      REQUIRE(number_of_recovery_files_in_ledger_dir() == 0);
      REQUIRE_THROWS(read_entries_range_from_ledger(new_ledger, 1, last_idx));

      // Entries pre-recovery can still be read
      read_entries_range_from_ledger(new_ledger, 1, pre_recovery_last_idx);
    }
  }
}

TEST_CASE("Recover both ledger dirs")
{
  auto dir = AutoDeleteFolder(ledger_dir);
  auto dir2 = AutoDeleteFolder(ledger_dir_read_only);

  fs::create_directory(ledger_dir_read_only);

  size_t chunk_threshold = 30;
  size_t entries_per_chunk = get_entries_per_chunk(chunk_threshold);
  size_t last_idx = 0;
  size_t chunk_count = 3;

  INFO("Create ledger");
  {
    Ledger ledger(ledger_dir, wf, chunk_threshold);
    TestEntrySubmitter entry_submitter(ledger);

    initialise_ledger(entry_submitter, chunk_threshold, chunk_count);
    last_idx = ledger.get_last_idx();
    ledger.commit(last_idx);

    move_all_from_to(
      ledger_dir, ledger_dir_read_only, std::nullopt, false /* copy */);

    // Delete last committed file from ledger directory so that new ledger
    // starts with main ledger directory behind read-only ledger directory
    REQUIRE(fs::remove(fs::path(ledger_dir) / "ledger_5-6.committed"));
  }

  INFO("Recover from both ledger dirs");
  {
    Ledger ledger(ledger_dir, wf, chunk_threshold, 0, {ledger_dir_read_only});
    TestEntrySubmitter entry_submitter(ledger, last_idx);

    for (int i = 0; i < entries_per_chunk * chunk_count; i++)
    {
      entry_submitter.write(true);
    }
    read_entries_range_from_ledger(ledger, 1, ledger.get_last_idx());
    ledger.commit(ledger.get_last_idx());
  }
}

int main(int argc, char** argv)
{
  logger::config::default_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}