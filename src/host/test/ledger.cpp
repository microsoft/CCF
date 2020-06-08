// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../ds/serialized.h"
#include "../multiple_ledger.h"

#include <doctest/doctest.h>
#include <string>

using frame_header_type = uint32_t;
static constexpr size_t frame_header_size = sizeof(frame_header_type);
static constexpr auto ledger_dir = "ledger_dir";
ringbuffer::Circuit eio(1024);
auto wf = ringbuffer::WriterFactory(eio);

// Ledger entry type
template <typename T>
struct LedgerEntry
{
  T value_ = 0;

  uint8_t* data()
  {
    return reinterpret_cast<uint8_t*>(&value_);
  }

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
  LedgerEntry(const std::vector<uint8_t>& raw)
  {
    const uint8_t* data = raw.data();
    size_t size = raw.size();
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

void verify_framed_entries_range(
  const std::vector<uint8_t>& framed_entries, size_t from, size_t to)
{
  size_t idx = from;
  for (int i = 0; i < framed_entries.size();)
  {
    const uint8_t* data = &framed_entries[i];
    size_t size = framed_entries.size() - i;

    auto frame = serialized::read<frame_header_type>(data, size);
    auto entry = serialized::read(data, size, frame);
    LOG_DEBUG_FMT("Value is {}", TestLedgerEntry(entry).value());
    REQUIRE(TestLedgerEntry(entry).value() == idx);
    i += frame_header_size + frame;
    idx++;
  }

  REQUIRE(idx == to + 1);
}

void read_entry_from_ledger(asynchost::MultipleLedger& ledger, size_t idx)
{
  REQUIRE(TestLedgerEntry(ledger.read_entry(idx)).value() == idx);
}

void read_entries_range_from_ledger(
  const asynchost::MultipleLedger& ledger, size_t from, size_t to)
{
  verify_framed_entries_range(ledger.read_framed_entries(from, to), from, to);
}

// Keeps track of ledger entries written to the ledger.
// An entry submitted at index i has for value i so that it is easy to verify
// that the ledger entry returned by the ledger at a specific index is right.
class TestEntrySubmitter
{
private:
  asynchost::MultipleLedger& ledger;
  size_t last_idx;

public:
  TestEntrySubmitter(
    asynchost::MultipleLedger& ledger, size_t initial_last_idx = 0) :
    ledger(ledger),
    last_idx(initial_last_idx)
  {}

  size_t get_last_idx()
  {
    return last_idx;
  }

  void write(bool is_committable)
  {
    auto e = TestLedgerEntry(++last_idx);
    REQUIRE(
      ledger.write_entry(e.data(), sizeof(TestLedgerEntry), is_committable) ==
      last_idx);
  }

  void truncate(size_t idx)
  {
    ledger.truncate(idx);

    // Check that we can read until truncated entry but cannot read after it
    read_entries_range_from_ledger(ledger, 1, idx);
    REQUIRE(ledger.read_framed_entries(1, idx + 1).size() == 0);

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
  // size of each _framed_ entry
  return ceil(
    (static_cast<float>(chunk_threshold - sizeof(size_t))) /
    (frame_header_size + sizeof(TestLedgerEntry)));
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
  LOG_DEBUG_FMT("Submitting {} txs", entries_per_chunk * chunk_count);

  for (int i = 0; i < entries_per_chunk * chunk_count; i++)
  {
    entry_submitter.write(is_committable);
  }

  REQUIRE(number_of_files_in_ledger_dir() == chunk_count);

  return entries_per_chunk;
}

TEST_CASE("Regular chunking")
{
  fs::remove_all(ledger_dir);

  INFO("Cannot create a ledger with a chunk threshold of 0");
  {
    size_t chunk_threshold = 0;
    REQUIRE_THROWS(asynchost::MultipleLedger(ledger_dir, wf, chunk_threshold));
  }

  size_t chunk_threshold = 30;
  size_t entries_per_chunk = get_entries_per_chunk(chunk_threshold);
  asynchost::MultipleLedger ledger(ledger_dir, wf, chunk_threshold);
  TestEntrySubmitter entry_submitter(ledger);

  size_t end_of_first_chunk_idx = 0;
  bool is_committable = true;

  INFO("Not quite enough entries before chunk threshold");
  {
    is_committable = true;
    for (int i = 0; i < entries_per_chunk; i++)
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
    end_of_first_chunk_idx = entry_submitter.get_last_idx() - 1;
    REQUIRE(number_of_files_in_ledger_dir() == 2);
  }

  INFO(
    "Submitting more committable entries trigger chunking at regular interval");
  {
    size_t chunk_count = 2;
    LOG_DEBUG_FMT("Submitting {} txs", entries_per_chunk * chunk_count);

    for (int i = 0; i < entries_per_chunk * chunk_count; i++)
    {
      entry_submitter.write(is_committable);
    }
  }

  INFO("Reading entries across all chunks");
  {
    is_committable = false;
    entry_submitter.write(is_committable);
    auto last_idx = entry_submitter.get_last_idx();

    // Reading the last entry succeeds
    read_entry_from_ledger(ledger, last_idx);

    // Reading in the future fails
    REQUIRE(ledger.read_entry(last_idx + 1).size() == 0);

    // Reading at 0 fails
    REQUIRE(ledger.read_entry(0).size() == 0);

    // Reading in the past succeeds
    read_entry_from_ledger(ledger, 1);
    read_entry_from_ledger(ledger, end_of_first_chunk_idx);
    read_entry_from_ledger(ledger, end_of_first_chunk_idx + 1);
    read_entry_from_ledger(ledger, last_idx);
  }

  INFO("Reading range of entries across all chunks");
  {
    auto last_idx = entry_submitter.get_last_idx();

    // Reading from 0 fails
    REQUIRE(ledger.read_framed_entries(0, end_of_first_chunk_idx).size() == 0);

    // Reading in the future fails
    REQUIRE(ledger.read_framed_entries(1, last_idx + 1).size() == 0);
    REQUIRE(ledger.read_framed_entries(last_idx, last_idx + 1).size() == 0);

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
  fs::remove_all(ledger_dir);

  size_t chunk_threshold = 30;
  asynchost::MultipleLedger ledger(ledger_dir, wf, chunk_threshold);
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
    entry_submitter.write(true);
  }

  INFO("Truncating any entry in penultimate chunk closes latest file");
  {
    entry_submitter.truncate(last_idx - 2);
    REQUIRE(number_of_files_in_ledger_dir() == chunks_so_far - 1);
    entry_submitter.write(true);
    entry_submitter.write(true);
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

size_t number_of_compacted_files_in_ledger_dir()
{
  size_t compacted_file_count = 0;
  for (auto const& f : fs::directory_iterator(ledger_dir))
  {
    LOG_DEBUG_FMT("File: {}", f.path());
    if (asynchost::is_ledger_file_complete(f.path().string()))
    {
      compacted_file_count++;
    }
  }

  return compacted_file_count;
}

TEST_CASE("Compaction")
{
  fs::remove_all(ledger_dir);

  size_t chunk_threshold = 30;
  asynchost::MultipleLedger ledger(ledger_dir, wf, chunk_threshold);
  TestEntrySubmitter entry_submitter(ledger);

  size_t chunk_count = 3;
  size_t end_of_first_chunk_idx =
    initialise_ledger(entry_submitter, chunk_threshold, chunk_count);

  entry_submitter.write(true);
  size_t last_idx = entry_submitter.get_last_idx();
  REQUIRE(number_of_compacted_files_in_ledger_dir() == 0);

  INFO("Compacting end of first chunk");
  {
    ledger.compact(end_of_first_chunk_idx);
    REQUIRE(number_of_compacted_files_in_ledger_dir() == 1);
  }

  INFO("Compacting in the middle on complete chunk");
  {
    ledger.compact(end_of_first_chunk_idx + 1);
    REQUIRE(number_of_compacted_files_in_ledger_dir() == 1);
    ledger.compact(2 * end_of_first_chunk_idx - 1);
    REQUIRE(number_of_compacted_files_in_ledger_dir() == 1);
  }

  INFO("Compacting at the end of a complete chunk");
  {
    ledger.compact(2 * end_of_first_chunk_idx);
    REQUIRE(number_of_compacted_files_in_ledger_dir() == 2);
  }

  INFO("Compacting at latest index prepared");
  {
    ledger.compact(last_idx - 1);
    REQUIRE(number_of_compacted_files_in_ledger_dir() == 3);
  }

  INFO("Compacting incomplete chunk");
  {
    ledger.compact(last_idx);
    REQUIRE(number_of_compacted_files_in_ledger_dir() == 3);
  }

  // TODO: This is a limitation for now.
  // This is not ideal as the latest chunk would not get compacted until it's
  // reached the threshold, e.g. during inactivity
  INFO("Even though latest chunk is complete, it does not get compacted");
  {
    entry_submitter.write(true);
    entry_submitter.write(true);
    last_idx = entry_submitter.get_last_idx();
    ledger.compact(last_idx);
    REQUIRE(number_of_compacted_files_in_ledger_dir() == 3);
    entry_submitter.write(true);
    last_idx = entry_submitter.get_last_idx();
    ledger.compact(last_idx);
    REQUIRE(number_of_compacted_files_in_ledger_dir() == 4);
  }

  INFO("Ledger cannot be truncated earlier than compaction");
  {
    ledger.truncate(1); // No effect
    read_entries_range_from_ledger(ledger, 1, last_idx);

    ledger.truncate(2 * end_of_first_chunk_idx); // No effect
    read_entries_range_from_ledger(ledger, 1, last_idx);
  }
}

TEST_CASE("Restore existing ledger")
{
  fs::remove_all(ledger_dir);

  size_t chunk_threshold = 30;
  size_t last_idx = 0;
  size_t end_of_first_chunk_idx = 0;
  size_t chunk_count = 3;

  SUBCASE("Restoring uncompacted chunks")
  {
    INFO("Initialise first ledger with all but one complete chunk");
    {
      asynchost::MultipleLedger ledger(ledger_dir, wf, chunk_threshold);
      TestEntrySubmitter entry_submitter(ledger);

      end_of_first_chunk_idx =
        initialise_ledger(entry_submitter, chunk_threshold, chunk_count);

      entry_submitter.write(true);
      last_idx = entry_submitter.get_last_idx();
    }

    asynchost::MultipleLedger ledger2(ledger_dir, wf, chunk_threshold);
    read_entries_range_from_ledger(ledger2, 1, last_idx);

    // Restored ledger can be written to
    TestEntrySubmitter entry_submitter(ledger2, last_idx);
    entry_submitter.write(true);
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
      asynchost::MultipleLedger ledger(ledger_dir, wf, chunk_threshold);
      TestEntrySubmitter entry_submitter(ledger);

      end_of_first_chunk_idx =
        initialise_ledger(entry_submitter, chunk_threshold, chunk_count);

      entry_submitter.truncate(end_of_first_chunk_idx + 1);
      last_idx = entry_submitter.get_last_idx();
    }

    asynchost::MultipleLedger ledger2(ledger_dir, wf, chunk_threshold);
    read_entries_range_from_ledger(ledger2, 1, last_idx);
  }

  SUBCASE("Restoring some compacted chunks")
  {
    auto compacted_idx = 0;
    INFO("Initialise first ledger with compacted chunks");
    {
      asynchost::MultipleLedger ledger(ledger_dir, wf, chunk_threshold);
      TestEntrySubmitter entry_submitter(ledger);

      end_of_first_chunk_idx =
        initialise_ledger(entry_submitter, chunk_threshold, chunk_count);

      compacted_idx = 2 * end_of_first_chunk_idx + 1;
      entry_submitter.write(true);
      ledger.compact(compacted_idx);
      last_idx = entry_submitter.get_last_idx();
    }

    asynchost::MultipleLedger ledger2(ledger_dir, wf, chunk_threshold);
    read_entries_range_from_ledger(ledger2, 1, last_idx);

    // Restored ledger cannot be truncated before last idx of last compacted
    // chunk
    TestEntrySubmitter entry_submitter(ledger2, last_idx);
    entry_submitter.truncate(compacted_idx - 1); // Successful

    ledger2.truncate(compacted_idx - 2); // Unsuccessful
    read_entries_range_from_ledger(ledger2, 1, end_of_first_chunk_idx);
  }

  SUBCASE("Restoring ledger with different chunking threshold")
  {
    INFO("Initialise first ledger with compacted chunks");
    {
      asynchost::MultipleLedger ledger(ledger_dir, wf, chunk_threshold);
      TestEntrySubmitter entry_submitter(ledger);

      end_of_first_chunk_idx =
        initialise_ledger(entry_submitter, chunk_threshold, chunk_count);

      entry_submitter.write(true);
      last_idx = entry_submitter.get_last_idx();
    }

    INFO("Restore new ledger with twice the chunking threshold");
    {
      asynchost::MultipleLedger ledger2(ledger_dir, wf, 2 * chunk_threshold);
      read_entries_range_from_ledger(ledger2, 1, last_idx);

      TestEntrySubmitter entry_submitter(ledger2, last_idx);

      size_t orig_number_files = number_of_files_in_ledger_dir();
      while (number_of_files_in_ledger_dir() == orig_number_files)
      {
        LOG_DEBUG_FMT("Submitting new entry..............");
        entry_submitter.write(true);
      }
      last_idx = entry_submitter.get_last_idx();
    }

    INFO("Restore new ledger with half the chunking threshold");
    {
      asynchost::MultipleLedger ledger2(ledger_dir, wf, chunk_threshold / 2);
      read_entries_range_from_ledger(ledger2, 1, last_idx);

      TestEntrySubmitter entry_submitter(ledger2, last_idx);

      size_t orig_number_files = number_of_files_in_ledger_dir();
      while (number_of_files_in_ledger_dir() == orig_number_files)
      {
        LOG_DEBUG_FMT("Submitting new entry..............");
        entry_submitter.write(true);
      }
    }
  }
}
