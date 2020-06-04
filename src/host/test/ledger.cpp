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

template <typename T>
struct LedgerEntry
{
  T value_ = 0;

  uint8_t* increment_value()
  {
    value_++;
    return reinterpret_cast<uint8_t*>(&value_);
  }

  auto value() const
  {
    return value_;
  }

  LedgerEntry() = default;
  LedgerEntry(const std::vector<uint8_t>& raw)
  {
    const uint8_t* data = raw.data();
    size_t size = raw.size();
    value_ = serialized::read<T>(data, size);
  }
};
using TestLedgerEntry = LedgerEntry<uint64_t>;

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
    LOG_DEBUG_FMT("Value is {}", entry[0]);
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

TEST_CASE("Regular chunking")
{
  INFO("Cannot create a ledger with a chunk threshold of 0");
  {
    size_t chunk_threshold = 0;
    REQUIRE_THROWS(asynchost::MultipleLedger(ledger_dir, wf, chunk_threshold));
  }

  size_t chunk_threshold = 30;
  asynchost::MultipleLedger ledger(ledger_dir, wf, chunk_threshold);

  TestLedgerEntry dummy_entry;

  // The number of entries per chunk is a function of the threshold and the size
  // of each _framed_ entry
  size_t entries_per_chunk = ceil(
    static_cast<float>(chunk_threshold) /
    (frame_header_size + sizeof(TestLedgerEntry)));

  size_t last_idx = 0;
  size_t end_of_chunk_idx;
  bool is_committable;

  INFO("Not quite enough entries before chunk threshold");
  {
    is_committable = true;
    for (int i = 0; i < entries_per_chunk - 1; i++)
    {
      REQUIRE(
        ledger.write_entry(
          dummy_entry.increment_value(),
          sizeof(TestLedgerEntry),
          is_committable) == ++last_idx);
    }

    // Writing committable entries without reaching the chunk threshold
    // does not create new ledger files
    REQUIRE(number_of_files_in_ledger_dir() == 1);
  }

  INFO("Additional non-committable entries do not trigger chunking");
  {
    is_committable = false;
    REQUIRE(
      ledger.write_entry(
        dummy_entry.increment_value(),
        sizeof(TestLedgerEntry),
        is_committable) == ++last_idx);
    REQUIRE(
      ledger.write_entry(
        dummy_entry.increment_value(),
        sizeof(TestLedgerEntry),
        is_committable) == ++last_idx);

    REQUIRE(number_of_files_in_ledger_dir() == 1);
  }

  INFO("Additional committable entry triggers chunking");
  {
    is_committable = true;
    REQUIRE(
      ledger.write_entry(
        dummy_entry.increment_value(),
        sizeof(TestLedgerEntry),
        is_committable) == ++last_idx);

    end_of_chunk_idx = last_idx;
    REQUIRE(number_of_files_in_ledger_dir() == 2);
  }

  INFO(
    "Submitting more committable entries trigger chunking at regular interval");
  {
    size_t chunks_so_far = number_of_files_in_ledger_dir();

    size_t expected_number_of_chunks = 2;
    LOG_DEBUG_FMT(
      "Submitting {} txs", entries_per_chunk * expected_number_of_chunks);
    for (int i = 0; i < entries_per_chunk * expected_number_of_chunks; i++)
    {
      is_committable = true;
      REQUIRE(
        ledger.write_entry(
          dummy_entry.increment_value(),
          sizeof(TestLedgerEntry),
          is_committable) == ++last_idx);
    }
    REQUIRE(
      number_of_files_in_ledger_dir() ==
      expected_number_of_chunks + chunks_so_far);
  }

  INFO("Reading entries across all chunks");
  {
    is_committable = false;
    REQUIRE(
      ledger.write_entry(
        dummy_entry.increment_value(),
        sizeof(TestLedgerEntry),
        is_committable) == ++last_idx);

    // Reading the last entry succeeds
    read_entry_from_ledger(ledger, last_idx);

    // Reading in the future fails
    REQUIRE(ledger.read_entry(last_idx + 1).size() == 0);

    // Reading at 0 fails
    REQUIRE(ledger.read_entry(0).size() == 0);

    // Reading in the past succeeds
    read_entry_from_ledger(ledger, 1);
    read_entry_from_ledger(ledger, end_of_chunk_idx);
    read_entry_from_ledger(ledger, end_of_chunk_idx + 1);
    read_entry_from_ledger(ledger, last_idx);
  }

  INFO("Reading range of entries across all chunks");
  {
    LOG_DEBUG_FMT("Reading range of entries...");

    // Reading from 0 fails
    REQUIRE(ledger.read_framed_entries(0, end_of_chunk_idx).size() == 0);

    // Reading in the future fails
    REQUIRE(ledger.read_framed_entries(1, last_idx + 1).size() == 0);
    REQUIRE(ledger.read_framed_entries(last_idx, last_idx + 1).size() == 0);

    std::vector<uint8_t> framed_entries;

    // Reading from the start to any valid index succeeds
    read_entries_range_from_ledger(ledger, 1, end_of_chunk_idx);
    read_entries_range_from_ledger(ledger, 1, end_of_chunk_idx + 1);
    read_entries_range_from_ledger(ledger, 1, last_idx - 1);
    read_entries_range_from_ledger(ledger, 1, last_idx);

    // Reading from just before/after a chunk succeeds
    read_entries_range_from_ledger(
      ledger, end_of_chunk_idx, end_of_chunk_idx + 1);
    read_entries_range_from_ledger(ledger, end_of_chunk_idx, last_idx - 1);
    read_entries_range_from_ledger(ledger, end_of_chunk_idx, last_idx);
    read_entries_range_from_ledger(ledger, end_of_chunk_idx + 1, last_idx);
    read_entries_range_from_ledger(ledger, end_of_chunk_idx + 1, last_idx - 1);
  }
  // fs::remove_all(ledger_dir);
}

// TEST_CASE("Reading range of entries") {}
