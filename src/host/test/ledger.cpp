// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../ds/serialized.h"
#include "../multiple_ledger.h"

#include <doctest/doctest.h>
#include <string>

static constexpr auto ledger_dir = "ledger_dir";
ringbuffer::Circuit eio(1024);
auto wf = ringbuffer::WriterFactory(eio);

struct LedgerEntry
{
  uint8_t value_ = 0;

  uint8_t* value()
  {
    value_++;
    return reinterpret_cast<uint8_t*>(&value_);
  }
};

static constexpr size_t frame_header_size = sizeof(uint32_t);

size_t number_of_files_in_ledger_dir()
{
  size_t file_count = 0;
  for (auto const& f : fs::directory_iterator(ledger_dir))
  {
    file_count++;
  }
  return file_count;
}

size_t count_entries(const std::vector<uint8_t>& framed_entries)
{
  size_t entries_count = 0;
  for (int i = 0; i < framed_entries.size();)
  {
    const uint8_t* data = &framed_entries[i];
    size_t size = framed_entries.size() - i;

    auto frame = serialized::read<uint32_t>(data, size);
    // LOG_DEBUG_FMT("Frame is {}", frame);
    auto entry = serialized::read(data, size, frame);
    LOG_DEBUG_FMT("Value is {}", entry[0]);
    entries_count++;
    i += frame_header_size + frame;
  }

  return entries_count;
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

  LedgerEntry dummy_entry;
  size_t tx_per_chunk = ceil(
    static_cast<float>(chunk_threshold) /
    (frame_header_size + sizeof(LedgerEntry)));

  size_t last_idx = 0;
  size_t end_of_chunk_idx;
  bool is_committable;

  INFO("Not quite enough entries before chunk threshold");
  {
    is_committable = true;
    for (int i = 0; i < tx_per_chunk - 1; i++)
    {
      REQUIRE(
        ledger.write_entry(
          dummy_entry.value(), sizeof(LedgerEntry), is_committable) ==
        ++last_idx);
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
        dummy_entry.value(), sizeof(LedgerEntry), is_committable) ==
      ++last_idx);
    REQUIRE(
      ledger.write_entry(
        dummy_entry.value(), sizeof(LedgerEntry), is_committable) ==
      ++last_idx);

    REQUIRE(number_of_files_in_ledger_dir() == 1);
  }

  INFO("Additional committable entry triggers chunking");
  {
    is_committable = true;
    REQUIRE(
      ledger.write_entry(
        dummy_entry.value(), sizeof(LedgerEntry), is_committable) ==
      ++last_idx);

    end_of_chunk_idx = last_idx;
    REQUIRE(number_of_files_in_ledger_dir() == 2);
  }

  INFO(
    "Submitting more committable entries trigger chunking at regular interval");
  {
    size_t chunks_so_far = number_of_files_in_ledger_dir();

    size_t expected_number_of_chunks = 2;
    LOG_DEBUG_FMT(
      "Submitting {} txs", tx_per_chunk * expected_number_of_chunks);
    for (int i = 0; i < tx_per_chunk * expected_number_of_chunks; i++)
    {
      is_committable = true;
      REQUIRE(
        ledger.write_entry(
          dummy_entry.value(), sizeof(LedgerEntry), is_committable) ==
        ++last_idx);
    }
    REQUIRE(
      number_of_files_in_ledger_dir() ==
      expected_number_of_chunks + chunks_so_far);
  }

  INFO("Reading entries from latest chunk");
  {
    is_committable = false;
    REQUIRE(
      ledger.write_entry(
        dummy_entry.value(), sizeof(LedgerEntry), is_committable) ==
      ++last_idx);

    REQUIRE(ledger.read_entry(last_idx).size() != 0);

    // Reading in the future fails
    REQUIRE(ledger.read_entry(last_idx + 1).size() == 0);

    // Reading in the past succeeds
    REQUIRE(ledger.read_entry(0).size() == 0);
    REQUIRE(ledger.read_entry(1).size() != 0);
    REQUIRE(ledger.read_entry(end_of_chunk_idx).size() != 0);
    REQUIRE(ledger.read_entry(end_of_chunk_idx + 1).size() != 0);
    REQUIRE(ledger.read_entry(last_idx - 1).size() != 0);
  }

  INFO("Reading range of entries");
  {
    LOG_DEBUG_FMT("Reading range of entries...");

    REQUIRE(ledger.read_framed_entries(0, end_of_chunk_idx).size() == 0);
    REQUIRE(ledger.read_framed_entries(1, last_idx + 1).size() == 0);

    std::vector<uint8_t> framed_entries;

    LOG_DEBUG_FMT("Nope...");
    // auto framed_entries = ledger.read_framed_entries(1, end_of_chunk_idx);
    // REQUIRE(count_entries(framed_entries) == end_of_chunk_idx);

    LOG_DEBUG_FMT("last_idx: {}", last_idx);
    framed_entries = ledger.read_framed_entries(1, end_of_chunk_idx + 1);
    REQUIRE(count_entries(framed_entries) == end_of_chunk_idx + 1);

    framed_entries =
      ledger.read_framed_entries(end_of_chunk_idx, end_of_chunk_idx + 1);
    REQUIRE(count_entries(framed_entries) == 2);
  }
  // fs::remove_all(ledger_dir);
}

// TEST_CASE("Reading range of entries") {}
