// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../ledger.h"
#include "../multiple_ledger.h"

#include <doctest/doctest.h>
#include <string>

// TEST_CASE("Read/Write test")
// {
//   ringbuffer::Circuit eio(1024);
//   auto wf = ringbuffer::WriterFactory(eio);

//   const std::vector<uint8_t> e1 = {1, 2, 3};
//   const std::vector<uint8_t> e2 = {5, 5, 6, 7};
//   {
//     asynchost::Ledger l("testlog", wf);
//     l.truncate(0);
//     REQUIRE(l.get_last_idx() == 0);
//     l.write_entry(e1.data(), e1.size());
//     l.write_entry(e2.data(), e2.size());
//   }

//   asynchost::Ledger l("testlog", wf);
//   REQUIRE(l.get_last_idx() == 2);
//   auto r1 = l.read_entry(1);
//   REQUIRE(e1 == r1);
//   auto r2 = l.read_entry(2);
//   REQUIRE(e2 == r2);
// }

// TEST_CASE("Entry sizes")
// {
//   ringbuffer::Circuit eio(2);
//   auto wf = ringbuffer::WriterFactory(eio);

//   const std::vector<uint8_t> e1 = {1, 2, 3};
//   const std::vector<uint8_t> e2 = {5, 5, 6, 7};

//   asynchost::Ledger l("testlog", wf);
//   l.truncate(0);
//   REQUIRE(l.get_last_idx() == 0);
//   l.write_entry(e1.data(), e1.size());
//   l.write_entry(e2.data(), e2.size());

//   REQUIRE(l.entry_size(1) == e1.size());
//   REQUIRE(l.entry_size(2) == e2.size());
//   REQUIRE(l.entry_size(0) == 0);
//   REQUIRE(l.entry_size(3) == 0);

//   REQUIRE(l.framed_entries_size(1, 1) == (e1.size() + sizeof(uint32_t)));
//   REQUIRE(
//     l.framed_entries_size(1, 2) ==
//     (e1.size() + sizeof(uint32_t) + e2.size() + sizeof(uint32_t)));

//   /*
//     auto e = l.read_framed_entries(1, 1);
//     for (auto c : e)
//       std::cout << std::hex << (int)c;
//     std::cout << std::endl;*/
// }

struct LedgerEntry
{
  uint8_t value_;

  uint8_t* value()
  {
    return reinterpret_cast<uint8_t*>(&value_);
  }
};

static constexpr size_t frame_header_size = sizeof(uint32_t);

size_t number_of_files_in_directory(const fs::path& dir)
{
  size_t file_count = 0;
  for (auto const& f : fs::directory_iterator(dir))
  {
    file_count++;
  }
  return file_count;
}

TEST_CASE("Multiple ledgers")
{
  ringbuffer::Circuit eio(1024);
  auto wf = ringbuffer::WriterFactory(eio);
  std::string ledger_dir = "ledger_dir";

  INFO("Cannot create a ledger with a chunk threshold of 0");
  {
    size_t chunk_threshold = 0;
    REQUIRE_THROWS(asynchost::MultipleLedger(ledger_dir, wf, chunk_threshold));
  }

  size_t chunk_threshold = 30;
  asynchost::MultipleLedger ledger(ledger_dir, wf, chunk_threshold);

  size_t tx_per_chunk = ceil(
    static_cast<float>(chunk_threshold) /
    (frame_header_size + sizeof(LedgerEntry)));

  LOG_DEBUG_FMT("tx per chunk: {}", tx_per_chunk);

  size_t last_idx = 0;

  LedgerEntry dummy_entry = {0x42};
  INFO("Not quite enough entries before chunk threshold");
  {
    bool is_committable = true;
    for (int i = 0; i < tx_per_chunk - 1; i++)
    {
      REQUIRE(
        ledger.write_entry(
          dummy_entry.value(), sizeof(LedgerEntry), is_committable) ==
        ++last_idx);
    }

    // Writing committable entries without reaching the chunk threshold
    // does not create new ledger files
    REQUIRE(number_of_files_in_directory(ledger_dir) == 1);
  }

  INFO("Additional non-committable entries do not trigger chunking");
  {
    bool is_committable = false;
    REQUIRE(
      ledger.write_entry(
        dummy_entry.value(), sizeof(LedgerEntry), is_committable) ==
      ++last_idx);
    REQUIRE(
      ledger.write_entry(
        dummy_entry.value(), sizeof(LedgerEntry), is_committable) ==
      ++last_idx);

    REQUIRE(number_of_files_in_directory(ledger_dir) == 1);
  }

  INFO("Additional committable entry triggers chunking");
  {
    bool is_committable = true;
    REQUIRE(
      ledger.write_entry(
        dummy_entry.value(), sizeof(LedgerEntry), is_committable) ==
      ++last_idx);
    REQUIRE(number_of_files_in_directory(ledger_dir) == 2);
  }

  INFO(
    "Submitting more committable entries trigger chunking at regular interval");
  {
    size_t chunks_so_far = number_of_files_in_directory(ledger_dir);

    size_t expected_number_of_chunks = 5;
    LOG_DEBUG_FMT(
      "Submitting {} txs", tx_per_chunk * expected_number_of_chunks);
    for (int i = 0; i < tx_per_chunk * expected_number_of_chunks; i++)
    {
      bool is_committable = true;
      REQUIRE(
        ledger.write_entry(
          dummy_entry.value(), sizeof(LedgerEntry), is_committable) ==
        ++last_idx);
    }
    REQUIRE(
      number_of_files_in_directory(ledger_dir) ==
      expected_number_of_chunks + chunks_so_far);
  }

  INFO("Reading entries from latest chunk");
  {
    LOG_DEBUG_FMT("Now, reading...");
    bool is_committable = false;
    REQUIRE(
      ledger.write_entry(
        dummy_entry.value(), sizeof(LedgerEntry), is_committable) ==
      ++last_idx);

    LOG_DEBUG_FMT("Wrote entry at idx {}", last_idx);
    REQUIRE(ledger.read_entry(last_idx).size() != 0);

    // Reading in the future fails
    REQUIRE(ledger.read_entry(last_idx + 1).size() == 0);

    // Reading in the past succeeds
    REQUIRE(ledger.read_entry(last_idx - 1).size() != 0);
  }
  // fs::remove_all(ledger_dir);
}