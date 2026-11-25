// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/raw_serialise.h"

#include <doctest/doctest.h>
#include <type_traits>

static_assert(std::is_copy_constructible_v<ccf::kv::RawWriter>);
static_assert(std::is_copy_assignable_v<ccf::kv::RawWriter>);
static_assert(std::is_move_constructible_v<ccf::kv::RawWriter>);
static_assert(std::is_move_assignable_v<ccf::kv::RawWriter>);

TEST_CASE("RawWriter encoded bytes" * doctest::test_suite("serialisation"))
{
  for (const size_t size :
       {0,
        1,
        8,
        9,
        63,
        64,
        65,
        127,
        128,
        129,
        255,
        256,
        257,
        511,
        512,
        513,
        4096,
        16384})
  {
    INFO(size);
    ccf::kv::RawWriter writer;
    const auto entry_type =
      ccf::kv::EntryType::WriteSetWithCommitEvidenceAndClaims;
    const uint64_t version = 0xfedcba9876543210;
    ccf::crypto::Sha256Hash hash;
    for (size_t i = 0; i < hash.h.size(); ++i)
      hash.h[i] = static_cast<uint8_t>(i);
    const std::string text("a\0b\xff", 4);
    const std::vector<uint64_t> versions{1, 256, 0xfedcba9876543210};
    const std::vector<uint8_t> vector(size, 0x80);
    const ccf::ByteVector bytes(size, uint8_t{0xff});

    const auto expected_size = sizeof(uint8_t) + sizeof(version) +
      hash.h.size() + sizeof(size_t) + text.size() + sizeof(size_t) +
      versions.size() * sizeof(uint64_t) + sizeof(size_t) + vector.size() +
      sizeof(size_t) + bytes.size();
    std::vector<uint8_t> expected(expected_size);
    auto* data = expected.data();
    auto remaining = expected.size();
    serialized::write(data, remaining, static_cast<uint8_t>(entry_type));
    serialized::write(data, remaining, version);
    serialized::write(data, remaining, hash.h.data(), hash.h.size());
    serialized::write(data, remaining, text);
    serialized::write(data, remaining, versions.size() * sizeof(uint64_t));
    serialized::write(
      data,
      remaining,
      reinterpret_cast<const uint8_t*>(versions.data()),
      versions.size() * sizeof(uint64_t));
    serialized::write(data, remaining, vector.size());
    if (!vector.empty())
      serialized::write(data, remaining, vector.data(), vector.size());
    serialized::write(data, remaining, bytes.size());
    if (!bytes.empty())
      serialized::write(data, remaining, bytes.data(), bytes.size());
    REQUIRE(remaining == 0);

    for (size_t iteration = 0; iteration < 3; ++iteration)
    {
      writer.clear();
      CHECK(writer.size() == 0);
      CHECK(writer.get_raw_data().empty());
      writer.append(entry_type);
      writer.append(version);
      writer.append(hash);
      writer.append(text);
      writer.append(versions);
      writer.append(vector);
      writer.append(bytes);
      CHECK(writer.size() == expected_size);
      CHECK(writer.get_raw_data() == expected);
      auto exported = writer.get_raw_data();
      exported[0] ^= 0xff;
      CHECK(writer.get_raw_data() == expected);
    }
  }
}

TEST_CASE("RawWriter copy and move" * doctest::test_suite("serialisation"))
{
  for (const size_t size : {0, 8, 64, 256, 512, 4096})
  {
    INFO(size);
    ccf::kv::RawWriter writer;
    const std::vector<uint8_t> value(size, 42);
    writer.append(value);
    const auto expected = writer.get_raw_data();

    ccf::kv::RawWriter copy(writer);
    CHECK(copy.get_raw_data() == expected);
    writer.clear();
    CHECK(copy.get_raw_data() == expected);

    ccf::kv::RawWriter moved(std::move(copy));
    CHECK(moved.get_raw_data() == expected);
    copy.clear();
    copy.append(uint64_t{42});
    CHECK(copy.size() == sizeof(uint64_t));

    ccf::kv::RawWriter assigned;
    assigned.append(std::vector<uint8_t>(8192, 0));
    assigned = moved;
    CHECK(assigned.get_raw_data() == expected);
    assigned = std::move(moved);
    CHECK(assigned.get_raw_data() == expected);

    auto& same = assigned;
    assigned = same;
    CHECK(assigned.get_raw_data() == expected);
    assigned = std::move(same);
    CHECK(assigned.get_raw_data() == expected);
  }
}

TEST_CASE("RawWriter header and sizing" * doctest::test_suite("serialisation"))
{
  ccf::kv::RawWriter writer;
  ccf::kv::SizeWriter size_writer;
  const auto append = [&]<class T>(const T& entry) {
    const auto before = writer.size();
    writer.append(entry);
    size_writer.append(entry);
    CHECK(writer.size() - before == ccf::kv::RawWriter::serialised_size(entry));
    CHECK(writer.size() == size_writer.size());
  };
  append(ccf::kv::EntryType::WriteSetWithCommitEvidenceAndClaims);
  append(uint64_t{42});
  append(ccf::crypto::Sha256Hash{});
  append(ccf::crypto::Sha256Hash{});
  append(uint64_t{0});
  CHECK(writer.size() == 81);
  append(std::string("public:records"));
  append(std::vector<uint64_t>{1, 2, 3});
  append(std::vector<uint8_t>{});
  append(ccf::ByteVector{});
  CHECK(writer.get_raw_data().size() == size_writer.size());
}
