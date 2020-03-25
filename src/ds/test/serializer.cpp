// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../serializer.h"

#include "../ring_buffer.h"

#include <doctest/doctest.h>

using namespace ringbuffer;
using namespace serializer;

constexpr Message any_message = 42;

const size_t n = 0xbeef;
const char c = '!';
const auto s = std::string("Some large message payload");

// No way to actually check this, but useful to show examples of disallowed code
// inline with working tests
#define REQUIRE_COMPILE_ERROR(...)

//
// Utils
//
// A simple single-message Writer that we don't need to read from
struct VectorWriter : public AbstractWriter
{
  ringbuffer::Message message;
  std::vector<uint8_t> payload;
  bool done;

  virtual WriteMarker prepare(
    ringbuffer::Message m,
    size_t total_size,
    bool wait = true,
    size_t* identifier = nullptr) override
  {
    payload.resize(total_size);
    message = m;
    done = false;
    // WriteMarker is index into vector, start at the beginning
    return {0};
  }

  virtual void finish(const WriteMarker& marker) override
  {
    REQUIRE(marker.has_value());
    REQUIRE(marker.value() == 0);
    REQUIRE(!done);
    done = true;
  }

  virtual WriteMarker write_bytes(
    const WriteMarker& marker, const uint8_t* bytes, size_t size) override
  {
    REQUIRE(marker.has_value());
    auto index = marker.value();
    REQUIRE(index + size <= payload.size());
    ::memcpy(payload.data() + index, bytes, size);
    return {index + size};
  }

  template <typename FnCheckPayload>
  void require_done(ringbuffer::Message m, FnCheckPayload f)
  {
    REQUIRE(done);
    REQUIRE(message == m);
    REQUIRE(f(payload));

    // Clear for next iteration
    done = false;
    message = Const::msg_none;
    payload.clear();
  }
};

auto is_empty = [](const std::vector<uint8_t>& v) { return v.empty(); };
auto is_not_empty = [](const std::vector<uint8_t>& v) { return !v.empty(); };

// A section-serializer that converts all arguments into strings
struct StringifiedSection : public AbstractSerializedSection
{
  const std::string s;
  StringifiedSection(const std::string& s_) : s(s_) {}
  template <typename T>
  StringifiedSection(const T& t_) : s(std::to_string(t_))
  {}

  virtual const uint8_t* data() const override
  {
    return reinterpret_cast<const uint8_t*>(s.data());
  }

  virtual size_t size() const override
  {
    return s.size();
  }
};

struct StringifySerializer : private EmptySerializer
{
  // Can also serialize empty messages
  using EmptySerializer::serialize;

  template <typename T, typename... Ts>
  static auto serialize(const T& t, const Ts&... ts)
  {
    return std::tuple_cat(
      std::make_tuple(std::make_shared<StringifiedSection>(t)),
      serialize(ts...));
  }
};

template <typename Serializer, typename... Ts>
void require_minimum_serialized_arity(Ts&&... ts)
{
  // Any serializer should produce at least as many sections as arguments (some
  // arguments may produce multiple sections)
  static_assert(
    std::tuple_size_v<decltype(Serializer::serialize(ts...))> >= sizeof...(ts));
  REQUIRE_NOTHROW(
    auto sections = Serializer::serialize(std::forward<Ts>(ts)...));
}

template <typename Serializer, typename... Ts>
void require_roundtrip(Ts&&... ts)
{
  const Message fresh_message = rand();
  VectorWriter w;

  w.write_with<Serializer>(fresh_message, std::forward<Ts>(ts)...);
  REQUIRE(w.done);
  REQUIRE(w.message == fresh_message);

  auto result =
    Serializer::template deserialize<Ts...>(w.payload.data(), w.payload.size());

  static_assert(std::tuple_size_v<decltype(result)> == sizeof...(Ts));

  REQUIRE(result == std::make_tuple(ts...));
}

TEST_CASE("Serialize" * doctest::test_suite("serializer"))
{
  REQUIRE(std::make_tuple() == EmptySerializer::serialize());
  REQUIRE_COMPILE_ERROR(EmptySerializer::serialize(5));

  require_minimum_serialized_arity<CommonSerializer>(5);
  require_minimum_serialized_arity<CommonSerializer>(5, 6);
  require_minimum_serialized_arity<CommonSerializer>(5, 6, 7);
  require_minimum_serialized_arity<CommonSerializer>(
    5, (char)5, '5', std::string("5"));
}

TEST_CASE("Deserialize" * doctest::test_suite("serializer"))
{
  const std::vector<uint8_t> buffer = {
    'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};

  const auto data = buffer.data();
  const auto size = buffer.size();

  {
    REQUIRE_NOTHROW(EmptySerializer::deserialize(data, 0));
    REQUIRE_THROWS(EmptySerializer::deserialize(data, 1));
    REQUIRE_COMPILE_ERROR(EmptySerializer::deserialize<int>(data, 1));
  }

  {
    auto deser = CommonSerializer::deserialize<uint8_t>(data, size);
    REQUIRE(std::get<0>(deser) == buffer[0]);
  }

  {
    auto deser =
      CommonSerializer::deserialize<uint8_t, uint8_t, uint8_t>(data, size);
    REQUIRE(std::get<0>(deser) == buffer[0]);
    REQUIRE(std::get<1>(deser) == buffer[1]);
    REQUIRE(std::get<2>(deser) == buffer[2]);
  }

  {
    auto deser = CommonSerializer::deserialize<uint16_t>(data, size);
    REQUIRE(std::get<0>(deser) == (buffer[0] | (size_t)buffer[1] << 8));
  }

  {
    auto deser =
      CommonSerializer::deserialize<uint16_t, uint8_t, uint16_t>(data, size);
    REQUIRE(std::get<0>(deser) == (buffer[0] | (size_t)buffer[1] << 8));
    REQUIRE(std::get<1>(deser) == buffer[2]);
    REQUIRE(std::get<2>(deser) == (buffer[3] | (size_t)buffer[4] << 8));
  }

  {
    auto deser =
      CommonSerializer::deserialize<std::vector<uint8_t>>(data, size);
    REQUIRE(std::get<0>(deser) == buffer);
  }

  SUBCASE("CommonSerializer")
  {
    VectorWriter w;

    // As string
    w.write_with<CommonSerializer>(any_message, buffer.size(), buffer);
    auto deser = CommonSerializer::deserialize<std::string>(
      w.payload.data(), w.payload.size());
    REQUIRE(strcmp(std::get<0>(deser).data(), "Hello World") == 0);

    // As ByteRange
    ByteRange br{buffer.data(), buffer.size()};
    w.write_with<CommonSerializer>(any_message, br);
    auto deser2 = CommonSerializer::deserialize<ByteRange>(
      w.payload.data(), w.payload.size());
    const ByteRange& res = std::get<0>(deser2);
    REQUIRE(res.size == buffer.size());
    REQUIRE(memcmp(res.data, buffer.data(), buffer.size()) == 0);
  }

  SUBCASE("PreciseSerializer")
  {
    using PS = PreciseSerializer<uint8_t, uint8_t, uint16_t>;

    REQUIRE_COMPILE_ERROR(PS::deserialize<uint8_t>(data, size));
    REQUIRE_COMPILE_ERROR(
      PS::deserialize<uint8_t, uint8_t, uint8_t>(data, size));

    {
      auto d = data;
      auto s = size;

      auto deser = PS::deserialize(data, size);
      static_assert(std::tuple_size_v<decltype(deser)> == 3);

      REQUIRE(std::get<0>(deser) == buffer[0]);
      REQUIRE(std::get<1>(deser) == buffer[1]);
      REQUIRE(std::get<2>(deser) == (buffer[2] | (size_t)buffer[3] << 8));

      auto deser2 = PS::deserialize<uint8_t, uint8_t, uint16_t>(d, s);
      REQUIRE(deser == deser2);
    }
  }
}

TEST_CASE("StringifySerializer" * doctest::test_suite("serializer"))
{
  VectorWriter w;

  // Curried function to create a functor which converts a byte-vector to
  // string, and does string comparison with the target
  auto is_string = [](const std::string& s) {
    return [&s](const std::vector<uint8_t>& vec) {
      auto actual =
        std::string(reinterpret_cast<const char*>(vec.data()), vec.size());
      return actual == s;
    };
  };

  w.write_with<StringifySerializer>(any_message);
  w.require_done(any_message, is_empty);

  w.write_with<StringifySerializer>(any_message, n);
  w.require_done(any_message, is_string(std::to_string(n)));

  w.write_with<StringifySerializer>(any_message, c);
  w.require_done(any_message, is_string(std::to_string(c)));

  w.write_with<StringifySerializer>(any_message, n, c, n, s);
  w.require_done(
    any_message,
    is_string(std::to_string(n) + std::to_string(c) + std::to_string(n) + s));
}

TEST_CASE("roundtrip" * doctest::test_suite("serializer"))
{
  VectorWriter w;

  SUBCASE("EmptySerializer")
  {
    require_roundtrip<EmptySerializer>();

    REQUIRE_COMPILE_ERROR(require_roundtrip<EmptySerializer>(n));
    REQUIRE_COMPILE_ERROR(require_roundtrip<EmptySerializer>(c));
  }

  SUBCASE("CommonSerializer")
  {
    require_roundtrip<CommonSerializer>();

    require_roundtrip<CommonSerializer>(n);
    require_roundtrip<CommonSerializer>(c);
    require_roundtrip<CommonSerializer>(s);

    require_roundtrip<CommonSerializer>(n, c);
    require_roundtrip<CommonSerializer>(n, s, n, s);
    require_roundtrip<CommonSerializer>(s, c, n, n + 1, s);
  }

  SUBCASE("PreciseSerializer")
  {
    using NCS_Serializer =
      PreciseSerializer<decltype(n), decltype(c), decltype(s)>;

    REQUIRE_COMPILE_ERROR(require_roundtrip<NCS_Serializer>());
    REQUIRE_COMPILE_ERROR(require_roundtrip<NCS_Serializer>(n, c));
    REQUIRE_COMPILE_ERROR(require_roundtrip<NCS_Serializer>(n, c, n));
    require_roundtrip<NCS_Serializer>(n, c, s);

    using NNSN_Serializer =
      PreciseSerializer<decltype(n), decltype(n), decltype(s), decltype(n)>;

    require_roundtrip<NNSN_Serializer>(n, n, s, n);
    require_roundtrip<NNSN_Serializer>(n, n + 1, s, n + 5);
  }

  SUBCASE("ByteRange to vector")
  {
    INFO(
      "A serializer which expects a byte vector can take a ByteRange in to "
      "serialize, but will always deserialize to a copied byte vector");
    using TV = std::vector<uint8_t>;
    using TS = PreciseSerializer<TV>;

    constexpr uint8_t size = 42;
    uint8_t raw[size];
    for (uint8_t i = 0; i < size; ++i)
    {
      raw[i] = i;
    }

    const ByteRange br{raw, size};

    VectorWriter w;

    w.write_with<TS>(any_message, br);

    auto [vec] = TS::deserialize(w.payload.data(), w.payload.size());

    static_assert(std::is_same_v<decltype(vec), TV>);

    REQUIRE(vec.size() == size);

    for (auto i = 0; i < size; ++i)
    {
      REQUIRE(vec[i] == raw[i]);
    }
  }

  SUBCASE("TupleSerializer")
  {
    {
      using T1 = std::tuple<decltype(n), decltype(c), decltype(s)>;
      using T1_Serializer = TupleSerializer<T1>;

      // Args don't need to be tuple-packed
      REQUIRE_COMPILE_ERROR(require_roundtrip<T1_Serializer>());
      REQUIRE_COMPILE_ERROR(require_roundtrip<T1_Serializer>(n, c, n));
      require_roundtrip<T1_Serializer>(n, c, s);

      // Variations in ref-ness and const-ness are accepted
      require_roundtrip<T1_Serializer>(
        std::add_const_t<decltype(n)>(n),
        std::add_const_t<decltype(c)>(c),
        std::remove_const_t<decltype(s)>(s));

      require_roundtrip<T1_Serializer>(
        std::add_lvalue_reference_t<std::remove_const_t<decltype(n)>>(n),
        std::remove_reference_t<std::add_const_t<decltype(c)>>(c),
        std::add_rvalue_reference_t<std::add_const_t<decltype(s)>>(s));

      require_roundtrip<T1_Serializer>(n + 1, '.', std::string("Some string"));
    }

    {
      // Types don't need to be unique
      using T2 = std::tuple<decltype(n), decltype(n), decltype(n)>;
      using T2_Serializer = TupleSerializer<T2>;

      REQUIRE_COMPILE_ERROR(require_roundtrip<T2_Serializer>(n));
      REQUIRE_COMPILE_ERROR(require_roundtrip<T2_Serializer>(n, n));
      require_roundtrip<T2_Serializer>(n, n, n);
      REQUIRE_COMPILE_ERROR(require_roundtrip<T2_Serializer>(n, n, n, n));
    }
  }
}
