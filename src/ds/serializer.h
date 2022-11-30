// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"
#include "serialized.h"

#include <memory>
#include <tuple>
#include <type_traits>
#include <vector>

namespace serializer
{
  // A Serializer is generally used as a template argument. It should provide:
  // - serialize(...): returning a tuple of PartialSerializations representing
  //   all passed args. It may be templated and variadic or accept only precise
  //   argument types. Ideally it should give a useful error message at compile
  //   time when called with argument types it doesn't support.
  // - deserialize(const uint8_t* data, size_t size): returning a tuple of
  //   elements parsed from byte buffer, potentially throwing logic errors if
  //   anything is missing/malformed. May need to be templated on expected
  //   types.

  struct ByteRange
  {
    const uint8_t* data;
    const size_t size;
  };

  namespace details
  {
    /// Call functor on each element, cat all results. f takes a tuple-element,
    /// returns a tuple of results
    template <size_t I = 0, typename F, typename... Ts>
    static auto tuple_apply(const std::tuple<Ts...>& t, const F& f)
    {
      if constexpr (sizeof...(Ts) == 1)
      {
        return std::make_tuple();
      }
      else if constexpr (I == sizeof...(Ts) - 1)
      {
        return f(std::get<I>(t));
      }
      else
      {
        return std::tuple_cat(f(std::get<I>(t)), tuple_apply<I + 1>(t, f));
      }
    }

    template <typename Tup>
    struct TupMatcher
    {
      static constexpr size_t TupSize = std::tuple_size_v<Tup>;

      template <typename... Ts>
      struct correct_size
      {
        static constexpr bool value = TupSize == sizeof...(Ts);
      };

      template <typename... Ts>
      static constexpr bool correct_size_v = correct_size<Ts...>::value;

      template <size_t I, typename T>
      struct close_enough_at
      {
        using CanonTarget =
          std::remove_cvref_t<typename std::tuple_element_t<I, Tup>>;
        using CanonArgument = std::remove_cvref_t<T>;

        // This determines what types a Serializer will accept as arguments to
        // serialize(...), relative to the declared param types.
        // The main feature is the removal of const, volatile, and references
        // from the type so that a Serializer<int> will accept an argument of
        // type const int&.
        // Additionally, this will accept ByteRange arguments for parameters
        // declared as std::vector<uint8_t> and vice versa - when serializing we
        // can copy bytes from either in the same way, but there is a
        // distinction in the deserialized type of whether we are copying (to a
        // byte vector) or referring to an existing byte range. It may be
        // possible to generalise this further and replace with
        // std::is_constructible, but these restrictions are sufficient for the
        // current uses.
        // Additionally again, this will accept an array-like of ByteRanges for
        // a single ByteRange parameter. These will be serialised in-order, and
        // produce a single ByteRange in deserialisation.
        static constexpr bool value =
          std::is_same_v<CanonTarget, CanonArgument> ||
          (std::is_same_v<CanonTarget, std::vector<uint8_t>> &&
           std::is_same_v<CanonArgument, ByteRange>) ||
          (std::is_same_v<CanonTarget, ByteRange> &&
           std::is_same_v<CanonArgument, std::vector<uint8_t>>) ||
          (std::is_same_v<CanonTarget, ByteRange> &&
           (std::is_array_v<CanonArgument> &&
            std::is_same_v<std::remove_extent_t<CanonArgument>, ByteRange>));
      };

      // Only reached when Ts is empty
      template <size_t I, typename... Ts>
      struct close_enough_from
      {
        static constexpr bool value = I == TupSize;
      };

      template <size_t I, typename T, typename... Ts>
      struct close_enough_from<I, T, Ts...>
      {
        static constexpr bool value = close_enough_at<I, T>::value &&
          close_enough_from<I + 1, Ts...>::value;
      };

      template <typename... Ts>
      struct close_enough
      {
        static constexpr bool value = close_enough_from<0, Ts...>::value;
      };

      template <typename... Ts>
      static constexpr bool close_enough_v = close_enough<Ts...>::value;
    };

    template <typename... Ts>
    struct TypeMatcher : public TupMatcher<std::tuple<Ts...>>
    {};
  }

  struct AbstractSerializedSection
  {
    virtual ~AbstractSerializedSection() = default;
    virtual const uint8_t* data() const = 0;
    virtual size_t size() const = 0;
  };

  using PartialSerialization = std::shared_ptr<AbstractSerializedSection>;

  template <typename T>
  struct CopiedSection : public AbstractSerializedSection
  {
    const T t;

    CopiedSection(const T& t_) : t(t_) {}

    virtual const uint8_t* data() const override
    {
      return reinterpret_cast<const uint8_t*>(&t);
    }

    virtual size_t size() const override
    {
      return sizeof(T);
    }
  };

  template <typename T>
  struct RawSection : public AbstractSerializedSection
  {
    const T& t;

    RawSection(const T& t_) : t(t_) {}

    virtual const uint8_t* data() const override
    {
      return reinterpret_cast<const uint8_t*>(&t);
    }

    virtual size_t size() const override
    {
      return sizeof(T);
    }
  };

  struct MemoryRegionSection : public AbstractSerializedSection
  {
    const uint8_t* const d;
    const size_t s;

    MemoryRegionSection(const uint8_t* data_, size_t size_) : d(data_), s(size_)
    {}

    virtual const uint8_t* data() const override
    {
      return d;
    }

    virtual size_t size() const override
    {
      return s;
    }
  };

  class EmptySerializer
  {
  public:
    /// Can serialize empty messages, but nothing else
    template <typename... Ts>
    static std::tuple<> serialize(const Ts&... ts)
    {
      static_assert(
        sizeof...(ts) == 0,
        "EmptySerializer was given message payload to serialize - can only "
        "serialize empty "
        "messages");
      return std::make_tuple();
    }

    template <typename... Ts>
    static std::tuple<> deserialize(const uint8_t*, size_t size)
    {
      if constexpr (sizeof...(Ts) == 0)
      {
        if (size > 0)
          throw std::logic_error(
            "EmptySerializer asked to deserialize buffer of size " +
            std::to_string(size) + ", should be empty");
      }
      return std::make_tuple();
    }
  };

  class CommonSerializer : public EmptySerializer
  {
    template <size_t N, size_t... Is>
    static auto serialize_byte_range_with_index_sequence(
      const ByteRange (&brs)[N], std::index_sequence<Is...>)
    {
      return std::make_tuple(
        std::make_shared<MemoryRegionSection>(brs[Is].data, brs[Is].size)...);
    }

    /// Overloads of serialize_value - return a tuple of PartialSerializations
    ///@{
    /// Overload for ByteRanges (length-prefix prefixed)
    static auto serialize_value(const ByteRange& br)
    {
      auto cs = std::make_shared<CopiedSection<size_t>>(br.size);
      auto bfs = std::make_shared<MemoryRegionSection>(br.data, br.size);
      return std::tuple_cat(std::make_tuple(cs), std::make_tuple(bfs));
    }

    /// Overload for C-arrays of ByteRanges (potentially non-contiguous, no
    /// length-prefix)
    template <size_t N>
    static auto serialize_value(const ByteRange (&brs)[N])
    {
      return serialize_byte_range_with_index_sequence(
        brs, std::make_index_sequence<N>{});
    }

    /// Overload for std::vectors of bytes (length-prefixed)
    static auto serialize_value(const std::vector<uint8_t>& vec)
    {
      auto cs = std::make_shared<CopiedSection<size_t>>(vec.size());
      auto bfs = std::make_shared<MemoryRegionSection>(vec.data(), vec.size());
      return std::tuple_cat(std::make_tuple(cs), std::make_tuple(bfs));
    }

    /// Overload for strings (length-prefixed)
    static auto serialize_value(const std::string& s)
    {
      auto cs = std::make_shared<CopiedSection<size_t>>(s.size());
      auto bfs = std::make_shared<MemoryRegionSection>(
        reinterpret_cast<const uint8_t*>(s.data()), s.size());
      return std::tuple_cat(std::make_tuple(cs), std::make_tuple(bfs));
    }

    /// Generic case, for integral types - use raw byte representation
    template <
      typename T,
      std::enable_if_t<
        std::is_integral<T>::value || std::is_enum<T>::value,
        bool> = true>
    static auto serialize_value(const T& t)
    {
      auto rs = std::make_shared<RawSection<T>>(t);
      return std::make_tuple(rs);
    }
    ///@}

    /// Overloads of serialize_value_final - return a tuple of
    /// PartialSerializations
    ///@{
    /// Overload for ByteRanges, avoid length-prefix (use entire remaining size)
    static auto serialize_value_final(const ByteRange& br)
    {
      auto bfs = std::make_shared<MemoryRegionSection>(br.data, br.size);
      return std::make_tuple(bfs);
    }

    /// Overload for std::vectors of bytes, avoid length-prefix (use entire
    /// remaining size)
    static auto serialize_value_final(const std::vector<uint8_t>& vec)
    {
      auto bfs = std::make_shared<MemoryRegionSection>(vec.data(), vec.size());
      return std::make_tuple(bfs);
    }

    /// Generic case - fallback to serialize_value
    template <typename T>
    static auto serialize_value_final(const T& t)
    {
      return serialize_value(t);
    }
    ///@}

    /// Tag type to distinguish deserialize overloads by return type
    template <typename T>
    struct Tag
    {
      using type = T;
    };

    /// Overloads of deserialize_value
    ///@{
    /// Overload for ByteRange (refers to data in-place)
    static ByteRange deserialize_value(
      const uint8_t*& data, size_t& size, const Tag<ByteRange>&)
    {
      const auto prefixed_size = serialized::read<size_t>(data, size);
      ByteRange br{data, prefixed_size};
      serialized::skip(data, size, prefixed_size);
      return br;
    }

    /// Overload for std::vectors of bytes (copied)
    static std::vector<uint8_t> deserialize_value(
      const uint8_t*& data, size_t& size, const Tag<std::vector<uint8_t>>&)
    {
      const auto prefixed_size = serialized::read<size_t>(data, size);
      return serialized::read(data, size, prefixed_size);
    }

    /// Overload for strings
    static std::string deserialize_value(
      const uint8_t*& data, size_t& size, const Tag<std::string>&)
    {
      return serialized::read<std::string>(data, size);
    }

    /// Generic case
    template <
      typename T,
      std::enable_if_t<
        std::is_integral<T>::value || std::is_enum<T>::value,
        bool> = true>
    static T deserialize_value(
      const uint8_t*& data, size_t& size, const Tag<T>&)
    {
      return serialized::read<T>(data, size);
    }
    ///@}

    /// Overloads of deserialize_value_final
    ///@{
    /// Overload for ByteRanges
    static auto deserialize_value_final(
      const uint8_t*& data, size_t& size, const Tag<ByteRange>&)
    {
      ByteRange br{data, size};
      serialized::skip(data, size, size);
      return br;
    }

    /// Overload for std::vectors of bytes
    static auto deserialize_value_final(
      const uint8_t*& data, size_t& size, const Tag<std::vector<uint8_t>>&)
    {
      return serialized::read(data, size, size);
    }

    /// Generic case - fallback to deserialize_value
    template <typename T>
    static T deserialize_value_final(
      const uint8_t*& data, size_t& size, const Tag<T>& tag)
    {
      return deserialize_value(data, size, tag);
    }
    ///@}

    template <typename T, typename... Ts>
    static auto deserialize_impl(const uint8_t* data, size_t size)
    {
      using StrippedT = std::remove_cvref_t<T>;

      if constexpr (sizeof...(Ts) == 0)
      {
        return std::make_tuple(
          deserialize_value_final(data, size, Tag<StrippedT>{}));
      }
      else
      {
        const auto next =
          std::make_tuple(deserialize_value(data, size, Tag<StrippedT>{}));
        return std::tuple_cat(next, deserialize_impl<Ts...>(data, size));
      }
    }

  public:
    // Can also serialize empty messages
    using EmptySerializer::serialize;

    /// General serialize call - convert each argument to a tuple, cat those
    /// tuples
    template <typename T, typename... Ts>
    static auto serialize(T&& t, Ts&&... ts)
    {
      if constexpr (sizeof...(Ts) == 0)
      {
        return serialize_value_final(std::forward<T>(t));
      }
      else
      {
        const auto next = serialize_value(std::forward<T>(t));
        return std::tuple_cat(next, serialize(std::forward<Ts>(ts)...));
      }
    }

    template <typename... Ts>
    static auto deserialize(const uint8_t* data, size_t size)
    {
      if constexpr (sizeof...(Ts) == 0)
      {
        return EmptySerializer::deserialize(data, size);
      }
      else
      {
        return deserialize_impl<Ts...>(data, size);
      }
    }
  };

  // Serializes a list of exactly these argument types, and nothing else
  template <typename... Us>
  class PreciseSerializer : private CommonSerializer
  {
    using Matcher = details::TypeMatcher<Us...>;

  public:
    template <typename... Ts>
    static auto serialize(Ts&&... ts)
    {
      static_assert(
        Matcher::template correct_size_v<Ts...>,
        "Incorrect number of arguments for PreciseSerializer");
      static_assert(
        Matcher::template close_enough_v<Ts...>,
        "Incorrect type of arguments for PreciseSerializer");

      return CommonSerializer::serialize(std::forward<Ts>(ts)...);
    }

    template <typename... Ts>
    static auto deserialize(const uint8_t* data, size_t size)
    {
      static_assert(
        Matcher::template correct_size_v<Ts...>,
        "Incorrect number of results for PreciseSerializer");
      static_assert(
        Matcher::template close_enough_v<Ts...>,
        "Incorrect type of results for PreciseSerializer");

      return CommonSerializer::deserialize<Us...>(data, size);
    }

    static auto deserialize(const uint8_t* data, size_t size)
    {
      return CommonSerializer::deserialize<Us...>(data, size);
    }
  };

  template <typename>
  class TupleSerializer;

  // Specializes a specific tuple-type only. Removes ref and const when
  // comparing types, ie tuple<int, const float&> will be accepted by
  // TupleSerializers specialized at tuple<int, float>, tuple<const int&, const
  // float&> etc
  template <typename... Us>
  class TupleSerializer<std::tuple<Us...>> : private CommonSerializer
  {
    using Tup = std::tuple<Us...>;
    using Matcher = details::TupMatcher<Tup>;

  public:
    template <typename... Ts>
    static auto serialize(std::tuple<Ts...>&& t)
    {
      static_assert(
        Matcher::template correct_size_v<Ts...>,
        "Incorrect tuple size for TupleSerializer");
      static_assert(
        Matcher::template close_enough_v<Ts...>,
        "Incorrect tuple type for TupleSerializer");

      return details::tuple_apply(
        t, [](const auto& e) { return CommonSerializer::serialize(e); });
    }

    // Takes variadic arguments list, they don't need to be packed in tuple
    template <typename... Ts>
    static auto serialize(Ts&&... ts)
    {
      static_assert(
        Matcher::template correct_size_v<Ts...>,
        "Incorrect number of args for unpacked TupleSerializer");
      static_assert(
        Matcher::template close_enough_v<Ts...>,
        "Incorrect arg types for unpacked TupleSerializer");

      return CommonSerializer::serialize(std::forward<Ts>(ts)...);
    }

    template <typename... Ts>
    static auto deserialize(const uint8_t* data, size_t size)
    {
      static_assert(
        Matcher::template correct_size_v<Ts...>,
        "Incorrect number of results for TupleSerializer");
      static_assert(
        Matcher::template close_enough_v<Ts...>,
        "Incorrect type of results for TupleSerializer");

      return CommonSerializer::deserialize<Ts...>(data, size);
    }

    static auto deserialize(const uint8_t* data, size_t size)
    {
      return CommonSerializer::deserialize<Us...>(data, size);
    }
  };
} // namespace serializer
