// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/hash.h"
#include "ccf/ds/nonstd.h"
#include "serializer.h"

#include <atomic>
#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ringbuffer
{
  using Message = uint32_t;

  // Align by cacheline to avoid false sharing
  static constexpr size_t CACHELINE_SIZE = 64;

  struct alignas(CACHELINE_SIZE) Offsets
  {
    // This is a lagging value of head, used only by writers. Its purpose is to
    // reduce contention on head. While there is sufficient space between the
    // tail and this cached value, the writers and readers do not interact with
    // any of the same data. Only when this range is filled do the writers
    // update this cache with a more recent value of head.
    std::atomic<size_t> head_cache = {0};

    // This marks the end of the in-use segment. The next ringbuffer message
    // will be written starting at this point, by a writer advancing this tail
    // value and thus reserving the space between the previous and current value
    // for its own message. Many writers may try to access this concurrently, so
    // the winner is determined by an atomic compare-and-swap (with losers
    // immediately retrying with the new tail).
    std::atomic<size_t> tail = {0};

    // This marks the start of the in-use segment. It is written only by the
    // reader, advancing this value once it has read a message and cleared that
    // message's memory. It is read by writers, but only to update the
    // head_cache value which is used for calculations.
    alignas(CACHELINE_SIZE) std::atomic<size_t> head = {0};
  };

  class message_error : public std::logic_error
  {
  public:
    Message ringbuffer_message_type;

    template <typename... Ts>
    message_error(Message m, Ts&&... ts) :
      std::logic_error(std::forward<Ts>(ts)...),
      ringbuffer_message_type(m)
    {}
  };

  class AbstractWriter
  {
  public:
    virtual ~AbstractWriter() = default;

    /// Write a message of the given type, containing serialized representation
    /// of each of the args, in order. Blocks until the entire message is
    /// written.
    template <typename Serializer, typename... Ts>
    void write_with(Message m, Ts&&... ts)
    {
      write_multiple<Serializer>(m, true, std::forward<Ts>(ts)...);
    }

    /// Try to write a message, but fail (and write nothing) if there is not
    /// currently sufficient space to write completely.
    template <typename Serializer, typename... Ts>
    bool try_write_with(Message m, Ts&&... ts)
    {
      return write_multiple<Serializer>(m, false, std::forward<Ts>(ts)...);
    }

    template <typename... Ts>
    void write(Message m, Ts&&... ts)
    {
      write_with<serializer::CommonSerializer>(m, std::forward<Ts>(ts)...);
    }

    template <typename... Ts>
    bool try_write(Message m, Ts&&... ts)
    {
      return try_write_with<serializer::CommonSerializer>(
        m, std::forward<Ts>(ts)...);
    }

    // If a call to prepare or write_bytes fails, this returned value will be
    // empty. Otherwise it is an opaque marker that the implementation can use
    // to track progress between writes in the same message.
    using WriteMarker = std::optional<size_t>;

    /// Implementation requires 3 methods - prepare, finish, and write_bytes.
    /// For each message, prepare will be called with the total message size. It
    /// should return a WriteMarker for this reservation. That WriteMarker will
    /// be passed to write_bytes, which may be called repeatedly for each part
    /// of the message. write_bytes returns an opaque WriteMarker which will be
    /// passed to the next invocation of write_bytes, to track progress.
    /// Finally, finish will be called with the WriteMarker initially returned
    /// from prepare.
    ///@{
    virtual WriteMarker prepare(
      Message m,
      size_t size,
      bool wait = true,
      size_t* identifier = nullptr) = 0;

    virtual void finish(const WriteMarker& marker) = 0;

    virtual WriteMarker write_bytes(
      const WriteMarker& marker, const uint8_t* bytes, size_t size) = 0;

    virtual size_t get_max_message_size() = 0;
    ///@}

  private:
    template <typename Serializer, typename... Ts>
    bool write_multiple(Message m, bool wait, Ts&&... ts)
    {
      auto sections = Serializer::serialize(std::forward<Ts>(ts)...);

      // Fold section->sizes over the + operator, with initial value 0
      size_t total_size = std::apply(
        [](const auto&... section) { return (section->size() + ... + 0); },
        sections);

      const auto initial_marker = prepare(m, total_size, wait);

      if (!initial_marker.has_value())
        return false;

      auto next = initial_marker;
      serializer::details::tuple_for_each(sections, [&](const auto& s) {
        next = write_bytes(next, s->data(), s->size());
      });

      finish(initial_marker);

      return next.has_value();
    }
  };

  using WriterPtr = std::shared_ptr<AbstractWriter>;

  class AbstractWriterFactory
  {
  public:
    virtual ~AbstractWriterFactory() = default;

    virtual WriterPtr create_writer_to_outside() = 0;
    virtual WriterPtr create_writer_to_inside() = 0;
  };

  /// Useful machinery
#define DEFINE_RINGBUFFER_MSG_TYPE(NAME) \
  NAME = ds::fnv_1a<ringbuffer::Message>(#NAME)

  template <ringbuffer::Message m>
  struct MessageSerializers
  {
    static_assert(
      nonstd::value_dependent_false<ringbuffer::Message, m>::value,
      "No payload specialization for this Message");
  };

#define DECLARE_RINGBUFFER_MESSAGE_NO_PAYLOAD(MTYPE) \
  template <> \
  struct ringbuffer::MessageSerializers<MTYPE> \
    : public serializer::EmptySerializer \
  {};

#define DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(MTYPE, ...) \
  template <> \
  struct ringbuffer::MessageSerializers<MTYPE> \
    : public serializer::PreciseSerializer<__VA_ARGS__> \
  {};

  // Helper functions to write/read with serializer determined by message
  template <ringbuffer::Message m, typename WriterPtr, typename... Ts>
  inline void write_message(const WriterPtr& w, Ts&&... ts)
  {
    using S = MessageSerializers<m>;

    w->template write_with<S>(m, std::forward<Ts>(ts)...);
  }

  template <ringbuffer::Message m, typename WriterPtr, typename... Ts>
  inline bool try_write_message(const WriterPtr& w, Ts&&... ts)
  {
    using S = MessageSerializers<m>;

    return w->template try_write_with<S>(m, std::forward<Ts>(ts)...);
  }

  template <ringbuffer::Message m>
  inline auto read_message(const uint8_t*& data, size_t& size)
  {
    using S = MessageSerializers<m>;

    return S::deserialize(data, size);
  }

  template <ringbuffer::Message m>
  inline auto read_message(std::span<const uint8_t>& span)
  {
    using S = MessageSerializers<m>;

    const uint8_t* data = span.data();
    size_t size = span.size();
    size_t original_size = size;

    auto ret = S::deserialize(data, size);
    span = span.subspan(original_size - size);
    return ret;
  }

  template <ringbuffer::Message m, typename... Ts>
  inline void write_message_with_error_wrapper(char const* prefix, Ts&&... ts)
  {
    try
    {
      write_message<m>(std::forward<Ts>(ts)...);
    }
    catch (const ringbuffer::message_error& ex)
    {
      throw std::logic_error(fmt::format("[{}] {}", prefix, ex.what()));
    }
  }

  template <ringbuffer::Message m, typename... Ts>
  inline bool try_write_message_with_error_wrapper(
    char const* prefix, Ts&&... ts)
  {
    try
    {
      return try_write_message<m>(std::forward<Ts>(ts)...);
    }
    catch (const ringbuffer::message_error& ex)
    {
      throw std::logic_error(fmt::format("[{}] {}", prefix, ex.what()));
    }

    return false;
  }

  /// Macros to catch message-related errors and translate to a human-readable
  /// message name
#define RINGBUFFER_WRITE_MESSAGE(MSG, ...) \
  ringbuffer::write_message_with_error_wrapper<MSG>(#MSG, __VA_ARGS__)

#define RINGBUFFER_TRY_WRITE_MESSAGE(MSG, ...) \
  ringbuffer::try_write_message_with_error_wrapper<MSG>(#MSG, __VA_ARGS__)
}