// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "hash.h"
#include "serializer.h"

#include <optional>
#include <string>
#include <vector>

namespace ringbuffer
{
  using Message = uint32_t;

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

  /// Machinery for writing and reading typed messages
  namespace
  {
    template <ringbuffer::Message m>
    struct dependent_false : public std::false_type
    {};
  };

  template <ringbuffer::Message m>
  struct MessageSerializers
  {
    static_assert(
      dependent_false<m>::value, "No payload specialization for this Message");
  };

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

  template <ringbuffer::Message m, typename... Ts>
  inline void write_message_with_error_wrapper(char const* prefix, Ts&&... ts)
  {
    try
    {
      write_message<m>(std::forward<Ts>(ts)...);
    }
    catch (const ringbuffer::message_error& ex)
    {
      throw std::logic_error(std::string("[") + prefix + "] " + ex.what());
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
      throw std::logic_error(std::string("[") + prefix + "] " + ex.what());
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