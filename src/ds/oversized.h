// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "messaging.h"
#include "ring_buffer.h"
#include "serialized.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <unordered_map>
#include <utility>

#define LOG_AND_THROW(ERROR_TYPE, ...) \
  do \
  { \
    const auto msg = fmt::format(__VA_ARGS__); \
    LOG_FAIL_FMT("{}", msg); \
    throw ERROR_TYPE(msg); \
  } while (0)
namespace oversized
{
  enum OversizedMessage : ringbuffer::Message
  {
    /// Part of a larger message. Can be sent both ways
    DEFINE_RINGBUFFER_MSG_TYPE(fragment),
  };

  class FragmentReconstructor
  {
    messaging::RingbufferDispatcher& dispatcher;

    struct PartialMessage
    {
      const ringbuffer::Message m;
      const size_t total_size;

      size_t received;
      uint8_t* data;
    };

    std::unordered_map<size_t, PartialMessage> partial_messages;

  public:
    FragmentReconstructor(messaging::RingbufferDispatcher& d) : dispatcher(d)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        d,
        OversizedMessage::fragment,
        [this](const uint8_t* data, size_t size) {
          auto message_id = serialized::read<size_t>(data, size);

          auto it = partial_messages.find(message_id);
          if (it == partial_messages.end())
          {
            // First reference to this oversized message - should contain a
            // header. Read its type, size, then allocate space for it
            auto m = serialized::read<ringbuffer::Message>(data, size);
            auto total_size = serialized::read<size_t>(data, size);

            // No safety checks on the size - trust that in normal operation the
            // Writer has set sensible limits, don't duplicate here
            // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
            auto* dest = new uint8_t[total_size];

            auto ib =
              partial_messages.insert({message_id, {m, total_size, 0, dest}});

            it = ib.first;
          }

          auto& partial = it->second;
          if (size + partial.received > partial.total_size)
          {
            throw ringbuffer::message_error(
              message_id,
              fmt::format(
                "Too much data for oversized fragmented message. Message {} "
                "asked for {} bytes, has already written {}, but has sent a "
                "further {}",
                message_id,
                partial.total_size,
                partial.received,
                size));
          }

          ::memcpy(partial.data + partial.received, data, size);
          partial.received += size;
          data += size;
          size -= size;

          if (partial.received == partial.total_size)
          {
            // Entire message received - dispatch it then free buffer
            dispatcher.dispatch(partial.m, partial.data, partial.total_size);

            delete[] partial.data; // NOLINT(cppcoreguidelines-owning-memory)

            // Erase by key - dispatch may have invalidated previous iterator
            // (nested fragmented messages - odd, but no reason to disallow)
            partial_messages.erase(message_id);
          }
        });
    }

    ~FragmentReconstructor() noexcept
    {
      try
      {
        dispatcher.remove_message_handler(OversizedMessage::fragment);
      }
      catch (...) // NOLINT(bugprone-empty-catch)
      {
        // Destructors must not throw - exception ignored
      }

      for (const auto& [_, partial] : partial_messages)
      {
        delete[] partial.data; // NOLINT(cppcoreguidelines-owning-memory)
      }
    }
  };

#pragma pack(push, 1)
  struct InitialFragmentHeader
  {
    size_t identifier;
    ringbuffer::Message contained;
    size_t total_size;
  };
#pragma pack(pop)

  class Writer : public ringbuffer::AbstractWriter
  {
  private:
    ringbuffer::WriterPtr underlying_writer;

    const size_t max_fragment_size;
    const size_t max_total_size;

    struct FragmentProgress
    {
      WriteMarker marker; // Track this so a later call can finish this fragment
      size_t identifier; // Identifier for all fragments of oversized message
      size_t remainder; // Remaining space in currently prepared fragment buffer
    };

    // None iff the message is small enough to fit in a single fragment, or
    // we're not currently within a [prepare, write_bytes*, finish] loop
    std::optional<FragmentProgress> fragment_progress;

  public:
    Writer(ringbuffer::WriterPtr writer, size_t f, size_t t = -1) :
      underlying_writer(std::move(writer)),
      max_fragment_size(f),
      max_total_size(t)
    {
      if (max_fragment_size >= max_total_size)
      {
        LOG_AND_THROW(
          std::invalid_argument,
          "Fragment sizes must be smaller than total max: {} >= {}",
          max_fragment_size,
          max_total_size);
      }

      constexpr auto header_size = sizeof(InitialFragmentHeader);
      if (max_fragment_size <= header_size)
      {
        LOG_AND_THROW(
          std::invalid_argument,
          "Fragment size must be large enough to contain the header for the "
          "initial fragment, and some additional payload data: {} <= {}",
          max_fragment_size,
          header_size);
      }
    }

    WriteMarker prepare(
      ringbuffer::Message m,
      size_t total_size,
      bool wait = true,
      size_t* identifier = nullptr) override
    {
      // Ensure this is not called out of order
      if (fragment_progress.has_value())
      {
        LOG_AND_THROW(
          std::logic_error, "This Writer is already preparing a message");
      }

      // Small enough to be handled directly by underlying writer
      if (total_size <= max_fragment_size)
      {
        return underlying_writer->prepare(m, total_size, wait, identifier);
      }

      if (total_size > max_total_size)
      {
        LOG_AND_THROW(
          std::invalid_argument,
          "Requested a write of {} bytes, max allowed is {}",
          total_size,
          max_total_size);
      }

      // Need to split this message into multiple fragments

      if (!wait)
      {
        LOG_AND_THROW(
          std::invalid_argument,
          "Requested write of {} bytes will be split into multiple fragments: "
          "caller must wait for these to complete as fragment writes will be "
          "blocking",
          total_size);
      }

      // Prepare space for the first fragment, getting an id for all related
      // fragments
      size_t outer_id = 0;
      const auto marker = underlying_writer->prepare(
        OversizedMessage::fragment, max_fragment_size, wait, &outer_id);
      if (!marker.has_value())
      {
        return {};
      }

      // Write the header
      InitialFragmentHeader header = {outer_id, m, total_size};
      auto next = underlying_writer->write_bytes(
        marker, reinterpret_cast<const uint8_t*>(&header), sizeof(header));

      // Track progress in current oversized message
      fragment_progress = {
        marker, outer_id, max_fragment_size - sizeof(header)};

      if (identifier != nullptr)
      {
        *identifier = outer_id;
      }

      // Don't need to store next - it will be an argument of the next call to
      // write_bytes
      return next;
    }

    void finish(const WriteMarker& marker) override
    {
      if (fragment_progress.has_value())
      {
        // We were writing an oversized message, the given marker means nothing
        // to us
        if (fragment_progress->remainder != 0)
        {
          LOG_AND_THROW(
            std::logic_error,
            "Attempting to finish an oversized message before the entire "
            "requested payload has been written");
        }

        // Finish the final fragment message
        underlying_writer->finish(fragment_progress->marker);

        // Clean up, ready for next call to prepare
        fragment_progress = {};
      }
      else
      {
        // We were writing a small message - get underlying writer to finish it
        underlying_writer->finish(marker);
      }
    }

    WriteMarker write_bytes(
      const WriteMarker& marker, const uint8_t* bytes, size_t size) override
    {
      if (!marker.has_value())
      {
        return {};
      }

      if (!fragment_progress.has_value())
      {
        // Writing a small message - nothing to do here
        return underlying_writer->write_bytes(marker, bytes, size);
      }

      // Append as much as possible into the current prepared buffer
      auto write_size = std::min(size, fragment_progress->remainder);
      auto next = underlying_writer->write_bytes(marker, bytes, write_size);
      bytes += write_size;
      size -= write_size;
      fragment_progress->remainder -= write_size;

      // While there is more to write...
      while (size > 0)
      {
        // Prepare a new fragment
        const auto id = fragment_progress->identifier;
        const auto frag_size = std::min(size + sizeof(id), max_fragment_size);
        next = underlying_writer->prepare(
          OversizedMessage::fragment, frag_size, true);

        if (!next.has_value())
        {
          // Intermediate fragment failed - this is unexpected
          LOG_AND_THROW(
            std::logic_error,
            "Failed to create fragment for oversized message");

          // If this path is hit it is likely because we have allowed oversized
          // writes to write without waiting. Some initial fragments were
          // written, but there is insufficient space to write this fragment.
          // In this case we can either cancel the entire oversized message, or
          // retry. In either case we should send a message to inform the
          // reader.
          fragment_progress->remainder = 0;
          break;
        }

        // Finish the previous fragment
        underlying_writer->finish(fragment_progress->marker);

        // Update progress tracking to reference the new fragment
        write_size = frag_size - sizeof(id);
        fragment_progress->marker = next;
        fragment_progress->remainder = write_size;

        // Write the id of the oversized message
        next = underlying_writer->write_bytes(
          next, reinterpret_cast<const uint8_t*>(&id), sizeof(id));

        // Write some fragment payload
        next = underlying_writer->write_bytes(next, bytes, write_size);
        bytes += write_size;
        size -= write_size;
        fragment_progress->remainder -= write_size;
      }

      return next;
    }

    size_t get_max_message_size() override
    {
      return max_total_size;
    }
  };

  struct WriterConfig
  {
    size_t max_fragment_size;
    size_t max_total_size;
  };

  // Wrap ringbuffer::Circuit to provide the same fragment/total maximum sizes
  // for every Writer
  class WriterFactory : public ringbuffer::AbstractWriterFactory
  {
    AbstractWriterFactory& factory_impl;

    const WriterConfig config;

  public:
    WriterFactory(AbstractWriterFactory& impl, const WriterConfig& config_) :
      factory_impl(impl),
      config(config_)
    {}

    std::shared_ptr<oversized::Writer> create_oversized_writer_to_outside()
    {
      return std::make_shared<oversized::Writer>(
        factory_impl.create_writer_to_outside(),
        config.max_fragment_size,
        config.max_total_size);
    }

    std::shared_ptr<oversized::Writer> create_oversized_writer_to_inside()
    {
      return std::make_shared<oversized::Writer>(
        factory_impl.create_writer_to_inside(),
        config.max_fragment_size,
        config.max_total_size);
    }

    std::shared_ptr<ringbuffer::AbstractWriter> create_writer_to_outside()
      override
    {
      return create_oversized_writer_to_outside();
    }

    std::shared_ptr<ringbuffer::AbstractWriter> create_writer_to_inside()
      override
    {
      return create_oversized_writer_to_inside();
    }
  };
}
