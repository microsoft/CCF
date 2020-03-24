// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ring_buffer.h"

#include <deque>
#include <fmt/format_header_only.h>
#include <memory>
#include <vector>

namespace ringbuffer
{
  // This wraps an underlying Writer implementation and ensure calls to write()
  // will not block indefinitely. This never calls the blocking write()
  // implementation. Instead it calls try_write(), and in the case that a write
  // fails (because the target ringbuffer is full), the message is placed in a
  // pending queue. These pending message must be flushed regularly, attempting
  // again to write to the ringbuffer.

  class NonBlockingWriter : public AbstractWriter
  {
  private:
    WriterPtr underlying_writer;

    struct PendingMessage
    {
      Message m;
      size_t marker;
      bool finished;
      std::vector<uint8_t> buffer;

      PendingMessage(Message m_, std::vector<uint8_t>&& buffer_) :
        m(m_),
        buffer(buffer_),
        marker(0),
        finished(false)
      {}
    };

    std::deque<PendingMessage> pending;

  public:
    NonBlockingWriter(const WriterPtr& writer) : underlying_writer(writer) {}

    virtual WriteMarker prepare(
      ringbuffer::Message m,
      size_t total_size,
      bool wait = true,
      size_t* identifier = nullptr) override
    {
      if (pending.empty())
      {
        // No currently pending messages - try to write to underlying buffer
        const auto marker =
          underlying_writer->prepare(m, total_size, false, identifier);

        if (marker.has_value())
        {
          return marker;
        }

        // Prepare failed, no space in buffer - so add to queue
      }

      pending.emplace_back(m, std::vector<uint8_t>(total_size));

      auto& msg = pending.back();
      msg.marker = (size_t)msg.buffer.data();

      // NB: There is an assumption that these markers will never conflict with
      // the markers produced by the underlying writer impl
      return msg.marker;
    }

    virtual void finish(const WriteMarker& marker) override
    {
      if (marker.has_value())
      {
        for (auto& it : pending)
        {
          // NB: finish is passed the _initial_ WriteMarker, so we compare
          // against it.buffer.data() rather than it.marker
          if ((size_t)it.buffer.data() == marker.value())
          {
            // This is a pending write. Mark as completed, so we can later flush
            // it
            it.finished = true;
            return;
          }
        }
      }

      underlying_writer->finish(marker);
    }

    virtual WriteMarker write_bytes(
      const WriteMarker& marker, const uint8_t* bytes, size_t size) override
    {
      if (marker.has_value())
      {
        for (auto& it : pending)
        {
          const auto buffer_end = it.buffer.data() + it.buffer.size();
          if (
            it.marker == marker.value() &&
            marker.value() != reinterpret_cast<uint64_t>(buffer_end))
          {
            // This is a pending write - dump data directly to write marker,
            // which should be within the appropriate buffer
            auto dest = (uint8_t*)marker.value();
            if (dest < it.buffer.data())
            {
              throw std::runtime_error(fmt::format(
                "Invalid pending marker - writing before buffer: {} < {}",
                (size_t)dest,
                (size_t)it.buffer.data()));
            }

            if (dest + size > buffer_end)
            {
              throw std::runtime_error(fmt::format(
                "Invalid pending marker - write extends beyond buffer: {} + {} "
                "> {}",
                (size_t)dest,
                (size_t)size,
                (size_t)buffer_end));
            }

            std::memcpy(dest, bytes, size);
            dest += size;
            it.marker = (size_t)dest;
            return {it.marker};
          }
        }
      }

      // Otherwise, this was successfully prepared on the underlying
      // implementation - delegate to it for remaining writes
      return underlying_writer->write_bytes(marker, bytes, size);
    }

    // Returns true if flush completed and there are no more pending messages.
    // False means 0 or more pending messages were written, but some remain
    bool try_flush_pending()
    {
      while (!pending.empty())
      {
        const auto& next = pending.front();
        if (!next.finished)
        {
          // If we reached an in-progress pending message, stop - we can't flush
          // this or anything after it
          break;
        }

        // Try to write this pending message to the underlying writer
        const auto marker = underlying_writer->prepare(
          next.m, next.buffer.size(), false, nullptr);

        if (!marker.has_value())
        {
          // No space - stop flushing
          break;
        }

        underlying_writer->write_bytes(
          marker, next.buffer.data(), next.buffer.size());
        underlying_writer->finish(marker);

        // This pending message was successfully written - pop it and continue
        pending.pop_front();
      }

      return pending.empty();
    }
  };

  class NonBlockingWriterFactory : public AbstractWriterFactory
  {
    AbstractWriterFactory& factory_impl;

    // Could be set, but needs custom hash() + operator<, so vector is simpler
    using WriterSet = std::vector<std::weak_ptr<ringbuffer::NonBlockingWriter>>;

    WriterSet writers_to_outside;
    WriterSet writers_to_inside;

    std::shared_ptr<ringbuffer::NonBlockingWriter> add_writer(
      const std::shared_ptr<ringbuffer::AbstractWriter>& underlying,
      WriterSet& writers)
    {
      auto new_writer = std::make_shared<NonBlockingWriter>(underlying);
      writers.emplace_back(new_writer);
      return new_writer;
    }

    bool flush_all(WriterSet& writers)
    {
      bool all_empty = true;

      auto it = writers.begin();
      while (it != writers.end())
      {
        auto shared_ptr = it->lock();
        if (shared_ptr)
        {
          all_empty &= shared_ptr->try_flush_pending();
          ++it;
        }
        else
        {
          it = writers.erase(it);
        }
      }

      return all_empty;
    }

  public:
    NonBlockingWriterFactory(AbstractWriterFactory& impl) : factory_impl(impl)
    {}

    std::shared_ptr<ringbuffer::NonBlockingWriter>
    create_non_blocking_writer_to_outside()
    {
      return add_writer(
        factory_impl.create_writer_to_outside(), writers_to_outside);
    }

    bool flush_all_outbound()
    {
      return flush_all(writers_to_outside);
    }

    std::shared_ptr<ringbuffer::NonBlockingWriter>
    create_non_blocking_writer_to_inside()
    {
      return add_writer(
        factory_impl.create_writer_to_inside(), writers_to_inside);
    }

    bool flush_all_inbound()
    {
      return flush_all(writers_to_inside);
    }

    std::shared_ptr<ringbuffer::AbstractWriter> create_writer_to_outside()
      override
    {
      return create_non_blocking_writer_to_outside();
    }

    std::shared_ptr<ringbuffer::AbstractWriter> create_writer_to_inside()
      override
    {
      return create_non_blocking_writer_to_inside();
    }
  };
}