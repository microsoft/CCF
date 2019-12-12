#pragma once

#include "ringbuffer.h"

#include <deque>
#include <fmt/format_header_only.h>

namespace ringbuffer
{
  // This wraps an underlying Writer implementation and ensure calls to write()
  // will not block indefinitely. This never calls the blocking write()
  // implementation. Instead it calls try_write(), and in the case that a write
  // fails (because the target ringbuffer is full), the message is placed in a
  // pending queue. These pending message must be flushed regularly, attempting
  // again to write to the ringbuffer.

  class PendingQueueWriter : public AbstractWriter
  {
  private:
    std::unique_ptr<AbstractWriter> writer_impl;

    struct PendingMessage
    {
      Message m;
      size_t marker;
      std::vector<uint8_t> buffer;

      PendingMessage(
        Message m_, size_t marker_, std::vector<uint8_t>&& buffer_) :
        m(m_),
        marker(marker_),
        buffer(buffer_)
      {}
    };

    std::deque<PendingMessage> pending;

  public:
    PendingQueueWriter(std::unique_ptr<AbstractWriter>&& writer) :
      writer_impl(std::move(writer))
    {}

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
          writer_impl->prepare(m, total_size, false, identifier);

        if (marker.has_value())
        {
          return marker;
        }

        // Prepare failed, no space in buffer - so add to queue
      }

      pending.emplace_back(m, 0, std::vector<uint8_t>(total_size));

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
        for (const auto& it : pending)
        {
          // NB: finish is passed the _initial_ WriteMarker, so we compare
          // against it.buffer.data() rather than it.marker
          if ((size_t)it.buffer.data() == marker.value())
          {
            // This is a pending write. All data should now be written. No work
            // to do for finish
            return;
          }
        }
      }

      writer_impl->finish(marker);
    }

    virtual WriteMarker write_bytes(
      const WriteMarker& marker, const uint8_t* bytes, size_t size) override
    {
      if (marker.has_value())
      {
        for (auto& it : pending)
        {
          if (it.marker == marker.value())
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

            const auto buffer_end = it.buffer.data() + it.buffer.size();
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
      return writer_impl->write_bytes(marker, bytes, size);
    }

    bool try_flush_pending()
    {
      return false;
    }
  };

  class PendingQueueFactory : public AbstractWriterFactory
  {
    AbstractWriterFactory& factory_impl;

  public:
    PendingQueueFactory(AbstractWriterFactory& factory) : factory_impl(factory)
    {}

    std::unique_ptr<ringbuffer::PendingQueueWriter>
    create_pending_writer_to_outside()
    {
      return std::make_unique<PendingQueueWriter>(
        factory_impl.create_writer_to_outside());
    }

    std::unique_ptr<ringbuffer::PendingQueueWriter>
    create_pending_writer_to_inside()
    {
      return std::make_unique<PendingQueueWriter>(
        factory_impl.create_writer_to_inside());
    }

    std::unique_ptr<ringbuffer::AbstractWriter> create_writer_to_outside()
      override
    {
      return create_pending_writer_to_outside();
    }

    std::unique_ptr<ringbuffer::AbstractWriter> create_writer_to_inside()
      override
    {
      return create_pending_writer_to_inside();
    }
  };
}