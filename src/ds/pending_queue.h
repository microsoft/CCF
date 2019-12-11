#pragma once

#include "ringbuffer.h"

#include <fmt/format_header_only.h>
#include <queue>

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
    // std::queue pending;

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
      std::cout
        << fmt::format(
             "prepare({}, {}, {}, {})", m, total_size, wait, (size_t)identifier)
        << std::endl;

      return writer_impl->prepare(m, total_size, wait, identifier);
    }

    virtual void finish(const WriteMarker& marker) override
    {
      std::cout << fmt::format(
                     "finish({})",
                     marker.has_value() ? fmt::format("{}", *marker) : "EMPTY")
                << std::endl;

      writer_impl->finish(marker);
    }

    virtual WriteMarker write_bytes(
      const WriteMarker& marker, const uint8_t* bytes, size_t size) override
    {
      std::cout << fmt::format(
                     "write_bytes({}, {}, {})",
                     marker.has_value() ? fmt::format("{}", *marker) : "EMPTY",
                     (size_t)bytes,
                     size)
                << std::endl;

      return writer_impl->write_bytes(marker, bytes, size);
    }
  };

  template <typename FactoryImpl>
  class PendingQueueFactory : public ringbuffer::AbstractWriterFactory
  {
    FactoryImpl& factory_impl;

  public:
    PendingQueueFactory(FactoryImpl& factory) : factory_impl(factory) {}

    std::unique_ptr<ringbuffer::AbstractWriter> create_writer_to_outside()
      override
    {
      return std::make_unique<PendingQueueWriter>(
        factory_impl.create_writer_to_outside());
    }

    std::unique_ptr<ringbuffer::AbstractWriter> create_writer_to_inside()
      override
    {
      return std::make_unique<PendingQueueWriter>(
        factory_impl.create_writer_to_inside());
    }
  };
}