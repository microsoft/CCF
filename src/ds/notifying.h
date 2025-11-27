// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ring_buffer.h"
#include "work_beacon.h"

#include <utility>

namespace ringbuffer
{
  class NotifyingWriter : public AbstractWriter
  {
  private:
    WriterPtr underlying_writer;
    ccf::ds::WorkBeaconPtr work_beacon;

  public:
    NotifyingWriter(WriterPtr writer, ccf::ds::WorkBeaconPtr wb) :
      underlying_writer(std::move(writer)),
      work_beacon(std::move(wb))
    {}

    // After the underlying writer finishes writing a message, notify any
    // waiting receivers
    void finish(const WriteMarker& marker) override
    {
      underlying_writer->finish(marker);
      work_beacon->notify_work_available();
    }

    // For all other overrides, defer directly to the underlying writer
    WriteMarker prepare(
      Message m,
      size_t size,
      bool wait = true,
      size_t* identifier = nullptr) override
    {
      return underlying_writer->prepare(m, size, wait, identifier);
    }

    WriteMarker write_bytes(
      const WriteMarker& marker, const uint8_t* bytes, size_t size) override
    {
      return underlying_writer->write_bytes(marker, bytes, size);
    }

    size_t get_max_message_size() override
    {
      return underlying_writer->get_max_message_size();
    }
  };

  class NotifyingWriterFactory : public AbstractWriterFactory
  {
  private:
    AbstractWriterFactory& factory_impl;

    ccf::ds::WorkBeaconPtr outbound_work_beacon;
    ccf::ds::WorkBeaconPtr inbound_work_beacon;

  public:
    NotifyingWriterFactory(AbstractWriterFactory& impl) :
      factory_impl(impl),
      outbound_work_beacon(std::make_shared<ccf::ds::WorkBeacon>()),
      inbound_work_beacon(std::make_shared<ccf::ds::WorkBeacon>())
    {}

    ccf::ds::WorkBeaconPtr get_outbound_work_beacon()
    {
      return outbound_work_beacon;
    }

    ccf::ds::WorkBeaconPtr get_inbound_work_beacon()
    {
      return inbound_work_beacon;
    }

    std::shared_ptr<NotifyingWriter> create_notifying_writer_to_outside()
    {
      return std::make_shared<NotifyingWriter>(
        factory_impl.create_writer_to_outside(), outbound_work_beacon);
    }

    std::shared_ptr<NotifyingWriter> create_notifying_writer_to_inside()
    {
      return std::make_shared<NotifyingWriter>(
        factory_impl.create_writer_to_inside(), inbound_work_beacon);
    }

    std::shared_ptr<ringbuffer::AbstractWriter> create_writer_to_outside()
      override
    {
      return create_notifying_writer_to_outside();
    }

    std::shared_ptr<ringbuffer::AbstractWriter> create_writer_to_inside()
      override
    {
      return create_notifying_writer_to_inside();
    }
  };
}
