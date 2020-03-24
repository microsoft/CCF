// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ring_buffer_types.h"

#include <atomic>
#include <cstring>
#include <functional>

// Ideally this would be _mm_pause or similar, but finding cross-platform
// headers that expose this neatly through OE (ie - non-standard std libs) is
// awkward. Instead we resort to copying OE, and implementing this directly
// ourselves.
#define CCF_PAUSE() asm volatile("pause")

// This file implements a Multiple-Producer Single-Consumer ringbuffer.

// A single Reader instance owns an underlying memory buffer, and a single
// thread should process message written to it. Any number of other threads and
// Writers may write to it, and the messages will be distinct, correct, and
// ordered.

// A Circuit wraps a pair of ringbuffers to allow 2-way communication - messages
// are written to the inbound buffer, processed inside an enclave, and responses
// written back to the outbound.

namespace ringbuffer
{
  using Handler = std::function<void(Message, const uint8_t*, size_t)>;

  // Align by cacheline to avoid false sharing
  static constexpr size_t CACHELINE_SIZE = 64;

  // High bit of message size is used to indicate a pending message
  static constexpr uint32_t pending_write_flag = 1 << 31;
  static constexpr uint32_t length_mask = ~pending_write_flag;

  struct alignas(CACHELINE_SIZE) Var
  {
    std::atomic<size_t> head_cache;
    std::atomic<size_t> tail;
    alignas(CACHELINE_SIZE) std::atomic<size_t> head;
  };

  struct Const
  {
    enum : Message
    {
      msg_max = std::numeric_limits<Message>::max() - 1,
      msg_min = 1,
      msg_none = 0,
      msg_pad = std::numeric_limits<Message>::max()
    };

    static constexpr bool is_power_of_2(size_t n)
    {
      return n && ((n & (~n + 1)) == n);
    }

    static constexpr size_t header_size()
    {
      // The header is a 32 bit length and a 32 bit message ID.
      return sizeof(int32_t) + sizeof(uint32_t);
    }

    static constexpr size_t align_size(size_t n)
    {
      // Make sure the header is aligned in memory.
      return (n + (header_size() - 1)) & ~(header_size() - 1);
    }

    static constexpr size_t entry_size(size_t n)
    {
      return Const::align_size(n + header_size());
    }

    static constexpr size_t max_size()
    {
      // The length of a message plus its header must be encodable in the
      // header. High bit of lengths indicate pending writes.
      return std::numeric_limits<int32_t>::max() - header_size();
    }

    static constexpr size_t max_reservation_size(size_t buffer_size)
    {
      // This guarantees that in an empty buffer, we can always make this
      // reservation in a single contiguous region (either before or after the
      // current tail). If we allow larger reservations then we may need to
      // artificially advance the tail (writing padding then clearing it) to
      // create a sufficiently large region.
      return buffer_size / 2;
    }

    uint8_t* const buffer;
    const size_t size;

    Const(uint8_t* const buffer, size_t size) : buffer(buffer), size(size)
    {
      if (!is_power_of_2(size))
        throw std::logic_error("Buffer size must be a power of 2");
    }
  };

  class Reader
  {
    friend class Writer;

    std::vector<uint8_t> buffer;
    Const c;
    Var v;

  public:
    Reader(const size_t size) :
      buffer(size, 0),
      c(buffer.data(), size),
      v{{0}, {0}, {0}}
    {}

    size_t read(size_t limit, Handler f)
    {
      auto mask = c.size - 1;
      auto hd = v.head.load(std::memory_order_acquire);
      auto hd_index = hd & mask;
      auto block = c.size - hd_index;
      size_t advance = 0;
      size_t count = 0;

      while ((advance < block) && (count < limit))
      {
        auto msg_index = hd_index + advance;
        auto header = read64(msg_index);
        auto size = length(header);

        // If we see a pending write, we're done.
        if ((size & pending_write_flag) != 0u)
          break;

        auto m = message(header);

        if (m == Const::msg_none)
        {
          // There is no message here, we're done.
          break;
        }
        else if (m == Const::msg_pad)
        {
          // If we see padding, skip it.
          advance += size;
          continue;
        }

        advance += Const::entry_size(size);
        ++count;

        // Call the handler function for this message.
        f(m, c.buffer + msg_index + Const::header_size(), (size_t)size);
      }

      if (advance > 0)
      {
        // Zero the buffer and advance the head.
        ::memset(c.buffer + hd_index, 0, advance);
        v.head.store(hd + advance, std::memory_order_release);
      }

      return count;
    }

  private:
    uint64_t read64(size_t index)
    {
      uint64_t r = *reinterpret_cast<volatile uint64_t*>(c.buffer + index);
      atomic_thread_fence(std::memory_order_acq_rel);
      return r;
    }

    static Message message(uint64_t header)
    {
      return (Message)(header >> 32);
    }

    static uint32_t length(uint64_t header)
    {
      return header & std::numeric_limits<uint32_t>::max();
    }
  };

  class Writer : public AbstractWriter
  {
  protected:
    Const c; // copy of reader's consts
    Var* v; // pointer to reader's vars

    virtual void checkAccess(size_t index, size_t size) {}

    struct Reservation
    {
      // Index within buffer of reservation start
      size_t index;

      // Individual identifier for this reservation. Should be unique across
      // buffer lifetime, amongst all writers
      size_t identifier;
    };

  public:
    Writer(const Reader& r) : c(r.c), v(const_cast<ringbuffer::Var*>(&r.v)) {}

    Writer(const Writer& that) : c(that.c), v(that.v) {}

    virtual ~Writer() {}

    virtual std::optional<size_t> prepare(
      Message m,
      size_t size,
      bool wait = true,
      size_t* identifier = nullptr) override
    {
      // Make sure we aren't using a reserved message.
      if ((m < Const::msg_min) || (m > Const::msg_max))
        throw message_error(
          m, "Cannot use a reserved message (" + std::to_string(m) + ")");

      // Make sure the message fits.
      if (size > Const::max_size())
        throw message_error(
          m,
          "Message (" + std::to_string(m) + ") is too long for any writer (" +
            std::to_string(size) + " > " + std::to_string(Const::max_size()) +
            ")");

      auto rsize = Const::entry_size(size);
      auto rmax = Const::max_reservation_size(c.size);
      if (rsize > rmax)
      {
        throw message_error(
          m,
          "Message (" + std::to_string(m) +
            ") with header is too long for this writer (" +
            std::to_string(rsize) + " > " + std::to_string(rmax) + ")");
      }

      auto r = reserve(rsize);

      if (!r.has_value())
      {
        if (wait)
        {
          // Retry until there is sufficient space.
          do
          {
            CCF_PAUSE();
            r = reserve(rsize);
          } while (!r.has_value());
        }
        else
        {
          // Fail if there is insufficient space.
          return {};
        }
      }

      // Write the preliminary header and return the buffer pointer.
      // The initial header length has high bit set to indicate a pending
      // message. We rewrite the real length after the message data.
      write64(r.value().index, make_header(m, size));

      if (identifier != nullptr)
        *identifier = r.value().identifier;

      return {r.value().index + Const::header_size()};
    }

    virtual void finish(const WriteMarker& marker) override
    {
      if (marker.has_value())
      {
        // Fix up the size to indicate we're done writing - unset pending bit.
        const auto index = marker.value() - Const::header_size();
        auto size = read32(index);
        write32(index, size & length_mask);
      }
    }

  protected:
    virtual WriteMarker write_bytes(
      const WriteMarker& marker, const uint8_t* bytes, size_t size) override
    {
      if (!marker.has_value())
      {
        return {};
      }

      const auto index = marker.value();

      checkAccess(index, size);

      // Standard says memcpy(x, null, 0) is undefined, so avoid it
      if (size > 0)
        ::memcpy(c.buffer + index, bytes, size);

      return {index + size};
    }

  private:
    uint32_t read32(size_t index)
    {
      uint32_t r;
      checkAccess(index, sizeof(r));
      r = *reinterpret_cast<volatile uint32_t*>(c.buffer + index);
      atomic_thread_fence(std::memory_order_acq_rel);
      return r;
    }

    void write32(size_t index, uint32_t value)
    {
      atomic_thread_fence(std::memory_order_acq_rel);
      checkAccess(index, sizeof(value));
      *reinterpret_cast<volatile uint32_t*>(c.buffer + index) = value;
    }

    void write64(size_t index, uint64_t value)
    {
      atomic_thread_fence(std::memory_order_acq_rel);
      checkAccess(index, sizeof(value));
      *reinterpret_cast<volatile uint64_t*>(c.buffer + index) = value;
    }

    uint64_t make_header(Message m, size_t size, bool pending = true)
    {
      return (((uint64_t)m) << 32) |
        ((size & length_mask) | (pending ? pending_write_flag : 0u));
    }

    std::optional<Reservation> reserve(size_t size)
    {
      auto mask = c.size - 1;
      auto hd = v->head_cache.load(std::memory_order_relaxed);
      auto tl = v->tail.load(std::memory_order_relaxed);

      // NB: These will be always be set on the first loop, before they are
      // read, so this initialisation is unnecessary. It is added to placate
      // static analyzers.
      size_t padding = 0u;
      size_t tl_index = 0u;

      do
      {
        auto gap = tl - hd;
        auto avail = c.size - gap;

        // If the head cache is too far behind the tail, or if the message does
        // not fit in the available space, get an accurate head and try again.
        if ((gap > c.size) || (size > avail))
        {
          // If the message does not fit in the sum of front-space and
          // back-space, see if head has moved to give us enough space.
          hd = v->head.load(std::memory_order_relaxed);

          // This happens if the head has passed the tail we previously loaded.
          // It is safe to continue here, as the compare_exchange_weak is
          // guaranteed to fail and update tl.
          if (hd > tl)
            continue;

          avail = c.size - (tl - hd);

          // If it still doesn't fit, fail.
          if (size > avail)
            return {};

          // This may move the head cache backwards, but if so, that is safe and
          // will be corrected later.
          v->head_cache.store(hd, std::memory_order_relaxed);
        }

        padding = 0;
        tl_index = tl & mask;
        auto block = c.size - tl_index;

        if (size > block)
        {
          // If the message doesn't fit in back-space...
          auto hd_index = hd & mask;

          if (size > hd_index)
          {
            // If message doesn't fit in front-space, see if the head has moved
            hd = v->head.load(std::memory_order_relaxed);
            hd_index = hd & mask;

            // If it still doesn't fit, fail - there is not a contiguous region
            // large enough for this reservation
            if (size > hd_index)
              return {};

            // This may move the head cache backwards, but if so, that is safe
            // and will be corrected later.
            v->head_cache.store(hd, std::memory_order_relaxed);
          }

          // Pad the back-space and reserve front-space for our message in a
          // single tail update.
          padding = block;
        }
      } while (!v->tail.compare_exchange_weak(
        tl, tl + size + padding, std::memory_order_seq_cst));

      if (padding != 0)
      {
        write64(tl_index, make_header(Const::msg_pad, padding, false));
        tl_index = 0;
      }

      return {{tl_index, tl}};
    }
  };

  // This is entirely non-virtual so can be safely passed to the enclave
  class Circuit
  {
  private:
    ringbuffer::Reader from_outside;
    ringbuffer::Reader from_inside;

  public:
    Circuit(size_t size) : from_outside(size), from_inside(size) {}

    ringbuffer::Reader& read_from_outside()
    {
      return from_outside;
    }

    ringbuffer::Reader& read_from_inside()
    {
      return from_inside;
    }

    ringbuffer::Writer write_to_outside()
    {
      return ringbuffer::Writer(from_inside);
    }

    ringbuffer::Writer write_to_inside()
    {
      return ringbuffer::Writer(from_outside);
    }
  };

  class WriterFactory : public AbstractWriterFactory
  {
    ringbuffer::Circuit& raw_circuit;

  public:
    WriterFactory(ringbuffer::Circuit& c) : raw_circuit(c) {}

    std::shared_ptr<ringbuffer::AbstractWriter> create_writer_to_outside()
      override
    {
      return std::make_shared<Writer>(raw_circuit.read_from_inside());
    }

    std::shared_ptr<ringbuffer::AbstractWriter> create_writer_to_inside()
      override
    {
      return std::make_shared<Writer>(raw_circuit.read_from_outside());
    }
  };
}
