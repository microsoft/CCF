// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/mem.h"
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

  // High bit of message size is used to indicate a pending message
  static constexpr uint32_t pending_write_flag = 1 << 31;
  static constexpr uint32_t length_mask = ~pending_write_flag;

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

    static bool is_aligned(uint8_t const* data, size_t align)
    {
      return reinterpret_cast<std::uintptr_t>(data) % align == 0;
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

    static constexpr size_t previous_power_of_2(size_t n)
    {
      const auto lz = __builtin_clzll(n);
      return 1ul << (sizeof(size_t) * 8 - 1 - lz);
    }

    static bool find_acceptable_sub_buffer(uint8_t*& data_, size_t& size_)
    {
      void* data = reinterpret_cast<void*>(data_);
      size_t size = size_;

      auto ret = std::align(8, sizeof(size_t), data, size);
      if (ret == nullptr)
      {
        return false;
      }

      data_ = reinterpret_cast<uint8_t*>(data);
      size_ = previous_power_of_2(size);
      return true;
    }

    static uint64_t make_header(Message m, size_t size, bool pending = true)
    {
      return (((uint64_t)m) << 32) |
        ((size & length_mask) | (pending ? pending_write_flag : 0u));
    }
  };

  struct BufferDef
  {
    uint8_t* data;
    size_t size;

    Offsets* offsets;

    void check_access(size_t index, size_t access_size)
    {
      if (index + access_size > size)
      {
#ifdef RINGBUFFER_USE_ABORT
        abort();
#else
        throw std::runtime_error(fmt::format(
          "Ringbuffer access out of bounds - attempting to access {}, max "
          "index is {}",
          index + access_size,
          size));
#endif
      }
    }
  };

  namespace
  {
    static inline uint64_t read64_impl(const BufferDef& bd, size_t index)
    {
#ifdef __cpp_lib_atomic_ref
      std::atomic_ref slot(reinterpret_cast<uint64_t*>(bd.data + index));
      return slot.load(std::memory_order_acquire);
#else
      // __atomic_load is used instead of std::atomic_ref since it's not
      // supported by libc++ yet.
      // https://en.cppreference.com/w/Template:cpp/compiler_support/20
      uint64_t r = 0;
      __atomic_load(
        reinterpret_cast<uint64_t*>(bd.data + index), &r, __ATOMIC_ACQUIRE);
      return r;
#endif
    }

    static inline Message message(uint64_t header)
    {
      return (Message)(header >> 32);
    }

    static inline uint32_t length(uint64_t header)
    {
      return header & std::numeric_limits<uint32_t>::max();
    }
  }

  class Reader
  {
    friend class Writer;

    BufferDef bd;

    std::vector<uint8_t> local_copy;

    virtual uint64_t read64(size_t index)
    {
      bd.check_access(index, sizeof(uint64_t));
      return read64_impl(bd, index);
    }

    virtual void clear_mem(size_t index, size_t advance)
    {
      ::memset(bd.data + index, 0, advance);
    }

  public:
    Reader(const BufferDef& bd_) : bd(bd_)
    {
      if (!Const::is_power_of_2(bd.size))
      {
        throw std::logic_error(
          fmt::format("Buffer size must be a power of 2, not {}", bd.size));
      }

      if (!Const::is_aligned(bd.data, 8))
      {
        throw std::logic_error("Buffer must be 8-byte aligned");
      }
    }

    size_t read(size_t limit, Handler f)
    {
      auto mask = bd.size - 1;
      auto hd = bd.offsets->head.load(std::memory_order_acquire);
      auto hd_index = hd & mask;
      auto block = bd.size - hd_index;
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
          // NB: Padding messages are potentially unaligned, where other
          // messages are aligned by calls to entry_size(). Even for an empty
          // padding message (size == 0), we need to skip past the message
          // header.
          advance += Const::header_size() + size;
          continue;
        }

        advance += Const::entry_size(size);
        ++count;

        // Call the handler function for this message.
        bd.check_access(hd_index, advance);

        if (ccf::pal::require_alignment_for_untrusted_reads() && size > 0)
        {
          // To prevent unaligned reads during message processing, copy aligned
          // chunk into enclave memory
          const auto copy_size = Const::align_size(size);
          if (local_copy.size() < copy_size)
          {
            local_copy.resize(copy_size);
          }
          ccf::pal::safe_memcpy(
            local_copy.data(),
            bd.data + msg_index + Const::header_size(),
            copy_size);
          f(m, local_copy.data(), (size_t)size);
        }
        else
        {
          f(m, bd.data + msg_index + Const::header_size(), (size_t)size);
        }
      }

      if (advance > 0)
      {
        // Zero the buffer and advance the head.
        bd.check_access(hd_index, advance);
        clear_mem(hd_index, advance);
        bd.offsets->head.store(hd + advance, std::memory_order_release);
      }

      return count;
    }
  };

  class Writer : public AbstractWriter
  {
  protected:
    BufferDef bd; // copy of reader's buffer definition
    const size_t rmax;

    struct Reservation
    {
      // Index within buffer of reservation start
      size_t index;

      // Individual identifier for this reservation. Should be unique across
      // buffer lifetime, amongst all writers
      size_t identifier;
    };

  public:
    Writer(const Reader& r) :
      bd(r.bd),
      rmax(Const::max_reservation_size(bd.size))
    {}

    Writer(const Writer& that) : bd(that.bd), rmax(that.rmax) {}

    virtual ~Writer() {}

    virtual std::optional<size_t> prepare(
      Message m,
      size_t size,
      bool wait = true,
      size_t* identifier = nullptr) override
    {
      // Make sure we aren't using a reserved message.
      if ((m < Const::msg_min) || (m > Const::msg_max))
      {
        throw message_error(
          m, fmt::format("Cannot use a reserved message ({})", m));
      }

      // Make sure the message fits.
      if (size > Const::max_size())
      {
        throw message_error(
          m,
          fmt::format(
            "Message ({}) is too long for any writer: {} > {}",
            m,
            size,
            Const::max_size()));
      }

      auto rsize = Const::entry_size(size);
      if (rsize > rmax)
      {
        throw message_error(
          m,
          fmt::format(
            "Message ({}) is too long for this writer: {} > {}",
            m,
            rsize,
            rmax));
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
      write64(r.value().index, Const::make_header(m, size));

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
        const auto header = read64(index);
        const auto size = length(header);
        const auto m = message(header);
        const auto finished_header = Const::make_header(m, size, false);
        write64(index, finished_header);
      }
    }

    virtual size_t get_max_message_size() override
    {
      return Const::max_size();
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

      bd.check_access(index, size);

      // Standard says memcpy(x, null, 0) is undefined, so avoid it
      if (size > 0)
      {
        ccf::pal::safe_memcpy(bd.data + index, bytes, size);
      }

      return {index + size};
    }

  private:
    // We use this to detect whether the head is ahead of the tail. In real
    // operation they should be close to each, relative to the total range of a
    // uint64_t. To handle wrap-around (ie - when a write has overflowed past
    // the max value), we consider it larger if the distance between a and b is
    // less than half the total range (and positive).
    static bool greater_with_wraparound(size_t a, size_t b)
    {
      static constexpr auto switch_point = UINT64_MAX / 2;

      return (a != b) && ((a - b) < switch_point);
    }

    virtual uint64_t read64(size_t index)
    {
      bd.check_access(index, sizeof(uint64_t));
      return read64_impl(bd, index);
    }

    virtual void write64(size_t index, uint64_t value)
    {
      bd.check_access(index, sizeof(value));
#ifdef __cpp_lib_atomic_ref
      std::atomic_ref slot(reinterpret_cast<uint64_t*>(bd.data + index));
      slot.store(value, std::memory_order_release);
#else
      // __atomic_store is used instead of std::atomic_ref since it's not
      // supported by libc++ yet.
      // https://en.cppreference.com/w/Template:cpp/compiler_support/20
      __atomic_store(
        reinterpret_cast<uint64_t*>(bd.data + index), &value, __ATOMIC_RELEASE);
#endif
    }

    std::optional<Reservation> reserve(size_t size)
    {
      auto mask = bd.size - 1;
      auto hd = bd.offsets->head_cache.load(std::memory_order_acquire);
      auto tl = bd.offsets->tail.load(std::memory_order_relaxed);

      // NB: These will be always be set on the first loop, before they are
      // read, so this initialisation is unnecessary. It is added to placate
      // static analyzers.
      size_t padding = 0u;
      size_t tl_index = 0u;

      do
      {
        auto gap = tl - hd;
        auto avail = bd.size - gap;

        // If the head cache is too far behind the tail, or if the message does
        // not fit in the available space, get an accurate head and try again.
        if ((gap > bd.size) || (size > avail))
        {
          // If the message does not fit in the sum of front-space and
          // back-space, see if head has moved to give us enough space.
          hd = bd.offsets->head.load(std::memory_order_acquire);

          // This happens if the head has passed the tail we previously loaded.
          // It is safe to continue here, as the compare_exchange_weak is
          // guaranteed to fail and update tl.
          if (greater_with_wraparound(hd, tl))
          {
            continue;
          }

          avail = bd.size - (tl - hd);

          // If it still doesn't fit, fail.
          if (size > avail)
            return {};

          // This may move the head cache backwards, but if so, that is safe and
          // will be corrected later.
          bd.offsets->head_cache.store(hd, std::memory_order_release);
        }

        padding = 0;
        tl_index = tl & mask;
        auto block = bd.size - tl_index;

        if (size > block)
        {
          // If the message doesn't fit in back-space...
          auto hd_index = hd & mask;

          if (size > hd_index)
          {
            // If message doesn't fit in front-space, see if the head has moved
            hd = bd.offsets->head.load(std::memory_order_acquire);
            hd_index = hd & mask;

            // If it still doesn't fit, fail - there is not a contiguous region
            // large enough for this reservation
            if (size > hd_index)
              return {};

            // This may move the head cache backwards, but if so, that is safe
            // and will be corrected later.
            bd.offsets->head_cache.store(hd, std::memory_order_release);
          }

          // Pad the back-space and reserve front-space for our message in a
          // single tail update.
          padding = block;
        }
      } while (!bd.offsets->tail.compare_exchange_weak(
        tl, tl + size + padding, std::memory_order_seq_cst));

      if (padding != 0)
      {
        write64(
          tl_index,
          Const::make_header(
            Const::msg_pad, padding - Const::header_size(), false));
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
    Circuit(
      const BufferDef& from_outside_buffer,
      const BufferDef& from_inside_buffer) :
      from_outside(from_outside_buffer),
      from_inside(from_inside_buffer)
    {}

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

  // This struct wraps buffer management to simplify testing
  struct TestBuffer
  {
    std::vector<uint8_t> storage;
    Offsets offsets;

    BufferDef bd;

    TestBuffer(size_t size) : storage(size, 0), offsets()
    {
      bd.data = storage.data();
      bd.size = storage.size();
      bd.offsets = &offsets;
    }
  };
}
