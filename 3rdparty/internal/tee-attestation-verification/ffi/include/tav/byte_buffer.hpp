// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <tav/byte_buffer.h>

#include <cstdint>
#include <span>
#include <utility>

namespace tav
{
/// An owned byte buffer returned by a public C ABI function.
///
/// Moving transfers the handle and empties the source. bytes() returns a view
/// borrowed from this buffer; it must not outlive the ByteBuffer.
class ByteBuffer
{
public:
    ByteBuffer() = default;
    ByteBuffer(const ByteBuffer&) = delete;
    ByteBuffer& operator=(const ByteBuffer&) = delete;

    ByteBuffer(ByteBuffer&& other) noexcept :
      handle_(std::exchange(other.handle_, nullptr))
    {}

    ByteBuffer& operator=(ByteBuffer&& other) noexcept
    {
        if (this != &other)
        {
            tav_byte_buffer_free(handle_);
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    ~ByteBuffer()
    {
        tav_byte_buffer_free(handle_);
    }

    /// True if a buffer is owned, even when it contains zero bytes.
    [[nodiscard]] bool has_value() const noexcept
    {
        return handle_ != nullptr;
    }

    [[nodiscard]] std::span<const uint8_t> bytes() const
    {
        return {tav_byte_buffer_data(handle_), tav_byte_buffer_len(handle_)};
    }

    /// Takes ownership of `handle`, a buffer a C ABI function produced. The
    /// bytes are not copied; the returned ByteBuffer frees the handle when it
    /// is destroyed.
    ///
    /// `handle` must be null or a live buffer from this library. Adopting null
    /// yields an empty ByteBuffer. The caller must not adopt the same non-null
    /// handle twice, or free it separately: nothing here tracks a handle that
    /// was already adopted, so a second owner double-frees it.
    static ByteBuffer adopt(TavByteBuffer* handle)
    {
        return ByteBuffer(handle);
    }

private:
    explicit ByteBuffer(TavByteBuffer* handle) : handle_(handle) {}

    TavByteBuffer* handle_ = nullptr;
};
}
