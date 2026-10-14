// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "ccf/byte_vector.h"
#include "kv/raw_serialise.h"

#include <cerrno>
#include <doctest/doctest.h>

namespace
{
  thread_local bool fail_next_allocation = false;

  bool should_fail()
  {
    if (!fail_next_allocation)
      return false;
    fail_next_allocation = false;
    errno = ENOMEM;
    return true;
  }

  struct AllocationFailure
  {
    AllocationFailure()
    {
      fail_next_allocation = true;
    }
    ~AllocationFailure()
    {
      fail_next_allocation = false;
    }
  };

  template <class F>
  void check_allocation_failure(F&& operation)
  {
    bool threw = false;
    bool injected = false;
    {
      AllocationFailure failure;
      try
      {
        operation();
      }
      catch (const std::bad_alloc&)
      {
        threw = true;
      }
      injected = !fail_next_allocation;
    }
    REQUIRE(injected);
    REQUIRE(threw);
  }
}

extern "C"
{
  void* __real_malloc(size_t) noexcept;
  void* __real_realloc(void*, size_t) noexcept;
  void* __real_calloc(size_t, size_t) noexcept;

  void* __wrap_malloc(size_t size) noexcept
  {
    return should_fail() ? nullptr : __real_malloc(size);
  }

  void* __wrap_realloc(void* pointer, size_t size) noexcept
  {
    return should_fail() ? nullptr : __real_realloc(pointer, size);
  }

  void* __wrap_calloc(size_t count, size_t size) noexcept
  {
    return should_fail() ? nullptr : __real_calloc(count, size);
  }
}

TEST_CASE("ByteVector allocation failures preserve contents and ownership")
{
  for (const bool heap : {false, true})
  {
    for (size_t operation = 0; operation < 8; ++operation)
    {
      INFO(heap, operation);
      ccf::ByteVector bytes;
      if (heap)
        bytes.reserve(64);
      bytes.resize(bytes.capacity(), uint8_t{42});
      const ccf::ByteVector expected(bytes);
      const auto* pointer = bytes.data();
      const auto capacity = bytes.capacity();
      const ccf::ByteVector source(capacity + 100, uint8_t{7});
      check_allocation_failure([&]() {
        switch (operation)
        {
          case 0:
            bytes.reserve(capacity + 1);
            break;
          case 1:
            bytes.resize(capacity + 1);
            break;
          case 2:
            bytes.append(source.begin(), source.end());
            break;
          case 3:
            bytes.push_back(bytes[0]);
            break;
          case 4:
            bytes.assign(capacity + 1, bytes[0]);
            break;
          case 5:
            bytes = source;
            break;
          case 6:
          {
            const ccf::ByteVector copy(source);
            asm volatile("" : : "g"(&copy) : "memory");
            break;
          }
          case 7:
            bytes.insert(bytes.begin(), size_t{2}, bytes[0]);
            break;
        }
      });
      CHECK(bytes == expected);
      CHECK(bytes.data() == pointer);
      CHECK(bytes.capacity() == capacity);
    }
  }

  check_allocation_failure([]() {
    const ccf::ByteVector bytes(size_t{1024});
    asm volatile("" : : "g"(&bytes) : "memory");
  });
}

TEST_CASE("RawWriter allocation failures preserve complete output")
{
  for (const bool heap : {false, true})
  {
    for (size_t operation = 0; operation < 3; ++operation)
    {
      INFO(heap, operation);
      ccf::kv::RawWriter writer;
      writer.append(std::vector<uint8_t>(heap ? 1024 : 8, 42));
      const auto expected = writer.get_raw_data();
      const std::vector<uint8_t> extra(16384, 7);
      ccf::kv::RawWriter source;
      source.append(extra);
      check_allocation_failure([&]() {
        if (operation == 0)
          writer.append(extra);
        else if (operation == 1)
          writer = source;
        else
        {
          const ccf::kv::RawWriter copy(source);
          asm volatile("" : : "g"(&copy) : "memory");
        }
      });
      CHECK(writer.get_raw_data() == expected);
      CHECK(writer.size() == expected.size());
    }
  }
}
