// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/hardware_info.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

// Adapted from:
// https://software.intel.com/en-us/articles/intel-digital-random-number-generator-drng-software-implementation-guide

#define DRNG_NO_SUPPORT 0x0
#define DRNG_HAS_RDRAND 0x1
#define DRNG_HAS_RDSEED 0x2

// `It is recommended that applications attempt 10 retries in a tight loop in
// the unlikely event that the RDRAND instruction does not return a random
// number. This number is based on a binomial probability argument: given
// the design margins of the DRNG, the odds of ten failures in a row are
// astronomically small and would in fact be an indication of a larger CPU
// issue.`
#define RDRAND_RETRIES 10

namespace crypto
{
  using rng_func_t = int (*)(void* ctx, unsigned char* output, size_t len);

  class Entropy
  {
  public:
    Entropy() = default;
    virtual ~Entropy() = default;

    /// Generate @p len random bytes
    /// @param len Number of random bytes to generate
    /// @return vector random bytes
    virtual std::vector<uint8_t> random(size_t len) = 0;

    /// Generate @p len random bytes into @p data
    /// @param len Number of random bytes to generate
    /// @param data Buffer to fill
    virtual void random(unsigned char* data, size_t len) = 0;

    /// Generate a random uint64_t
    /// @return a random uint64_t
    virtual uint64_t random64() = 0;
  };

  class IntelDRNG : public Entropy
  {
  private:
    static int get_drng_support()
    {
      thread_local int drng_features = -1;

      /* So we don't call cpuid multiple times for the same information */
      if (drng_features == -1)
      {
        drng_features = DRNG_NO_SUPPORT;

        if (ccf::pal::is_intel_cpu())
        {
          ccf::pal::CpuidInfo info;

          ccf::pal::cpuid(&info, 1, 0);

          if ((info.ecx & 0x40000000) == 0x40000000)
            drng_features |= DRNG_HAS_RDRAND;

          cpuid(&info, 7, 0);

          if ((info.ebx & 0x40000) == 0x40000)
            drng_features |= DRNG_HAS_RDSEED;
        }
      }

      return drng_features;
    }

    // The attribute below prevents ASAN error
    // (Internal ticket: https://github.com/microsoft/CCF/issues/5050).
    // ASAN with Debug mode causes invalid memory access.
    // These suppressions can be removed after
    // https://github.com/google/sanitizers/issues/1629 is resolved.
#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
    __attribute__((no_sanitize("address")))
#  endif
#endif
    static int
    rdrand16_step(uint16_t* rand)
    {
      unsigned char ok;
      asm volatile("rdrand %0; setc %1" : "=r"(*rand), "=qm"(ok));
      return (int)ok;
    }

#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
    __attribute__((no_sanitize("address")))
#  endif
#endif
    static int
    rdrand32_step(uint32_t* rand)
    {
      unsigned char ok;
      asm volatile("rdrand %0; setc %1" : "=r"(*rand), "=qm"(ok));
      return (int)ok;
    }

#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
    __attribute__((no_sanitize("address")))
#  endif
#endif
    static int
    rdrand64_step(uint64_t* rand)
    {
      unsigned char ok;
      asm volatile("rdrand %0; setc %1" : "=r"(*rand), "=qm"(ok));
      return (int)ok;
    }

    static int rdrand16_retry(unsigned int retries, uint16_t* rand)
    {
      unsigned int count = 0;

      while (count <= retries)
      {
        if (rdrand16_step(rand))
          return 1;
        ++count;
      }

      return 0;
    }

    static int rdrand32_retry(unsigned int retries, uint32_t* rand)
    {
      unsigned int count = 0;

      while (count <= retries)
      {
        if (rdrand32_step(rand))
          return 1;

        ++count;
      }

      return 0;
    }

    static int rdrand64_retry(unsigned int retries, uint64_t* rand)
    {
      unsigned int count = 0;

      while (count <= retries)
      {
        if (rdrand64_step(rand))
          return 1;

        ++count;
      }

      return 0;
    }

    static unsigned int rdrand_get_bytes(unsigned int n, unsigned char* dest)
    {
      unsigned char *headstart, *tailstart = nullptr;
      uint64_t* blockstart;
      unsigned int count, ltail, lhead, lblock;
      uint64_t i, temprand;

      /* Get the address of the first 64-bit aligned block in the
       * destination buffer. */
      headstart = dest;
      if (((uint64_t)headstart % (uint64_t)8) == 0)
      {
        blockstart = (uint64_t*)headstart;
        lblock = n;
        lhead = 0;
      }
      else
      {
        blockstart =
          (uint64_t*)(((uint64_t)headstart & ~(uint64_t)7) + (uint64_t)8);
        lhead = (unsigned int)((uint64_t)blockstart - (uint64_t)headstart);
        lblock =
          ((n - lhead) & ~(unsigned int)7); // cwinter: this bit is/as buggy in
                                            // the Intel examples.
      }

      /* Compute the number of 64-bit blocks and the remaining number
       * of bytes (the tail) */
      ltail = n - lblock - lhead;
      count = lblock / 8; /* The number 64-bit rands needed */

      assert(lhead < 8);
      assert(lblock <= n);
      assert(ltail < 8);

      if (ltail)
        tailstart = (unsigned char*)((uint64_t)blockstart + (uint64_t)lblock);

      /* Populate the starting, mis-aligned section (the head) */
      if (lhead)
      {
        if (!rdrand64_retry(RDRAND_RETRIES, &temprand))
          return 0;
        memcpy(headstart, &temprand, lhead);
      }

      /* Populate the central, aligned block */
      for (i = 0; i < count; ++i, ++blockstart)
      {
        if (!rdrand64_retry(RDRAND_RETRIES, blockstart))
          return i * 8 + lhead;
      }

      /* Populate the tail */
      if (ltail)
      {
        if (!rdrand64_retry(RDRAND_RETRIES, &temprand))
          return count * 8 + lhead;
        memcpy(tailstart, &temprand, ltail);
      }

      return n;
    }

    // The following three functions should be used to generate
    // randomness that will be used as seed for another RNG
    static int rdseed16_step(uint16_t* seed)
    {
      unsigned char ok;
      asm volatile("rdseed %0; setc %1" : "=r"(*seed), "=qm"(ok));
      return (int)ok;
    }

    static int rdseed32_step(uint32_t* seed)
    {
      unsigned char ok;
      asm volatile("rdseed %0; setc %1" : "=r"(*seed), "=qm"(ok));
      return (int)ok;
    }

    static int rdseed64_step(uint64_t* seed)
    {
      unsigned char ok;
      asm volatile("rdseed %0; setc %1" : "=r"(*seed), "=qm"(ok));
      return (int)ok;
    }

  public:
    IntelDRNG()
    {
      if (!is_drng_supported())
        throw std::logic_error("No support for RDRAND / RDSEED on this CPU.");
    }

    /** Generate @p len random bytes
     * @param len Number of random bytes to generate
     * @return vector random bytes
     */
    std::vector<uint8_t> random(size_t len) override
    {
      std::vector<uint8_t> buf(len);

      if (rdrand_get_bytes(buf.size(), buf.data()) < buf.size())
        throw std::logic_error("Couldn't create random data");

      return buf;
    }

    /** Generate a random uint64_t
     * @return a random uint64_t
     */
    uint64_t random64() override
    {
      uint64_t rnd;
      uint64_t len = sizeof(uint64_t);

      if (rdrand_get_bytes(len, reinterpret_cast<unsigned char*>(&rnd)) < len)
      {
        throw std::logic_error("Couldn't create random data");
      }

      return rnd;
    }

    /** Generate @p len random bytes into @p data
     * @param len Number of random bytes to generate
     * @param data Buffer to fill
     */
    void random(unsigned char* data, size_t len) override
    {
      if (rdrand_get_bytes(len, data) < len)
        throw std::logic_error("Couldn't create random data");
    }

    static int rng(void*, unsigned char* output, size_t len)
    {
      if (rdrand_get_bytes(len, output) < len)
        throw std::logic_error("Couldn't create random data");
      return 0;
    }

    static bool is_drng_supported()
    {
      return (get_drng_support() & (DRNG_HAS_RDRAND | DRNG_HAS_RDSEED)) ==
        (DRNG_HAS_RDRAND | DRNG_HAS_RDSEED);
    }
  };

  static bool use_drng = IntelDRNG::is_drng_supported();
  using EntropyPtr = std::shared_ptr<Entropy>;
  static EntropyPtr intel_drng_ptr;

  /** Create a default Entropy object */
  EntropyPtr create_entropy();
}
