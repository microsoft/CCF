// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <random>

namespace tpcc
{
  static constexpr int32_t num_warehouses = 10;
  static constexpr int32_t districts_per_warehouse = 10;
  static constexpr int32_t customers_per_district = 10;
  static constexpr int32_t num_items = 100;
  // YYYY-MM-DD HH:MM:SS This is supposed to be a date/time field from Jan 1st
  // 1900 - Dec 31st 2100 with a resolution of 1 second. See TPC-C 1.3.1.
  static constexpr int DATETIME_SIZE = 14;
  static constexpr std::array<char, tpcc::DATETIME_SIZE + 1> tx_time = {
    "12345 time"};

  // Defined by TPC-C 4.3.2.3.
  static void make_last_name(int num, char* name)
  {
    static const char* const SYLLABLES[] = {
      "BAR",
      "OUGHT",
      "ABLE",
      "PRI",
      "PRES",
      "ESE",
      "ANTI",
      "CALLY",
      "ATION",
      "EING",
    };
    static const int LENGTHS[] = {
      3,
      5,
      4,
      3,
      4,
      3,
      4,
      5,
      5,
      4,
    };

    int indicies[] = {num / 100, (num / 10) % 10, num % 10};

    int offset = 0;
    for (uint32_t i = 0; i < sizeof(indicies) / sizeof(*indicies); ++i)
    {
      memcpy(
        name + offset,
        SYLLABLES[indicies[i]],
        static_cast<size_t>(LENGTHS[indicies[i]]));
      offset += LENGTHS[indicies[i]];
    }
    name[offset] = '\0';
  }

  static float random_float(float min, float max, std::mt19937& rand_generator)
  {
    std::uniform_real_distribution<float> dist(min, max);
    return dist(rand_generator);
  }

  static uint32_t random_int(
    uint32_t min, uint32_t max, std::mt19937& rand_generator)
  {
    std::uniform_int_distribution<uint32_t> dist(min, max - 1);
    return dist(rand_generator);
  }

  static int32_t random_int_excluding(
    int lower, int upper, int excluding, std::mt19937& rand_generator)
  {
    // Generate 1 less number than the range
    int num = random_int(lower, upper - 1, rand_generator);

    // Adjust the numbers to remove excluding
    if (num >= excluding)
    {
      num += 1;
    }
    return num;
  }
}