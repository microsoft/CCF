#pragma once

namespace tpcc
{
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

  static float random_float(float max, float min)
  {
    return min +
      static_cast<float>(rand()) / (static_cast<float>(RAND_MAX / (max - min)));
  }

  static uint32_t random_int(uint32_t min, uint32_t max)
  {
    return (rand() % (max - min)) + min;
  }

  static int32_t random_int_excluding(int lower, int upper, int excluding)
  {
    // Generate 1 less number than the range
    int num = random_int(lower, upper - 1);

    // Adjust the numbers to remove excluding
    if (num >= excluding)
    {
      num += 1;
    }
    return num;
  }
}