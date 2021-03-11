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

}