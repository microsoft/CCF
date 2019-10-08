// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

template <class T>
inline T K_max(int k, const T* vector, int n, T tmax)
{
  // Requires: "vector" has "n" elements and tmax is the maximum value
  // for type T.
  // Effects: Returns a value "r" of "T" such that there are "k"
  // values greater than or equal to "r" in vector. It works well for
  // small "n" and "k" and when there are many elements with the value
  // being selected. These conditions are all expected to hold.
  T last_max = tmax;
  int last_count = 0;

  T cur_max = -1;
  int cur_count = 0;

  while (last_count < k)
  {
    for (int i = 0; i < n; i++)
    {
      T cv = vector[i];

      if (cv == cur_max)
      {
        cur_count++;
        continue;
      }

      if (cv > cur_max)
      {
        if (cv < last_max)
        {
          cur_count = 1;
          cur_max = cv;
        }
      }
    }
    last_max = cur_max;
    last_count += cur_count;
    cur_max = 0;
    cur_count = 0;
  }
  return last_max;
}
