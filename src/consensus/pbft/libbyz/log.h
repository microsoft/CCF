// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "parameters.h"
#include "pbft_assert.h"
#include "types.h"

#include <iostream>
#include <vector>

template <class T>
class Log
{
  //
  // Log of T ordered by sequence number.
  //
  // Requires that "t" has a method:
  // void clear();

public:
  Log(int sz = max_out, Seqno h = 1);
  // Requires: "sz" is a power of 2 (allows for more efficient implementation).
  // Effects: Creates a log that holds "sz" elements and has
  // head equal to "h". The log only maintains elements with sequence
  // number higher than "head" and lower than "tail" = "head"+"max_size"-1

  void clear(Seqno h);
  // Effects: Calls "clear" for all elements in log and sets head to "h"

  T& fetch(Seqno seqno);
  // Requires: "within_range(seqno)"
  // Effects: Returns the entry corresponding to "seqno".

  void truncate(Seqno new_head);
  // Effects: Truncates the log clearing all elements with sequence
  // number lower than new_head.

  bool within_range(Seqno seqno) const;
  // Effects: Returns true iff "seqno" is within range.

  Seqno head_seqno() const;
  // Effects: Returns the sequence number for the head of the log.

  Seqno max_seqno() const;
  // Effects: Returns the maximum sequence number that can be
  // stored in the log.

  void dump_state(std::ostream& os);
  // Effects: logs state for debugging

protected:
  Seqno head;
  int max_size;
  std::map<Seqno, T> elems;
};

template <class T>
inline bool Log<T>::within_range(Seqno seqno) const
{
  return seqno >= head && seqno < head + max_size;
}

template <class T>
inline Seqno Log<T>::head_seqno() const
{
  return head;
}

template <class T>
inline Seqno Log<T>::max_seqno() const
{
  return head + max_size - 1;
}

template <class T>
Log<T>::Log(int sz, Seqno h) : head(h), max_size(sz)
{}

template <class T>
void Log<T>::clear(Seqno h)
{
  elems.clear();

  head = h;
}

template <class T>
T& Log<T>::fetch(Seqno seqno)
{
  PBFT_ASSERT(within_range(seqno), "Invalid argument\n");
  return elems[seqno];
}

template <class T>
void Log<T>::truncate(Seqno new_head)
{
  for (auto it = elems.begin(); it != elems.end();)
  {
    if (it->first < new_head)
    {
      it = elems.erase(it);
    }
    else
    {
      ++it;
    }
  }

  head = new_head;
}

template <class T>
void Log<T>::dump_state(std::ostream& os)
{
  os << " head:" << head << std::endl;
  for (Seqno n = head; n < head + max_size; n++)
  {
    auto& entry = elems[n];
    if (!entry.is_empty())
    {
      os << "seqno: " << n;
      if (entry.is_complete())
      {
        os << " is complete\n";
      }
      else
      {
        os << " ";
        entry.dump_state(os);
      }
    }
  }
}
