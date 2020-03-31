// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "bits.h"
#include "pbft_assert.h"

#include <stdio.h>

typedef size_t Chunk;
const size_t ChunkBits = sizeof(Chunk) * BYTE_BITS;

class Bitmap
{
public:
  Bitmap(size_t size);
  // Creates a bitmap with all bits reset

  Bitmap(Bitmap const& other) = delete;
  Bitmap& operator=(Bitmap const& other) = delete;

  ~Bitmap();

  void clear();
  // Clears the bitmap.

  bool test(size_t i) const;
  // requires: "i" is within bounds.
  // effects:  returns ith boolean.

  size_t size() const;
  // effects:  returns the size of the bitmap

  void set(size_t i);
  // requires: "i" is within bounds.
  // effects:  Sets ith boolean to true.
  // Note: this is faster than "assign"ing it to true.

  void reset(size_t i);
  // requires: "i" is within bounds.
  // effects:  Sets ith boolean to false.

  class Iter
  {
    // An iterator for yielding the booleans in a bool bitmap
    // Once created, an iterator must be used before any
    // changes are made to the iterated object. The effect is undefined
    // if an iterator method is called after such a change.

  public:
    Iter(Bitmap* bitmap);
    // Creates iterator to yield indices of bits set to true

    bool get(size_t& index);
    // modifies: index
    // effects: Sets "index" to the next index of a bit with value true.
    // Returns false iff there is no such index.

  private:
    Bitmap* bitmap; // The bitmap being yielded.

    size_t index; // Index of next boolean to be tested
  };

private:
  friend class Iter;

  size_t num; // size of the bitmap
  Chunk* chunks; // array of chunks storing booleans
  size_t nc; // number of chunks

  Chunk bitSelector(size_t i) const;
  // requires: "ChunkBits" is a power of 2.
  // effects: Computes the position p of the ith boolean within its
  // chunk and returns a chunk with pth bit set
};

inline Bitmap::Bitmap(size_t sz)
{
  num = sz;
  nc = (sz + ChunkBits - 1) / ChunkBits;
  chunks = new Chunk[nc];
  memset(chunks, 0, sizeof(Chunk) * nc);
}

inline Bitmap::~Bitmap()
{
  delete[] chunks;
}

inline Chunk Bitmap::bitSelector(size_t i) const
{
  return 1ULL << (i % ChunkBits);
}

inline void Bitmap::clear()
{
  memset(chunks, 0, sizeof(Chunk) * nc);
}

inline bool Bitmap::test(size_t i) const
{
  PBFT_ASSERT(i < num, "Index out of bounds\n");
  return (chunks[i / ChunkBits] & bitSelector(i)) != 0;
}

inline size_t Bitmap::size() const
{
  return num;
}

inline void Bitmap::set(size_t i)
{
  PBFT_ASSERT(i < num, "Index out of bounds\n");
  chunks[i / ChunkBits] |= bitSelector(i);
}

inline void Bitmap::reset(size_t i)
{
  PBFT_ASSERT(i < num, "Index out of bounds\n");
  chunks[i / ChunkBits] &= (~bitSelector(i));
}

inline Bitmap::Iter::Iter(Bitmap* b) : bitmap(b), index(0) {}

inline bool Bitmap::Iter::get(size_t& ind)
{
  while (index < bitmap->num)
  {
    if (bitmap->chunks[index / ChunkBits] == 0)
    {
      index += ChunkBits;
      continue;
    }

    if (bitmap->test(index))
    {
      ind = index++;
      return true;
    }
    index++;
  }
  return false;
}

//
// Generic char[] bitmap manipulation
//

static inline void Bits_set(char* bmap, int i)
{
  char* byte = bmap + (i / BYTE_BITS);
  *byte |= (1 << (i % BYTE_BITS));
}

static inline void Bits_reset(char* bmap, int i)
{
  char* byte = bmap + (i / BYTE_BITS);
  *byte &= ~(1 << (i % BYTE_BITS));
}

static inline bool Bits_test(char* bmap, int i)
{
  char* byte = bmap + (i / BYTE_BITS);
  return (*byte & (1 << (i % BYTE_BITS))) ? true : false;
}
