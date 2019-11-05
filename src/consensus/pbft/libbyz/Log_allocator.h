// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "pbft_assert.h"
#include "types.h"

#include <cstring>

// Since messages may contain other messages in the payload. It is
// important to ensure proper alignment to allow access to the fields
// of embedded messages. The following macros are used to check and
// enforce alignment requirements. All message pointers and message
// sizes must satisfy ALIGNED.

// Minimum required alignment for correctly accessing message fields.
// Must be a power of 2.
#define ALIGNMENT 8

// bool ALIGNED(void *ptr) or bool ALIGNED(long sz)
// Effects: Returns true iff the argument is aligned to ALIGNMENT
#define ALIGNED(ptr) (((uintptr_t)(ptr)) % ALIGNMENT == 0)

// int ALIGNED_SIZE(int sz)
// Effects: Increases sz to the least multiple of ALIGNMENT greater
// than size.
#define ALIGNED_SIZE(sz) \
  ((ALIGNED(sz)) ? (sz) : (sz) - (sz) % ALIGNMENT + ALIGNMENT)

#ifndef NDEBUG
#  define DEBUG_ALLOC 1
#endif

#define USE_STD_MALLOC

class Log_allocator
{
  // Overview: A fast and space efficient memory allocator. It assumes
  // objects that are allocated close together in time are freed close
  // together in time (otherwise it may waste a lot of memory). For
  // example, this assumption holds if the heap objects are allocated
  // as part of a sequential log and are deallocated when the log is
  // truncated.

public:
  Log_allocator(int csz = 131072, int nc = 16);
  // Requires: "csz" is a multiple of the operating system vm page size.
  // Effects: Creates an allocator object with chunks of size "csz" and
  // an area for allocating chunks that can hold up to "nc" chunks.

  ~Log_allocator();

  char* malloc(int sz);
  // Requires: size > 0 and sz < this.chunk_size
  // Effects: Allocates a heap block with "sz" bytes. The user of the
  // abstraction is responsible for keeping track of the size of the
  // returned block.

  void free(char* p, int sz);
  // Requires: "p" was allocated by this allocator and has size "sz"
  // Effects: Frees "p".

  bool realloc(char* p, int osz, int nsz);
  // Requires: "p" was allocated by this allocator and has size "osz".
  // Effects: Returns true, if it suceeds in converting "p" into a block
  // of size "nsz" (allocating more space or freeing it as necessary).
  // Otherwise, returns false and does nothing.

  void debug_print();
  // Effects: Prints debug information

private:
  struct Chunk
  {
    char* next; // Pointer to beginning of free area
    char* max; // Pointer to end of free area
    Long nb; // Reference count (number of blocks allocated in this)
             // plus one when this is the current block.
    char data[1];
    // Followed by extra data

    void debug_print()
    {
      LOG_DEBUG << "Chunk " << uintptr_t(this) << ": next=" << next
                << " max=" << max << " nb=" << (int)nb << std::endl;
    }
  };

  class SpinLock
  {
    std::atomic_flag locked = ATOMIC_FLAG_INIT;

  public:
    void lock()
    {
      while (locked.test_and_set(std::memory_order_acquire))
      {
        ;
      }
    }
    void unlock()
    {
      locked.clear(std::memory_order_release);
    }

    class SpinLockRAII
    {
    public:
      SpinLockRAII(SpinLock& lock) : _lock(lock)
      {
        lock.lock();
      }
      ~SpinLockRAII()
      {
        _lock.unlock();
      }

    private:
      SpinLock& _lock;
    };
  };

  Chunk* alloc_chunk();
  // Effects: Allocates a new (current) chunk and initializes it

  void free_chunk(Chunk* p);
  // Effects: Frees the chunk pointed to by "p"

  Chunk* cur; // current chunk
  int chunk_size; // size of chunk

  char* chunks; // array of "chunk_size" chunks
  int max_num_chunks; // maximum number of chunks in "chunks"
  int num_chunks; // number of chunks already allocated in "chunks".

  Chunk* free_chunks; // list of free chunks
  SpinLock spin_lock;
};

inline char* Log_allocator::malloc(int sz)
{
  PBFT_ASSERT(sz > 0 && sz < chunk_size, "Invalid argument");
  PBFT_ASSERT(ALIGNED_SIZE(sz), "Invalid argument");

#ifdef USE_STD_MALLOC
  return (char*)::malloc(sz);
#else
  char* next;
  SpinLock::SpinLockRAII lock(spin_lock);

  while (1)
  {
    next = cur->next;
    if (next + sz < cur->max)
    {
      // There is space in the current chunk
      cur->next = next + sz;
      cur->nb++;
#  ifdef DEBUG_ALLOC
      bzero(next, sz);
#  endif
      return next;
    }

    // Current chunk is full. Allocate a new one.
    if (cur->nb == 1)
    {
      // Can reuse current block.
      cur->next = cur->data;
    }
    else
    {
      // Allocate a new chunk
      cur->nb--; // To allow old chunk to be deallocated
      cur = alloc_chunk();
      if (cur == nullptr)
      {
        return nullptr;
      }
    }
  }
#endif
}

inline void Log_allocator::free_chunk(Chunk* p)
{
  p->next = (char*)free_chunks;
  free_chunks = p;
}

#ifdef DEBUG_ALLOC
const long Log_allocator_magic = 0x386592a7386592a7;
#endif

inline void Log_allocator::free(char* p, int sz)
{
  PBFT_ASSERT(ALIGNED_SIZE(sz), "Invalid argument");
  PBFT_ASSERT(ALIGNED(p), "Invalid argument");

#ifdef USE_STD_MALLOC
  ::free(p);
  return;
#else
  SpinLock::SpinLockRAII lock(spin_lock);
  Chunk* pc = (Chunk*)((uintptr_t)p & ~((uintptr_t)chunk_size - 1));

#  ifdef DEBUG_ALLOC
  long* pi = (long*)p;
  for (int i = 0; i < sz / sizeof(Log_allocator_magic); i++)
  {
    if (*(pi + i) == Log_allocator_magic)
    {
      LOG_FAIL << "WARNING: Storage possibly freed twice" << std::endl;
#    ifndef INSIDE_ENCLAVE
      logger::print_stacktrace();
#    endif
    }
    *(pi + i) = Log_allocator_magic;
  }
#  endif

  if (pc == cur && p + sz == cur->next)
  {
    // Adjust pointer to reuse space in current chunk
    cur->next -= sz;
  }

  pc->nb--;
  if (pc->nb == 0)
  {
    // The chunk can be freed
    PBFT_ASSERT(pc != cur, "Invalid state");
    free_chunk(pc);
  }
#endif
}

inline bool Log_allocator::realloc(char* p, int osz, int nsz)
{
#ifdef USE_STD_MALLOC
  return false;
#else
  SpinLock::SpinLockRAII lock(spin_lock);
  Chunk* pc = (Chunk*)((uintptr_t)p & ~((uintptr_t)chunk_size - 1));
  if (pc == cur && p + osz == cur->next)
  {
    int diff = nsz - osz;
    if (cur->next + diff < cur->max)
    {
      cur->next += diff;
      return true;
    }
  }
  return false;
#endif
}
