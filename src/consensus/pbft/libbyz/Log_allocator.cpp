// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#ifndef INSIDE_ENCLAVE
#  include <sys/mman.h>
#endif

#include "Log_allocator.h"
#include "ds/logger.h"

#ifndef MAP_VARIABLE
#  define MAP_VARIABLE 0x00
#endif

Log_allocator::Log_allocator(int csz, int nc)
{
  chunk_size = csz;
  max_num_chunks = nc;
  num_chunks = nc;
  free_chunks = 0;
  chunks = 0;
  cur = alloc_chunk();
}

void Log_allocator::should_use_malloc(bool _use_malloc)
{
  use_malloc = _use_malloc;
}

bool Log_allocator::use_malloc =
#ifdef USE_STD_MALLOC
  true
#else
  false
#endif
  ;

Log_allocator::~Log_allocator()
{
  ::free(chunks);
}

Log_allocator::Chunk* Log_allocator::alloc_chunk()
{
  Chunk* ret;
  if (free_chunks != 0)
  {
    // First try to allocate from free list
    ret = free_chunks;
    free_chunks = (Chunk*)(free_chunks->next);
  }
  else if (num_chunks < max_num_chunks)
  {
    // Try to allocate from the current chunks array.
    ret = (Chunk*)(chunks + chunk_size * num_chunks);
    num_chunks++;
  }
  else
  {
    // Allocate a new chunks array. The array must be chunk_size-aligned.
    posix_memalign((void**)&chunks, chunk_size, chunk_size * max_num_chunks);
    ret = (Chunk*)chunks;
    num_chunks = 1;
  }

  if (ret != nullptr)
  {
    ret->next = ret->data;
    ret->max = ret->next + (chunk_size - sizeof(Chunk));
    ret->nb = 1; // this is the current chunk
  }

  return ret;
}

void Log_allocator::debug_print()
{
  SpinLock::SpinLockRAII lock(spin_lock);
  LOG_INFO << "Free space: current chunk" << std::endl;
  if (cur)
  {
    cur->debug_print();
  }
  else
  {
    LOG_INFO << "(null)" << std::endl;
  }

  LOG_INFO << "Free chunks:" << std::endl;
  for (Chunk* p = free_chunks; p != 0; p = (Chunk*)(p->next))
  {
    p->debug_print();
  }

  LOG_INFO << "All chunks:";
  for (int i = 0; i < max_num_chunks; i++)
  {
    Chunk* p = (Chunk*)(chunks + chunk_size * i);
    p->debug_print();
  }
}
