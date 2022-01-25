// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

struct ccf_mallinfo_t
{
  size_t max_total_heap_size = 0;
  size_t current_allocated_heap_size = 0;
  size_t peak_allocated_heap_size = 0;
};

bool ccf_allocator_mallinfo(ccf_mallinfo_t& info);
