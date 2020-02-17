// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "libbyz.h"

//
// Definitions for hierarchical state partitions.
//

const size_t PChildren = 8; // Number of children for non-leaf partitions.
const size_t PLevels = 2; // Number of levels in partition tree.

// Number of siblings at each level.
const size_t PSize[] = {1, PChildren, PChildren, PChildren};

// Number of partitions at each level.
const size_t PLevelSize[] = {
  1, PChildren, PChildren* PChildren, PChildren* PChildren* PChildren};

// Number of blocks in a partition at each level
const size_t PBlocks[] = {
  PChildren * PChildren * PChildren, PChildren* PChildren, PChildren, 1};
