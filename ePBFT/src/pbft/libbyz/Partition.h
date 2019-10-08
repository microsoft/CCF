
#pragma once

#include "libbyz.h"

//
// Definitions for hierarchical state partitions.
//

const size_t PChildren = 128; // Number of children for non-leaf partitions.
const size_t PLevels = 4; // Number of levels in partition tree.

// Number of siblings at each level.
const size_t PSize[] = {1, PChildren, PChildren, PChildren};

// Number of partitions at each level.
const size_t PLevelSize[] = {
  1, PChildren, PChildren* PChildren, PChildren* PChildren* PChildren};

// Number of blocks in a partition at each level
const size_t PBlocks[] = {
  PChildren * PChildren * PChildren, PChildren* PChildren, PChildren, 1};
