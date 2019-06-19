// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// To avoid repeating this macro everywhere CCF wants to use libfmt, we do
// it once here
#define FMT_HEADER_ONLY
#include "format.h"

// This allows types which have operator<< defined to be used in format calls
#include "ostream.h"
