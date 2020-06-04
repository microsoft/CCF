// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "data.h"

#include "ds/ccf_assert.h"
#include "message_tags.h"

#include <string.h>

Data::Data(size_t i, Seqno lm, char* data) : Message(Data_tag, sizeof(Data_rep))
{
  rep().index = i;
  rep().lm = lm;
  memcpy(rep().data, data, Block_size);
}
