// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "network_mock.h"

INetwork* Create_Mock_Network()
{
  return new MockNetwork();
}
