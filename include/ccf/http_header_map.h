// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <map>
#include <string>

namespace http
{
  using HeaderMap = std::map<std::string, std::string, std::less<>>;
  using HeaderKeyValue = HeaderMap::value_type;
}
