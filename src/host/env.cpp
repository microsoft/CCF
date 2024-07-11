// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "host/env.h"

#include <filesystem>
#include <string>
#include <vector>

namespace ccf::env
{
  std::string expand_envvar(const std::string& str)
  {
    if (str.empty() || str[0] != '$')
    {
      return str;
    }

    char* e = std::getenv(str.c_str() + 1);
    if (e == nullptr)
    {
      return str;
    }
    else
    {
      return std::string(e);
    }
  }

  std::string expand_envvars_in_path(const std::string& str)
  {
    std::filesystem::path path(str);

    if (path.empty())
    {
      return str;
    }

    std::vector<std::filesystem::path> elements;
    auto it = path.begin();
    if (path.has_root_directory())
    {
      ++it;
      elements.push_back(path.root_directory());
    }

    while (it != path.end())
    {
      elements.push_back(expand_envvar(*it++));
    }

    std::filesystem::path resolved;
    for (auto& element : elements)
    {
      resolved /= element;
    }

    return resolved.lexically_normal().string();
  }
}
