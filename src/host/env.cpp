// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "host/env.h"

#include <cstdlib>
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

    const auto name = str.substr(1);
    char* value = std::getenv(name.c_str()); // NOLINT(concurrency-mt-unsafe)
    if (value == nullptr)
    {
      return str;
    }

    return {value};
  }

  std::string expand_envvars_in_path(const std::string& str)
  {
    const std::filesystem::path path(str);

    if (path.empty())
    {
      return str;
    }

    std::vector<std::filesystem::path> elements;
    auto path_element = path.begin();
    if (path.has_root_directory())
    {
      ++path_element;
      elements.push_back(path.root_directory());
    }

    while (path_element != path.end())
    {
      elements.emplace_back(expand_envvar(*path_element++));
    }

    std::filesystem::path resolved;
    for (auto& element : elements)
    {
      resolved /= element;
    }

    return resolved.lexically_normal().string();
  }
}
