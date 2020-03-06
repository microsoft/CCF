// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstring>
#include <fstream>
#include <glob.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace files
{
  /**
   * @brief Tries to read a file as byte vector.
   *
   * @param file the path
   * @param optional determines behaviour in the case where the file does not
   * exist. If true, an empty vector is returned. If false, the process exits
   * @return vector<uint8_t> the file contents as bytes.
   */
  std::vector<uint8_t> slurp(const std::string& file, bool optional = false)
  {
    using namespace std;
    ifstream f(file, ios::binary | ios::ate);

    if (!f)
    {
      if (optional)
      {
        return {};
      }
      else
      {
        std::cerr << "Could not open file " << file << std::endl;
        exit(-1);
      }
    }

    auto size = f.tellg();
    f.seekg(0, ios::beg);

    vector<uint8_t> data(size);
    f.read((char*)data.data(), size);

    if (!optional && !f)
    {
      std::cerr << "Could not read file " << file << std::endl;
      exit(-1);
    }
    return data;
  }

  /**
   * @brief Tries to read a file as string
   *
   * @param file the path
   * @param optional determines behaviour in the case where the file does not
   * exist. If true, an empty vector is returned. If false, the process exits
   * @return std::string the file contents as a string.
   */
  std::string slurp_string(const std::string& file, bool optional = false)
  {
    auto v = slurp(file, optional);
    return {v.begin(), v.end()};
  }

  /**
   * @brief Tries to read a file as JSON.
   *
   * @param file the path
   * @param optional determines behaviour in the case where the file does not
   * exist. If true, an empty JSON object is returned. If false, the process
   * exits
   * @return nlohmann::json JSON object containing the parsed file
   */
  nlohmann::json slurp_json(const std::string& file, bool optional = false)
  {
    auto v = slurp(file, optional);
    if (v.size() == 0)
      return nlohmann::json();

    return nlohmann::json::parse(v.begin(), v.end());
  }

  /**
   * @brief Writes the content of a vector to a file
   *
   * @param data vector to write
   * @param file the path
   */
  void dump(const std::vector<uint8_t>& data, const std::string& file)
  {
    using namespace std;
    ofstream f(file, ios::binary | ios::trunc);
    f.write((char*)data.data(), data.size());
    if (!f)
      throw logic_error("Failed to write to file: " + file);
  }

  /**
   * @brief Writes the content of a string to a file
   *
   * @param data string to write
   * @param file the path
   */
  void dump(const std::string& data, const std::string& file)
  {
    return dump(std::vector<uint8_t>(data.begin(), data.end()), file);
  }
}
