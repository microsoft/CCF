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

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <fmt/ostream.h>

namespace files
{
  namespace fs = std::filesystem;

  /**
   * @brief Checks if a path exists
   *
   * @param file file to check
   * @return true if the file exists.
   */
  static bool exists(const std::string& file)
  {
    std::ifstream f(file.c_str());
    return f.good();
  }

  /**
   * @brief Tries to read a file as byte vector.
   *
   * @param file the path
   * @param optional determines behaviour in the case where the file does not
   * exist. If true, an empty vector is returned. If false, the process exits
   * @return vector<uint8_t> the file contents as bytes.
   */
  static std::vector<uint8_t> slurp(
    const std::string& file, bool optional = false)
  {
    std::ifstream f(file, std::ios::binary | std::ios::ate);

    if (!f)
    {
      if (optional)
      {
        return {};
      }
      std::cerr << "Could not open file " << file << std::endl;
      exit(-1); // NOLINT(concurrency-mt-unsafe)
    }

    auto size = f.tellg();
    f.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(size);
    f.read(reinterpret_cast<char*>(data.data()), size);

    if (!optional && !f)
    {
      std::cerr << "Could not read file " << file << std::endl;
      exit(-1); // NOLINT(concurrency-mt-unsafe)
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
  static std::string slurp_string(
    const std::string& file, bool optional = false)
  {
    auto v = slurp(file, optional);
    return {v.begin(), v.end()};
  }

  static std::optional<std::string> try_slurp_string(const std::string& file)
  {
    if (!fs::exists(file))
    {
      return std::nullopt;
    }
    return files::slurp_string(file);
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
  static nlohmann::json slurp_json(
    const std::string& file, bool optional = false)
  {
    auto v = slurp(file, optional);
    if (v.empty())
    {
      return {};
    }

    return nlohmann::json::parse(v.begin(), v.end());
  }

  /**
   * @brief Writes the content of a vector to a file
   *
   * @param data vector to write
   * @param file the path
   */
  static void dump(const std::vector<uint8_t>& data, const std::string& file)
  {
    using namespace std;
    ofstream f(file, ios::binary | ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (!f)
    {
      throw logic_error("Failed to write to file: " + file);
    }
  }

  /**
   * @brief Writes the content of a string to a file
   *
   * @param data string to write
   * @param file the path
   */
  static void dump(const std::string& data, const std::string& file)
  {
    dump(std::vector<uint8_t>(data.begin(), data.end()), file);
  }

  static void rename(const fs::path& src, const fs::path& dst)
  {
    std::error_code ec;
    fs::rename(src, dst, ec);
    if (ec)
    {
      throw std::logic_error(fmt::format(
        "Could not rename file {} to {}: {}",
        src.string(),
        dst.string(),
        ec.message()));
    }
  }

  static void create_directory(const fs::path& dir)
  {
    std::error_code ec;
    fs::create_directory(dir, ec);
    if (ec && ec != std::errc::file_exists)
    {
      throw std::logic_error(fmt::format(
        "Could not create directory {}: {}", dir.string(), ec.message()));
    }
  }
}
