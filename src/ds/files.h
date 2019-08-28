// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef _WIN32
#  define _CRT_SECURE_NO_WARNINGS
#endif

#include "tls/cert.h"

#include <cstring>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <glob.h>
#endif

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
   * @brief Tries to glob files and parse them as x509 certificates
   *
   * @param path the path to glob
   * @param optional determines behaviour in the case where that no file matches
   * the glob patter. If true, an empty vector is returned. If false, the
   * process exits
   * @return vector<vector<uint8_t>> vector of certificates
   */
  std::vector<std::vector<uint8_t>> slurp_certs(
    const std::string& path, bool optional = false)
  {
    std::vector<std::vector<uint8_t>> certs;

#ifdef _WIN32
    WIN32_FIND_DATA fd;
    auto h = FindFirstFile(path.c_str(), &fd);

    if (h == INVALID_HANDLE_VALUE)
    {
      if (optional)
      {
        return {};
      }
      else
      {
        std::cerr << "Failed to search for cert pattern." << std::endl;
        exit(-1);
      }
    }
#else
    glob_t g;
    size_t i = 0;

    if (glob(path.c_str(), GLOB_ERR, NULL, &g) || g.gl_pathc < 1)
    {
      if (optional)
      {
        return {};
      }
      else
      {
        std::cerr << "Failed to search for cert pattern." << std::endl;
        exit(-1);
      }
    }
#endif

    do
    {
      mbedtls_x509_crt cert;
      mbedtls_x509_crt_init(&cert);
      std::string fn;
#ifdef _WIN32
      fn = fd.cFileName;
#else
      fn = g.gl_pathv[i];
#endif

      auto raw = slurp(fn);

      if (mbedtls_x509_crt_parse(&cert, raw.data(), raw.size()))
      {
        std::cerr << "Failed to parse certificate " << fn << std::endl;
        exit(-1);
      }

      certs.push_back({cert.raw.p, cert.raw.p + cert.raw.len});
      mbedtls_x509_crt_free(&cert);
    } while (
#ifdef _WIN32
      FindNextFile(h, &fd)
#else
      ++i < g.gl_pathc
#endif
    );

#ifdef _WIN32
    FindClose(h);
#else
    globfree(&g);
#endif

    return certs;
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
}
