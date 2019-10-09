// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/files.h"
#include "tls/cert.h"

#include <cstring>
#include <fstream>
#include <glob.h>
#include <iostream>
#include <sstream>
#include <vector>

namespace files
{
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

    do
    {
      mbedtls_x509_crt cert;
      mbedtls_x509_crt_init(&cert);
      std::string fn;
      fn = g.gl_pathv[i];

      auto raw = slurp(fn);

      if (mbedtls_x509_crt_parse(&cert, raw.data(), raw.size()))
      {
        std::cerr << "Failed to parse certificate " << fn << std::endl;
        exit(-1);
      }

      certs.push_back({cert.raw.p, cert.raw.p + cert.raw.len});
      mbedtls_x509_crt_free(&cert);
    } while (++i < g.gl_pathc);

    globfree(&g);

    return certs;
  }

}