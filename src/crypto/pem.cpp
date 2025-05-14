// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/crypto/pem.h"

namespace ccf::crypto
{
  void Pem::check_pem_format()
  {
    if (s.find("-----BEGIN") == std::string::npos)
    {
      throw std::runtime_error(
        fmt::format("PEM constructed with non-PEM data: {}", s));
    }
  }

  Pem::Pem(std::string pem_string) : s(std::move(pem_string))
  {
    check_pem_format();
  }

  Pem::Pem(const uint8_t* data, size_t size)
  {
    if (size == 0)
    {
      throw std::logic_error("Got PEM of size 0");
    }

    s.assign(
      reinterpret_cast<const char*>(
        data), // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
      size);
    if (s.back() == '\0')
    {
      s.pop_back();
    }

    check_pem_format();
  }

  std::vector<ccf::crypto::Pem> split_x509_cert_bundle(
    const std::string_view& pem)
  {
    std::string separator("-----END CERTIFICATE-----");
    std::vector<ccf::crypto::Pem> pems;
    size_t separator_end = 0;
    auto next_separator_start = pem.find(separator);
    while (next_separator_start != std::string_view::npos)
    {
      // Trim whitespace between certificates
      while (separator_end < next_separator_start &&
             (std::isspace(pem[separator_end]) != 0))
      {
        ++separator_end;
      }
      pems.emplace_back(std::string(pem.substr(
        separator_end,
        (next_separator_start - separator_end) + separator.size())));
      separator_end = next_separator_start + separator.size();
      next_separator_start = pem.find(separator, separator_end);
    }
    return pems;
  }
}