// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"

#include <array>
#include <span>
#include <type_traits>

namespace ccf::pal
{
  template <size_t N>
  struct AttestationReportData
  {
    std::array<uint8_t, N> report_data;

    static size_t size()
    {
      return N;
    }

    AttestationReportData() = default;
    AttestationReportData(std::span<const uint8_t> data)
    {
      if (data.size() != size())
      {
        throw std::logic_error(fmt::format(
          "Cannot initialise AttestationReportData with data of size {}, "
          "expected {}",
          data.size(),
          size()));
      }

      std::copy(data.data(), data.data() + data.size(), report_data.data());
    }
  };

  struct PlatformAttestationReportData
  {
    std::vector<uint8_t> data;

    PlatformAttestationReportData() = default;

    PlatformAttestationReportData(const crypto::Sha256Hash& hash) :
      data(hash.h.begin(), hash.h.end())
    {}

    template <size_t N>
    PlatformAttestationReportData(const AttestationReportData<N>& report_data) :
      data(report_data.report_data.begin(), report_data.report_data.end())
    {}

    crypto::Sha256Hash to_sha256_hash() const
    {
      std::span<const uint8_t, crypto::Sha256Hash::SIZE> s(
        data.data(), crypto::Sha256Hash::SIZE);
      return crypto::Sha256Hash::from_span(s);
    }
  };

  // SGX
  static constexpr size_t sgx_attestation_report_data_size = 32;
  using SgxAttestationReportData =
    AttestationReportData<sgx_attestation_measurement_size>;

  // SNP
  static constexpr size_t snp_attestation_report_data_size = 64;
  using SnpAttestationReportData =
    AttestationReportData<snp_attestation_report_data_size>;

}