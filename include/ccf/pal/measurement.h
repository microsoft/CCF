// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/hex.h"
#include "ccf/kv/serialisers/blit_serialiser.h"

#include <array>
#include <span>
#include <type_traits>

namespace ccf::pal
{
  template <size_t N>
  struct AttestationMeasurement
  {
    std::array<uint8_t, N> measurement;

    static size_t size()
    {
      return N;
    }

    std::string hex_str() const
    {
      return ds::to_hex(measurement);
    }

    AttestationMeasurement() = default;
    AttestationMeasurement(const std::string& hex_str)
    {
      ds::from_hex(hex_str, measurement);
    }
    AttestationMeasurement(std::span<const uint8_t> data)
    {
      if (data.size() != size())
      {
        throw std::logic_error(fmt::format(
          "Cannot initialise AttestationMeasurement with data of size {}, "
          "expected {}",
          data.size(),
          size()));
      }

      std::copy(data.data(), data.data() + data.size(), measurement.data());
    }
  };

  template <typename>
  struct is_attestation_measurement : std::false_type
  {};

  template <size_t N>
  struct is_attestation_measurement<AttestationMeasurement<N>> : std::true_type
  {};

  template <size_t N>
  inline void to_json(
    nlohmann::json& j, const AttestationMeasurement<N>& measurement)
  {
    j = measurement.hex_str();
  }

  template <size_t N>
  inline void from_json(
    const nlohmann::json& j, AttestationMeasurement<N>& measurement)
  {
    if (j.is_string())
    {
      measurement = j.get<std::string>();
    }
    else
    {
      throw JsonParseError(fmt::format(
        "Attestation measurement should be hex-encoded string: {}", j.dump()));
    }
  }

  template <size_t N>
  inline void fill_json_schema(
    nlohmann::json& schema, const AttestationMeasurement<N>*)
  {
    schema["type"] = "string";

    // According to the spec, "format is an open value, so you can use any
    // formats, even not those defined by the OpenAPI Specification"
    // https://swagger.io/docs/specification/data-models/data-types/#format
    schema["format"] = "hex";
    schema["pattern"] =
      fmt::format("^[a-f0-9]{}$", AttestationMeasurement<N>::size() * 2);
  }

  // SGX
  static constexpr size_t sgx_attestation_measurement_size = 32;
  using SgxAttestationMeasurement =
    AttestationMeasurement<sgx_attestation_measurement_size>;

  inline std::string schema_name(const SgxAttestationMeasurement*)
  {
    return "SgxAttestationMeasurement";
  }

  // SNP
  static constexpr size_t snp_attestation_measurement_size = 48;
  using SnpAttestationMeasurement =
    AttestationMeasurement<snp_attestation_measurement_size>;

  inline std::string schema_name(const SnpAttestationMeasurement*)
  {
    return "SnpAttestationMeasurement";
  }

}

namespace kv::serialisers
{
  template <size_t N>
  struct BlitSerialiser<ccf::pal::AttestationMeasurement<N>>
  {
    static SerialisedEntry to_serialised(
      const ccf::pal::AttestationMeasurement<N>& measurement)
    {
      auto hex_str = measurement.hex_str();
      return SerialisedEntry(hex_str.begin(), hex_str.end());
    }

    static ccf::pal::AttestationMeasurement<N> from_serialised(
      const SerialisedEntry& data)
    {
      ccf::pal::AttestationMeasurement<N> ret;
      ds::from_hex(std::string(data.data(), data.end()), ret.measurement);
      return ret;
    }
  };
}