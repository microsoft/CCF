// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/hex.h"
#include "ccf/kv/serialisers/blit_serialiser.h"

#include <array>

namespace ccf::pal
{
  // TODO:
  // 1. Same for SNP
  // 2. Remove CodeDigest altogether?
  // 3. Same for report data?

  static constexpr size_t sgx_attestation_measurement_size = 32;
  static constexpr size_t snp_attestation_measurement_size = 48;

  template <size_t N>
  struct AttestationMeasurement
  {
    std::array<uint8_t, N> data;

    static size_t size()
    {
      return N;
    }

    AttestationMeasurement() = default;
  };

  template <size_t N>
  inline void to_json(
    nlohmann::json& j, const AttestationMeasurement<N>& measurement)
  {
    j = ds::to_hex(measurement.data);
  }

  template <size_t N>
  inline void from_json(
    const nlohmann::json& j, AttestationMeasurement<N>& measurement)
  {
    if (j.is_string())
    {
      auto value = j.get<std::string>();
      ds::from_hex(value, measurement.data);
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

  using SgxAttestationMeasurement =
    AttestationMeasurement<sgx_attestation_measurement_size>;

  inline std::string schema_name(const SgxAttestationMeasurement*)
  {
    return "SgxAttestationMeasurement";
  }

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
      auto hex_str = ds::to_hex(measurement.data);
      return SerialisedEntry(hex_str.begin(), hex_str.end());
    }

    static ccf::pal::AttestationMeasurement<N> from_serialised(
      const SerialisedEntry& data)
    {
      ccf::pal::AttestationMeasurement<N> ret;
      ds::from_hex(std::string(data.data(), data.end()), ret.data);
      return ret;
    }
  };
}