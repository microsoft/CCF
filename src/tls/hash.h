// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "curve.h"

#include <vector>

namespace tls
{
  using HashBytes = std::vector<uint8_t>;

  template <size_t T>
  using HashFixedSize = std::array<uint8_t, T>;

  /**
   * Hash the given data, with the specified digest algorithm
   *
   * @return 0 on success
   */
  inline int do_hash(
    const uint8_t* data_ptr,
    size_t data_size,
    HashBytes& o_hash,
    mbedtls_md_type_t md_type)
  {
    const auto md_info = mbedtls_md_info_from_type(md_type);
    const auto hash_size = mbedtls_md_get_size(md_info);

    if (o_hash.size() < hash_size)
    {
      o_hash.resize(hash_size);
    }

    return mbedtls_md(md_info, data_ptr, data_size, o_hash.data());
  }

  /**
   * Hash the given data, with the specified digest algorithm
   *
   * @return 0 on success
   */
  template <size_t T>
  inline int do_hash(
    const uint8_t* data_ptr,
    size_t data_size,
    HashFixedSize<T>& o_hash,
    mbedtls_md_type_t md_type)
  {
    const auto md_info = mbedtls_md_info_from_type(md_type);
    const auto hash_size = mbedtls_md_get_size(md_info);

    if (o_hash.size() != hash_size)
    {
      return -1;
    }

    return mbedtls_md(md_info, data_ptr, data_size, o_hash.data());
  }

  /**
   * Hash the given data, with an algorithm chosen by key type
   *
   * @return 0 on success
   */
  inline int do_hash(
    const mbedtls_pk_context& ctx,
    const uint8_t* data_ptr,
    size_t data_size,
    HashBytes& o_hash,
    mbedtls_md_type_t md_type_ = MBEDTLS_MD_NONE)
  {
    const auto ec = get_ec_from_context(ctx);
    mbedtls_md_type_t md_type;
    if (md_type_ != MBEDTLS_MD_NONE)
    {
      md_type = md_type_;
    }
    else
    {
      md_type = get_md_for_ec(ec);
    }
    const auto md_info = mbedtls_md_info_from_type(md_type);
    const auto hash_size = mbedtls_md_get_size(md_info);

    if (o_hash.size() < hash_size)
      o_hash.resize(hash_size);

    return mbedtls_md(md_info, data_ptr, data_size, o_hash.data());
  }

}