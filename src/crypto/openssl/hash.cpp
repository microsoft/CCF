// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/hash.h"

#include <limits>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdexcept>

namespace ccf::crypto
{
  namespace OpenSSL
  {
    std::vector<uint8_t> hkdf(
      MDType md_type,
      size_t length,
      const std::span<const uint8_t>& ikm,
      const std::span<const uint8_t>& salt,
      const std::span<const uint8_t>& info)
    {
      const auto* md = get_md_type(md_type);
      EVP_PKEY_CTX* pctx = nullptr;
      std::vector<uint8_t> r(length);
      pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
      CHECK1(EVP_PKEY_derive_init(pctx));
      CHECK1(EVP_PKEY_CTX_set_hkdf_md(pctx, md));
      if (salt.size() > std::numeric_limits<int>::max())
      {
        throw std::logic_error("Salt size is too large");
      }
      int salt_size = static_cast<int>(salt.size());
      CHECK1(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt_size));
      if (ikm.size() > std::numeric_limits<int>::max())
      {
        throw std::logic_error("IKM size is too large");
      }
      int ikm_size = static_cast<int>(ikm.size());
      CHECK1(EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm_size));
      if (info.size() > std::numeric_limits<int>::max())
      {
        throw std::logic_error("Info size is too large");
      }
      int info_size = static_cast<int>(info.size());
      CHECK1(EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info_size));
      size_t outlen = length;
      CHECK1(EVP_PKEY_derive(pctx, r.data(), &outlen));
      EVP_PKEY_CTX_free(pctx);
      r.resize(outlen);
      return r;
    }
  }

  using namespace OpenSSL;

  static thread_local EVP_MD_CTX* mdctx = nullptr;
  static thread_local EVP_MD_CTX* basectx = nullptr;

  void openssl_sha256_init()
  {
    if (mdctx != nullptr || basectx != nullptr)
    {
      return; // Already initialised
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr)
    {
      throw std::logic_error("openssl_sha256_init: failed to create mdctx");
    }
    basectx = EVP_MD_CTX_new();
    if (basectx == nullptr)
    {
      mdctx = nullptr;
      throw std::logic_error("openssl_sha256_init: failed to create basectx");
    }
    if (EVP_DigestInit_ex(basectx, EVP_sha256(), nullptr) != 1)
    {
      mdctx = nullptr;
      basectx = nullptr;
      throw std::logic_error("EVP_DigestInit_ex failed");
    }
  }

  void openssl_sha256_shutdown()
  {
    if (mdctx != nullptr)
    {
      EVP_MD_CTX_free(mdctx);
      mdctx = nullptr;
    }
    if (basectx != nullptr)
    {
      EVP_MD_CTX_free(basectx);
      basectx = nullptr;
    }
  }

  void openssl_sha256(const std::span<const uint8_t>& data, uint8_t* h)
  {
    // EVP_Digest calls are notoriously slow with OpenSSL 3.x (see
    // https://github.com/openssl/openssl/issues/19612). Instead, we skip the
    // calls to EVP_DigestInit_ex() by keeping 2 static thread-local contexts
    // and reusing them between calls. This is about 2x faster than EVP_Digest
    // for 128-byte buffers.

    if (mdctx == nullptr || basectx == nullptr)
    {
      throw std::logic_error(
        "openssl_sha256 failed: openssl_sha256_init should be called first");
    }

    int rc = EVP_MD_CTX_copy_ex(mdctx, basectx);
    if (rc != 1)
    {
      throw std::logic_error(fmt::format("EVP_MD_CTX_copy_ex failed: {}", rc));
    }
    rc = EVP_DigestUpdate(mdctx, data.data(), data.size());
    if (rc != 1)
    {
      throw std::logic_error(fmt::format("EVP_DigestUpdate failed: {}", rc));
    }
    rc = EVP_DigestFinal_ex(mdctx, h, nullptr);
    if (rc != 1)
    {
      throw std::logic_error(fmt::format("EVP_DigestFinal_ex failed: {}", rc));
    }
  }

  ISha256OpenSSL::ISha256OpenSSL() : ctx(EVP_MD_CTX_new())
  {
    if (ctx == nullptr)
    {
      throw std::logic_error("ISha256OpenSSL: failed to create ctx");
    }
    const EVP_MD* md = EVP_sha256();
    int rc = EVP_DigestInit(ctx, md);
    if (rc != 1)
    {
      throw std::logic_error(fmt::format("EVP_DigestInit failed: {}", rc));
    }
  }

  ISha256OpenSSL::~ISha256OpenSSL()
  {
    if (ctx != nullptr)
    {
      EVP_MD_CTX_free(ctx);
    }
  }

  void ISha256OpenSSL::update_hash(std::span<const uint8_t> data)
  {
    if (ctx == nullptr)
    {
      throw std::logic_error("Attempting to use hash after it was finalised");
    }

    int rc = EVP_DigestUpdate(ctx, data.data(), data.size());
    if (rc != 1)
    {
      throw std::logic_error(fmt::format("EVP_DigestUpdate failed: {}", rc));
    }
  }

  Sha256Hash ISha256OpenSSL::finalise()
  {
    if (ctx == nullptr)
    {
      throw std::logic_error("Attempting to use hash after it was finalised");
    }

    Sha256Hash r;
    int rc = EVP_DigestFinal(ctx, r.h.data(), nullptr);
    if (rc != 1)
    {
      EVP_MD_CTX_free(ctx);
      throw std::logic_error(fmt::format("EVP_DigestFinal failed: {}", rc));
    }
    EVP_MD_CTX_free(ctx);
    ctx = nullptr;
    return r;
  }
}