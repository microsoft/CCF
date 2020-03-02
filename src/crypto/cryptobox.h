// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

extern "C"
{
#include <evercrypt/EverCrypt_Curve25519.h>
#include <evercrypt/Hacl_NaCl.h>
}

#include <fmt/format_header_only.h>
#include <vector>

namespace crypto
{
  class BoxKey
  {
  public:
    static constexpr size_t KEY_SIZE = 32;

    static std::vector<uint8_t> public_from_private(
      std::vector<uint8_t>& private_key)
    {
      if (private_key.size() != KEY_SIZE)
      {
        throw std::logic_error(fmt::format(
          "Private key size {} is not {}", private_key.size(), KEY_SIZE));
      }

      std::vector<uint8_t> public_key(KEY_SIZE);
      EverCrypt_Curve25519_secret_to_public(
        public_key.data(), private_key.data());

      return public_key;
    }
  };

  class Box
  {
  public:
    static constexpr size_t NONCE_SIZE = 24;
    static constexpr size_t CIPHER_EXTRA_SIZE = 16;

    static std::vector<uint8_t> create(
      std::vector<uint8_t>& plain,
      std::vector<uint8_t>& nonce,
      std::vector<uint8_t>& recipient_public,
      std::vector<uint8_t>& sender_private)
    {
      if (nonce.size() != NONCE_SIZE)
      {
        throw std::logic_error(
          fmt::format("Box create(): nonce size is not {}", NONCE_SIZE));
      }
      std::vector<uint8_t> cipher(plain.size() + CIPHER_EXTRA_SIZE);

      if (
        Hacl_NaCl_crypto_box_easy(
          cipher.data(),
          plain.data(),
          plain.size(),
          nonce.data(),
          recipient_public.data(),
          sender_private.data()) != 0)
      {
        throw std::logic_error("Box create(): encryption failed");
      }

      return cipher;
    };

    static std::vector<uint8_t> open(
      const std::vector<uint8_t>& cipher,
      std::vector<uint8_t>& nonce,
      const std::vector<uint8_t>& sender_public,
      const std::vector<uint8_t>& recipient_private)
    {
      if (cipher.size() < CIPHER_EXTRA_SIZE)
      {
        throw std::logic_error(fmt::format(
          "Box open(): cipher to open should be of size >= {}",
          CIPHER_EXTRA_SIZE));
      }

      if (nonce.size() != NONCE_SIZE)
      {
        throw std::logic_error(
          fmt::format("Box open(): nonce size is not {}", NONCE_SIZE));
      }

      std::vector<uint8_t> plain(cipher.size() - CIPHER_EXTRA_SIZE);

      if (
        Hacl_NaCl_crypto_box_open_easy(
          plain.data(),
          (uint8_t*)cipher.data(),
          cipher.size(),
          nonce.data(),
          (uint8_t*)sender_public.data(),
          (uint8_t*)recipient_private.data()) != 0)
      {
        throw std::logic_error("Box open(): decryption failed");
      }
      return plain;
    }
  };
}