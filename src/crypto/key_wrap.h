// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "rsa_key_pair.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace crypto
{
  /// PKCS11 2.1.8 CKM_RSA_PKCS_OAEP wrap
  /// @param wrapping_key The wrapping (encryption) key
  /// @param unwrapped The unwrapped key to be wrapped
  /// @param label Optional label
  /// @return Wrapped key
  std::vector<uint8_t> ckm_rsa_pkcs_oaep_wrap(
    RSAPublicKeyPtr wrapping_key,
    const std::vector<uint8_t>& unwrapped,
    const std::vector<uint8_t>& label = {});

  /// PKCS11 2.1.8 CKM_RSA_PKCS_OAEP
  /// @param wrapping_key The wrapping (encryption) key
  /// @param unwrapped The unwrapped key to be wrapped
  /// @param label Optional label
  /// @return Wrapped key
  std::vector<uint8_t> ckm_rsa_pkcs_oaep_wrap(
    const Pem& wrapping_key,
    const std::vector<uint8_t>& unwrapped,
    const std::vector<uint8_t>& label = {});

  /// PKCS11 2.1.8 CKM_RSA_PKCS_OAEP unwrap
  /// @param wrapping_key The wrapping (encryption) key
  /// @param wrapped The wrapped key to unwrap
  /// @param label Optional label
  /// @return Unwrapped key
  std::vector<uint8_t> ckm_rsa_pkcs_oaep_unwrap(
    RSAKeyPairPtr wrapping_key,
    const std::vector<uint8_t>& wrapped,
    const std::vector<uint8_t>& label = {});

  /// PKCS11 2.1.8 CKM_RSA_PKCS_OAEP
  /// @param wrapping_key The wrapping (encryption) key
  /// @param wrapped The wrapped key to unwrap
  /// @param label Optional label
  /// @return Unwrapped key
  std::vector<uint8_t> ckm_rsa_pkcs_oaep_unwrap(
    const Pem& wrapping_key,
    const std::vector<uint8_t>& wrapped,
    const std::vector<uint8_t>& label = {});

  /// PKCS11 2.14.3 CKM_AES_KEY_WRAP_PAD wrap
  /// @param wrapping_key The wrapping (encryption) key
  /// @param unwrapped The unwrapped key to be wrapped
  /// @return Wrapped key
  std::vector<uint8_t> ckm_aes_key_wrap_pad(
    const std::vector<uint8_t>& wrapping_key,
    const std::vector<uint8_t>& unwrapped);

  /// PKCS11 2.14.3 CKM_AES_KEY_WRAP_PAD unwrap
  std::vector<uint8_t> ckm_aes_key_unwrap_pad(
    /// @param wrapping_key The wrapping (encryption) key
    /// @param wrapped The wrapped key to unwrap
    /// @return Unwrapped key
    const std::vector<uint8_t>& wrapping_key,
    const std::vector<uint8_t>& wrapped);

  /// PKCS11 2.1.21 CKM_RSA_AES_KEY_WRAP wrap
  /// @param aes_key_size Key size 128, 192 or 256.
  /// @param wrapping_key The wrapping (encryption) key
  /// @param unwrapped The key to wrap
  /// @param label Optional label
  /// @return Wrapped key
  std::vector<uint8_t> ckm_rsa_aes_key_wrap(
    size_t aes_key_size,
    RSAPublicKeyPtr wrapping_key,
    const std::vector<uint8_t>& unwrapped,
    const std::vector<uint8_t>& label = {});

  /// PKCS11 2.1.21 CKM_RSA_AES_KEY_WRAP wrap
  /// @param key_size Key size 128, 192 or 256.
  /// @param wrapping_key The wrapping (encryption) key
  /// @param unwrapped The key to wrap
  /// @param label Optional label
  /// @return Wrapped key
  std::vector<uint8_t> ckm_rsa_aes_key_wrap(
    size_t aes_key_size,
    const Pem& wrapping_key,
    const std::vector<uint8_t>& unwrapped,
    const std::vector<uint8_t>& label = {});

  /// PKCS11 2.1.21 CKM_RSA_AES_KEY_WRAP unwrap
  /// @param wrapping_key The wrapping (encryption) key
  /// @param wrapped The wrapped key to unwrap
  /// @param label Optional label
  /// @return Unwrapped key
  std::vector<uint8_t> ckm_rsa_aes_key_unwrap(
    RSAKeyPairPtr wrapping_key,
    const std::vector<uint8_t>& wrapped,
    const std::vector<uint8_t>& label = {});

  /// PKCS11 2.1.21 CKM_RSA_AES_KEY_WRAP unwrap
  /// @param wrapping_key The wrapping (encryption) key
  /// @param wrapped The wrapped key to unwrap
  /// @param label Optional label
  /// @return Unwrapped key
  std::vector<uint8_t> ckm_rsa_aes_key_unwrap(
    const Pem& wrapping_key,
    const std::vector<uint8_t>& wrapped,
    const std::vector<uint8_t>& label = {});
}
