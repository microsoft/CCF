// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/key_wrap.h"

#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/symmetric_key.h"
#include "openssl/symmetric_key.h"

#include <cstdint>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>

namespace crypto
{
  // With inspiration from
  // http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html

  std::vector<uint8_t> ckm_rsa_pkcs_oaep_wrap(
    RSAPublicKeyPtr wrapping_key,
    const std::vector<uint8_t>& unwrapped,
    const std::optional<std::vector<uint8_t>>& label)
  {
    return wrapping_key->rsa_oaep_wrap(unwrapped, label);
  }

  std::vector<uint8_t> ckm_rsa_pkcs_oaep_wrap(
    const Pem& wrapping_key,
    const std::vector<uint8_t>& unwrapped,
    const std::optional<std::vector<uint8_t>>& label)
  {
    auto pk = make_rsa_public_key(wrapping_key);
    return ckm_rsa_pkcs_oaep_wrap(pk, unwrapped, label);
  }

  std::vector<uint8_t> ckm_rsa_pkcs_oaep_unwrap(
    RSAKeyPairPtr wrapping_key,
    const std::vector<uint8_t>& wrapped,
    const std::optional<std::vector<uint8_t>>& label)
  {
    return wrapping_key->rsa_oaep_unwrap(wrapped, label);
  }

  std::vector<uint8_t> ckm_rsa_pkcs_oaep_unwrap(
    const Pem& wrapping_key,
    const std::vector<uint8_t>& wrapped,
    const std::optional<std::vector<uint8_t>>& label)
  {
    auto pk = make_rsa_key_pair(wrapping_key);
    return ckm_rsa_pkcs_oaep_unwrap(pk, wrapped, label);
  }

  std::vector<uint8_t> ckm_aes_key_wrap_pad(
    const std::vector<uint8_t>& wrapping_key,
    const std::vector<uint8_t>& unwrapped)
  {
    auto ossl = std::make_unique<KeyAesGcm_OpenSSL>(wrapping_key);
    return ossl->ckm_aes_key_wrap_pad(unwrapped);
  }

  std::vector<uint8_t> ckm_aes_key_unwrap_pad(
    const std::vector<uint8_t>& wrapping_key,
    const std::vector<uint8_t>& wrapped)
  {
    auto ossl = std::make_unique<KeyAesGcm_OpenSSL>(wrapping_key);
    return ossl->ckm_aes_key_unwrap_pad(wrapped);
  }

  std::vector<uint8_t> ckm_rsa_aes_key_wrap(
    size_t aes_key_size,
    RSAPublicKeyPtr wrapping_key,
    const std::vector<uint8_t>& unwrapped,
    const std::optional<std::vector<uint8_t>>& label)
  {
    if (aes_key_size != 128 && aes_key_size != 192 && aes_key_size != 256)
      throw std::runtime_error("invalid key size");

    // - Generates temporary random AES key of ulAESKeyBits length. This key is
    //   not accessible to the user - no handle is returned.
    std::vector<uint8_t> taeskey(aes_key_size / 8);
    RAND_bytes(taeskey.data(), taeskey.size());

    // - Wraps the AES key with the wrapping RSA key using CKM_RSA_PKCS_OAEP
    //   with parameters of OAEPParams.
    std::vector<uint8_t> w_aeskey = wrapping_key->rsa_oaep_wrap(taeskey, label);

    // - Wraps the target key with the temporary AES key using
    //   CKM_AES_KEY_WRAP_PAD (RFC5649).
    auto aes = std::make_unique<KeyAesGcm_OpenSSL>(taeskey);
    std::vector<uint8_t> w_target = aes->ckm_aes_key_wrap_pad(unwrapped);

    // - Zeroizes the temporary AES key.
    memset(taeskey.data(), 0, taeskey.size());

    // - Concatenates two wrapped keys and outputs the concatenated blob.
    std::vector<uint8_t> r;
    r.insert(r.end(), w_aeskey.begin(), w_aeskey.end());
    r.insert(r.end(), w_target.begin(), w_target.end());
    return r;
  }

  std::vector<uint8_t> ckm_rsa_aes_key_wrap(
    size_t aes_key_size,
    const Pem& wrapping_key,
    const std::vector<uint8_t>& unwrapped,
    const std::optional<std::vector<uint8_t>>& label)
  {
    auto pk = make_rsa_public_key(wrapping_key);
    return ckm_rsa_aes_key_wrap(aes_key_size, pk, unwrapped, label);
  }

  std::vector<uint8_t> ckm_rsa_aes_key_unwrap(
    RSAKeyPairPtr wrapping_key,
    const std::vector<uint8_t>& wrapped,
    const std::optional<std::vector<uint8_t>>& label)
  {
    // - Splits the input into two parts. The first is the wrapped AES key, and
    //   the second is the wrapped target key. The length of the first part is
    //   equal to the length of the unwrapping RSA key.

    size_t w_aes_sz = wrapping_key->key_size() / 8;

    if (wrapped.size() <= w_aes_sz)
      throw std::runtime_error("not enough ciphertext");

    std::vector<uint8_t> w_aeskey(wrapped.begin(), wrapped.begin() + w_aes_sz);
    std::vector<uint8_t> w_target(wrapped.begin() + w_aes_sz, wrapped.end());

    // - Un-wraps the temporary AES key from the first part with the private RSA
    //   key using CKM_RSA_PKCS_OAEP with parameters of OAEPParams.

    std::vector<uint8_t> t_aeskey =
      wrapping_key->rsa_oaep_unwrap(w_aeskey, label);

    if (t_aeskey.size() != 16 && t_aeskey.size() != 24 && t_aeskey.size() != 32)
      throw std::runtime_error("invalid key size");

    // - Un-wraps the target key from the second part with the temporary AES key
    //   using CKM_AES_KEY_WRAP_PAD (RFC5649).

    auto aes = std::make_unique<KeyAesGcm_OpenSSL>(t_aeskey);
    std::vector<uint8_t> target = aes->ckm_aes_key_unwrap_pad(w_target);

    // - Zeroizes the temporary AES key.
    memset(t_aeskey.data(), 0, t_aeskey.size());

    // - Returns the handle to the newly unwrapped target key.
    return target;
  }

  std::vector<uint8_t> ckm_rsa_aes_key_unwrap(
    const Pem& wrapping_key,
    const std::vector<uint8_t>& wrapped,
    const std::optional<std::vector<uint8_t>>& label)
  {
    auto pk = make_rsa_key_pair(wrapping_key);
    return ckm_rsa_aes_key_unwrap(pk, wrapped, label);
  }
}
