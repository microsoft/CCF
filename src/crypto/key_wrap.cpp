// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "key_wrap.h"

#include "openssl/symmetric_key.h"
#include "rsa_key_pair.h"

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace crypto
{
  // With inspiration from
  // http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html

  std::vector<uint8_t> ckm_rsa_aes_key_wrap(
    size_t aes_key_size,
    RSAPublicKeyPtr rsa_public,
    const std::vector<uint8_t>& target_key)
  {
    if (aes_key_size != 128 && aes_key_size != 192 && aes_key_size != 256)
      throw std::runtime_error("invalid key size");

    // - Generates temporary random AES key of ulAESKeyBits length. This key is
    //   not accessible to the user - no handle is returned.
    std::vector<uint8_t> taeskey(aes_key_size / 8);
    RAND_bytes(taeskey.data(), taeskey.size());

    // - Wraps the AES key with the wrapping RSA key using CKM_RSA_PKCS_OAEP
    //   with parameters of OAEPParams.
    std::vector<uint8_t> w_aeskey = rsa_public->wrap(taeskey);

    // - Wraps the target key with the temporary AES key using
    //   CKM_AES_KEY_WRAP_PAD (RFC5649).
    auto aes = std::make_unique<KeyAesGcm_OpenSSL>(taeskey);
    std::vector<uint8_t> w_target;
    aes->ckm_aes_key_wrap_pad(target_key, w_target);

    // - Zeroizes the temporary AES key.
    memset(taeskey.data(), 0, taeskey.size());

    // - Concatenates two wrapped keys and outputs the concatenated blob.
    std::vector<uint8_t> r;
    r.insert(r.begin(), w_target.begin(), w_target.end());
    r.insert(r.begin(), w_aeskey.begin(), w_aeskey.end());
    return r;
  }

  std::vector<uint8_t> ckm_rsa_aes_key_unwrap(
    const std::vector<uint8_t>& cipher, RSAKeyPairPtr rsakp)
  {
    // - Splits the input into two parts. The first is the wrapped AES key, and
    //   the second is the wrapped target key. The length of the first part is
    //   equal to the length of the unwrapping RSA key.

    size_t w_aes_sz = rsakp->key_size() / 8;

    if (cipher.size() <= w_aes_sz)
      throw std::runtime_error("not enough ciphertext");

    std::vector<uint8_t> w_aeskey(cipher.begin(), cipher.begin() + w_aes_sz);
    std::vector<uint8_t> w_target(cipher.begin() + w_aes_sz, cipher.end());

    // - Un-wraps the temporary AES key from the first part with the private RSA
    //   key using CKM_RSA_PKCS_OAEP with parameters of OAEPParams.

    std::vector<uint8_t> taeskey = rsakp->unwrap(w_aeskey);

    // - Un-wraps the target key from the second part with the temporary AES key
    //   using CKM_AES_KEY_WRAP_PAD (RFC5649).

    auto aes = std::make_unique<KeyAesGcm_OpenSSL>(taeskey);
    std::vector<uint8_t> target;
    aes->ckm_aes_key_unwrap_pad(w_target, target);

    // - Zeroizes the temporary AES key.
    memset(taeskey.data(), 0, taeskey.size());

    // - Returns the handle to the newly unwrapped target key.
    return target;
  }
}
