// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

// cwinter: this is a simplified version of CCBF's keypair.h that uses
// Hacl's EDDSA (Curve25519) directly instead of via mbedTLS. It does
// not support certificates (X509 certificate files, PEM, DER).

#include <cstring>
#include <iomanip>
#include <limits>
#include <memory>
#include <string.h>
#include <vector>

extern "C"
{
#include <evercrypt/EverCrypt_Curve25519.h>
#include <evercrypt/EverCrypt_Ed25519.h>
#include <evercrypt/EverCrypt_Error.h>
#include <evercrypt/EverCrypt_Hash.h>
}

#include "ds/logger.h"
#include "epbft_drng.h"
#include "parameters.h"

using SHA512 = std::array<uint8_t, SHA512_BYTES>;

class KeyPair
{
protected:
  typedef struct
  {
    uint8_t private_[32];
    uint8_t public_sig_[32]; /* Public key for signatures */
    uint8_t public_enc_[32]; /* Public key for encryption */
    // We need public
  } keys_t;

  keys_t keys;

private:
  void init()
  {
    // preconditions of EverCrypt_Ed25519_secret_to_public
    if (!(sizeof(keys.public_sig_) == 32 &&
          (keys.public_sig_ <= keys.private_ ||
           keys.public_sig_ >= keys.private_ + sizeof(keys.private_))))
      throw std::logic_error("key generation failed");

    keys.private_[0] &= 248;
    keys.private_[31] &= 127;
    keys.private_[31] |= 64;

    EverCrypt_Ed25519_secret_to_public(keys.public_sig_, keys.private_);

    uint8_t base[32] = {0};
    base[0] = 9;
    EverCrypt_Curve25519_ecdh(keys.public_enc_, keys.private_, base);
  }

public:
  typedef std::array<uint8_t, signature_size> Signature;

public:
  /**
   * Create a new public / private key pair
   */
  KeyPair()
  {
    epbft::IntelDRNG drng;
    drng.rng(0, keys.private_, 32);
    init();
  }

  KeyPair(const KeyPair&) = delete;

  KeyPair(KeyPair&& other)
  {
    keys = std::move(other.keys);
  }

  /**
   * Initialise from just a private key
   * **/
  KeyPair(uint8_t* private_key)
  {
    memcpy(keys.private_, private_key, 32);

    init();
  }

  ~KeyPair()
  {
    memset(&keys, 0, sizeof(keys_t));
  }

  uint8_t* get_public_sig_key()
  {
    return keys.public_sig_;
  }

  uint8_t* get_public_enc_key()
  {
    return keys.public_enc_;
  }

  uint8_t* get_private_key()
  {
    return keys.private_;
  }

  /**
   * Create signature over data from private key.
   *
   * @param d data
   *
   * @return Signature as a vector
   */
  std::vector<uint8_t> sign(unsigned char* d, size_t d_size) const
  {
    uint8_t sig[max_sig_size];
    sign(d, d_size, sig);
    return {sig, sig + signature_size};
  }

  /**
   * Create signature over data from private key.
   *
   * @param d data
   */
  void sign(unsigned char* d, size_t d_size, KeyPair::Signature& sig) const
  {
    sign(d, d_size, sig.data());
  }

  /**
   * Write signature over data, and the size of that signature to
   * specified locations.
   *
   * Important: While sig_size will always be written to as a single
   * unint8_t, sig must point somewhere that's at least
   * MBEDTLS_E{C,D}DSA_MAX_LEN.
   *
   * @param d data
   * @param sig_size location to which the signature size will be written
   * @param sig location to which the signature will be written
   *
   * @return 0 if successful, error code of mbedtls_pk_sign otherwise,
   *         or 0xf if the signature_size exceeds that of a uint8_t.
   */
  int sign(
    unsigned char* d, size_t d_size, uint8_t* sig_size, uint8_t* sig) const
  {
    uint8_t hash[SHA512_BYTES];
    EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA2_512, hash, d, d_size);

    size_t written = signature_size;

    // preconditions of EverCrypt_Ed25519_sign
    if (!(sizeof(keys.private_) == 32 &&
          sizeof(hash) < 4294967232 /* 2^32 - 64 */))
      throw std::logic_error("precondition to EverCrypt_Ed25519_sign violated");

    EverCrypt_Ed25519_sign(sig, (uint8_t*)keys.private_, sizeof(hash), hash);
    // postcondition of EverCrypt_Ed25519_sign: signature length = 64

    *sig_size = written;
    return 0;
  }

  std::vector<uint8_t> sign(std::vector<uint8_t> data) const
  {
    return sign((unsigned char*)data.data(), data.size());
  }

  std::vector<uint8_t> sign_hash(const uint8_t* hash, uint32_t hash_size) const
  {
    uint8_t sig[max_sig_size];

    // preconditions of EverCrypt_Ed25519_sign
    if (!(sizeof(keys.private_) == 32 &&
          hash_size < 4294967232 /* 2^32 - 64 */))
      throw std::logic_error("precondition to EverCrypt_Ed25519_sign violated");

    EverCrypt_Ed25519_sign(
      sig, (uint8_t*)keys.private_, hash_size, const_cast<uint8_t*>(hash));
    // postcondition of EverCrypt_Ed25519_sign: signature length = 64

    return {sig, sig + signature_size};
  }

private:
  void sign(unsigned char* d, size_t d_size, uint8_t* sig) const
  {
    uint8_t hash[SHA512_BYTES];
    EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA2_512, hash, d, d_size);

    // preconditions of EverCrypt_Ed25519_sign
    if (!(sizeof(keys.private_) == 32 &&
          sizeof(hash) < 4294967232 /* 2^32 - 64 */))
      throw std::logic_error("precondition to EverCrypt_Ed25519_sign violated");

    EverCrypt_Ed25519_sign(sig, (uint8_t*)keys.private_, sizeof(hash), hash);
    // postcondition of EverCrypt_Ed25519_sign: signature length = 64
  }
};

class PublicKey
{
protected:
  uint8_t key[32];

public:
  PublicKey(
    const std::vector<uint8_t>& public_key) // cwinter: raw format, no PEM!
  {
    if (public_key.size() != 32)
      throw std::logic_error("unexpected key size");

    for (unsigned i = 0; i < public_key.size(); i++)
      key[i] = public_key[i];
  }

  PublicKey(const uint8_t* public_key) // cwinter: raw format, no PEM!
  {
    memcpy(key, public_key, 32);
  }

  /**
   * Verify that a signature was produced on contents with the private key
   * associated with the public key held by the object.
   *
   * @param contents Sequence of bytes that was signed
   * @param signature Signature as a sequence of bytes
   *
   * @return Whether the signature matches the contents and the key
   */
  bool verify(
    const std::vector<uint8_t>& contents, const std::vector<uint8_t>& signature)
  {
    return verify(
      contents.data(), contents.size(), signature.data(), signature.size());
  }

  /**
   * Verify that a signature was produced on contents with the private key
   * associated with the public key held by the object.
   *
   * @param contents address of contents
   * @param contents_size size of contents
   * @param contents address of signature
   * @param contents_size size of signature
   *
   * @return Whether the signature matches the contents and the key
   */
  bool verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* sig,
    uint8_t sig_size)
  {
    uint8_t hash[SHA512_BYTES];
    EverCrypt_Hash_hash(
      Spec_Hash_Definitions_SHA2_512,
      hash,
      const_cast<uint8_t*>(contents),
      contents_size);

    // preconditions of EverCrypt_Ed25519_verify
    if (!(sizeof(key) == 32 && sig_size == signature_size &&
          sizeof(hash) < 4294967232 /* 2^32 - 64 */))
      throw std::logic_error(
        "precondition to EverCrypt_Ed25519_verify violated");

    auto rc = EverCrypt_Ed25519_verify(
      key, sizeof(hash), hash, const_cast<uint8_t*>(sig));

    if (!rc)
    {
      LOG_FAIL << "Verification failed" << std::endl;
    }

    return rc;
  }

  ~PublicKey()
  {
    memset(key, 0, sizeof(key));
  }
};
