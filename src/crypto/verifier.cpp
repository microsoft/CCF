// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/verifier.h"

#include "crypto/openssl/verifier.h"

namespace ccf::crypto
{
  using VerifierPtr = std::shared_ptr<Verifier>;
  using VerifierUniquePtr = std::unique_ptr<Verifier>;

  VerifierUniquePtr make_unique_verifier(const std::vector<uint8_t>& cert)
  {
    return std::make_unique<Verifier_OpenSSL>(cert);
  }

  VerifierPtr make_verifier(const std::vector<uint8_t>& cert)
  {
    return std::make_shared<Verifier_OpenSSL>(cert);
  }

  VerifierUniquePtr make_unique_verifier(const Pem& pem)
  {
    return make_unique_verifier(pem.raw());
  }

  VerifierPtr make_verifier(const Pem& pem)
  {
    return make_verifier(pem.raw());
  }

  ccf::crypto::Pem cert_der_to_pem(const std::vector<uint8_t>& der)
  {
    return make_verifier(der)->cert_pem();
  }

  std::vector<uint8_t> cert_pem_to_der(const ccf::crypto::Pem& pem)
  {
    return make_verifier(pem)->cert_der();
  }

  std::vector<uint8_t> public_key_der_from_cert(const std::vector<uint8_t>& der)
  {
    return make_unique_verifier(der)->public_key_der();
  }

  ccf::crypto::Pem public_key_pem_from_cert(const std::vector<uint8_t>& der)
  {
    return make_unique_verifier(der)->public_key_pem();
  }

  std::string get_subject_name(const Pem& cert)
  {
    return make_verifier(cert)->subject();
  }

  bool Verifier::verify_hash(
    const uint8_t* hash,
    size_t hash_size,
    const uint8_t* sig,
    size_t sig_size,
    MDType md_type)
  {
    if (std::holds_alternative<RSAPublicKeyPtr>(public_key))
    {
      return std::get<RSAPublicKeyPtr>(public_key)
        ->verify_hash(hash, hash_size, sig, sig_size, md_type);
    }
    else if (std::holds_alternative<ECPublicKeyPtr>(public_key))
    {
      return std::get<ECPublicKeyPtr>(public_key)
        ->verify_hash(hash, hash_size, sig, sig_size, md_type);
    }
    else
    {
      throw std::runtime_error("Invalid public key type");
    }
  }

  bool Verifier::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* sig,
    size_t sig_size,
    MDType md_type) const
  {
    if (std::holds_alternative<RSAPublicKeyPtr>(public_key))
    {
      return std::get<RSAPublicKeyPtr>(public_key)
        ->verify(contents, contents_size, sig, sig_size, md_type);
    }
    else if (std::holds_alternative<ECPublicKeyPtr>(public_key))
    {
      return std::get<ECPublicKeyPtr>(public_key)
        ->verify(contents, contents_size, sig, sig_size, md_type);
    }
    else
    {
      throw std::runtime_error("Invalid public key type");
    }
  }

  Pem Verifier::public_key_pem() const
  {
    if (std::holds_alternative<RSAPublicKeyPtr>(public_key))
    {
      return std::get<RSAPublicKeyPtr>(public_key)->public_key_pem();
    }
    else if (std::holds_alternative<ECPublicKeyPtr>(public_key))
    {
      return std::get<ECPublicKeyPtr>(public_key)->public_key_pem();
    }
    else
    {
      throw std::runtime_error("Invalid public key type");
    }
  }

  std::vector<uint8_t> Verifier::public_key_der() const
  {
    if (std::holds_alternative<RSAPublicKeyPtr>(public_key))
    {
      return std::get<RSAPublicKeyPtr>(public_key)->public_key_der();
    }
    else if (std::holds_alternative<ECPublicKeyPtr>(public_key))
    {
      return std::get<ECPublicKeyPtr>(public_key)->public_key_der();
    }
    else
    {
      throw std::runtime_error("Invalid public key type");
    }
  }
}
