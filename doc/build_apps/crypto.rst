Cryptography API
================

For convenience, CCF provides access to commonly used cryptographic primitives to applications.

.. note:: This page describes the C++ API. For the API for TypeScript/JavaScript applications, see :typedoc-module:`ccf-app/crypto` .

Hashing
-------

.. doxygenfunction:: ccf::crypto::sha256(const std::vector<uint8_t> &data)
  :project: CCF

.. doxygenfunction:: ccf::crypto::hmac(MDType, const std::vector<uint8_t>&, const std::vector<uint8_t>&)
  :project: CCF

.. doxygenClass:: ccf::crypto::HashProvider
  :project: CCF
  :members:

.. doxygenfunction:: ccf::crypto::make_hash_provider
  :project: CCF


Asymmetric Keys
-----------------------

CCF supports EC and RSA keys; public keys are held in (RSA)ECPublicKey objects and
private keys in (RSA)ECKeyPair objects. (RSA)KeyPairs automatically generate random
keys when constructed via :cpp:func:`ECKeyPairPtr ccf::crypto::make_key_pair(CurveID)` or
:cpp:func:`RSAKeyPairPtr ccf::crypto::make_rsa_key_pair(size_t, size_t)`.

.. doxygenclass:: ccf::crypto::ECPublicKey
  :project: CCF
  :members:

.. doxygenclass:: ccf::crypto::ECKeyPair
  :project: CCF
  :members:

.. doxygenclass:: ccf::crypto::RSAPublicKey
  :project: CCF
  :members:

.. doxygenclass:: ccf::crypto::RSAKeyPair
  :project: CCF
  :members:

.. doxygenenum:: ccf::crypto::CurveID
  :project: CCF

.. doxygenfunction:: ccf::crypto::make_key_pair(CurveID)
  :project: CCF

.. doxygenfunction:: ccf::crypto::make_key_pair(const Pem&)
  :project: CCF

.. doxygenfunction:: ccf::crypto::make_rsa_key_pair(size_t, size_t)
  :project: CCF

Symmetric Keys
--------------------

Currently, only AES-GCM is supported for symmetric encryption. New keys are generated via :cpp:func:`ccf::crypto::Entropy::random`

.. doxygenfunction:: ccf::crypto::aes_gcm_encrypt
  :project: CCF

.. doxygenfunction:: ccf::crypto::aes_gcm_decrypt
  :project: CCF

.. doxygenclass:: ccf::crypto::Entropy
  :project: CCF
  :members:

Signatures
------------

Verification of signatures is supported via the :cpp:class:`Verifier` class.

.. doxygenclass:: ccf::crypto::Verifier
  :project: CCF
  :members:


Key Wrapping
------------

PKCS11 2.1.8 CKM_RSA_PKCS_OAEP

.. doxygenfunction:: ccf::crypto::ckm_rsa_pkcs_oaep_wrap(RSAPublicKeyPtr, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

.. doxygenfunction:: ccf::crypto::ckm_rsa_pkcs_oaep_wrap(const Pem&, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

.. doxygenfunction:: ccf::crypto::ckm_rsa_pkcs_oaep_unwrap(RSAKeyPairPtr, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

.. doxygenfunction:: ccf::crypto::ckm_rsa_pkcs_oaep_unwrap(const Pem&, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

PKCS11 2.14.3 CKM_AES_KEY_WRAP_PAD (RFC 5649)

.. doxygenfunction:: ccf::crypto::ckm_aes_key_wrap_pad
  :project: CCF

.. doxygenfunction:: ccf::crypto::ckm_aes_key_unwrap_pad
  :project: CCF

PKCS11 2.1.21 CKM_RSA_AES_KEY_WRAP

.. doxygenfunction:: ccf::crypto::ckm_rsa_aes_key_wrap(size_t, RSAPublicKeyPtr, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

.. doxygenfunction:: ccf::crypto::ckm_rsa_aes_key_wrap(size_t, const Pem&, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

.. doxygenfunction:: ccf::crypto::ckm_rsa_aes_key_unwrap(RSAKeyPairPtr, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

.. doxygenfunction:: ccf::crypto::ckm_rsa_aes_key_unwrap(const Pem&, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF