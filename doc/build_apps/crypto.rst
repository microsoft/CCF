Cryptography API
================

For convenience, CCF provides access to commonly used cryptographic primitives to applications.


Hashing
-------

.. doxygenfunction:: crypto::sha256(const std::vector<uint8_t> &data)
  :project: CCF

.. doxygenfunction:: crypto::hmac(MDType, const std::vector<uint8_t>&, const std::vector<uint8_t>&)
  :project: CCF

.. doxygenClass:: crypto::HashProvider
  :project: CCF
  :members:

.. doxygenfunction:: crypto::make_hash_provider
  :project: CCF


Asymmetric Keys
-----------------------

CCF supports EC and RSA keys; public keys are held in (RSA)PublicKey objects and
private keys in (RSA)KeyPair objects. (RSA)KeyPairs automatically generate random
keys when constructed via :cpp:func:`KeyPairPtr crypto::make_key_pair(CurveID)` or
:cpp:func:`RSAKeyPairPtr crypto::make_rsa_key_pair(size_t, size_t)`.

.. doxygenclass:: crypto::PublicKey
  :project: CCF
  :members:

.. doxygenclass:: crypto::KeyPair
  :project: CCF
  :members:

.. doxygenclass:: crypto::RSAPublicKey
  :project: CCF
  :members:

.. doxygenclass:: crypto::RSAKeyPair
  :project: CCF
  :members:

.. doxygenenum:: crypto::CurveID
  :project: CCF

.. doxygenfunction:: crypto::make_key_pair(CurveID)
  :project: CCF

.. doxygenfunction:: crypto::make_key_pair(const Pem&)
  :project: CCF

.. doxygenfunction:: crypto::make_rsa_key_pair(size_t, size_t)
  :project: CCF

Symmetric Keys
--------------------

Currently, only AES-GCM is supported for symmetric encryption. New keys are generated via :cpp:func:`crypto::Entropy::random`

.. doxygenfunction:: crypto::aes_gcm_encrypt
  :project: CCF

.. doxygenfunction:: crypto::aes_gcm_decrypt
  :project: CCF

.. doxygenclass:: crypto::Entropy
  :project: CCF
  :members:

Signatures
------------

Verification of signatures is supported via the :cpp:class:`Verifier` class.

.. doxygenclass:: crypto::Verifier
  :project: CCF
  :members:


Key Wrapping
------------

PKCS11 2.1.8 CKM_RSA_PKCS_OAEP

.. doxygenfunction:: crypto::ckm_rsa_pkcs_oaep_wrap(RSAPublicKeyPtr, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

.. doxygenfunction:: crypto::ckm_rsa_pkcs_oaep_wrap(const Pem&, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

.. doxygenfunction:: crypto::ckm_rsa_pkcs_oaep_unwrap(RSAKeyPairPtr, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

.. doxygenfunction:: crypto::ckm_rsa_pkcs_oaep_unwrap(const Pem&, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

PKCS11 2.14.3 CKM_AES_KEY_WRAP_PAD (RFC 5649)

.. doxygenfunction:: crypto::ckm_aes_key_wrap_pad
  :project: CCF

.. doxygenfunction:: crypto::ckm_aes_key_unwrap_pad
  :project: CCF

PKCS11 2.1.21 CKM_RSA_AES_KEY_WRAP

.. doxygenfunction:: crypto::ckm_rsa_aes_key_wrap(size_t, RSAPublicKeyPtr, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

.. doxygenfunction:: crypto::ckm_rsa_aes_key_wrap(size_t, const Pem&, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

.. doxygenfunction:: crypto::ckm_rsa_aes_key_unwrap(RSAKeyPairPtr, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF

.. doxygenfunction:: crypto::ckm_rsa_aes_key_unwrap(const Pem&, const std::vector<uint8_t>&, const std::optional<std::vector<uint8_t>>&)
  :project: CCF