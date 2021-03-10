Cryptography API
================

For convenience, CCF provides access to commonly used cryptographic primitives to applications.


Hashing
-------

.. doxygenfunction:: crypto::SHA256
  :project: CCF

.. doxygenclass:: crypto::HashProvider
  :project: CCF


Asymmetric Cryptography
-----------------------


Symmetric Encryption
--------------------

.. doxygenfunction:: crypto::aes_gcm_encrypt
  :project: CCF

.. doxygenfunction:: crypto::aes_gcm_decrypt
  :project: CCF


Certificates
------------


Key Wrapping
------------

PKCS11 2.1.8 CKM_RSA_PKCS_OAEP

.. doxygenfunction:: crypto::ckm_rsa_pkcs_oaep_wrap(RSAPublicKeyPtr wrapping_key, const std::vector<uint8_t> &unwrapped, const std::vector<uint8_t> &label)
  :project: CCF

.. doxygenfunction:: crypto::ckm_rsa_pkcs_oaep_unwrap
  :project: CCF

PKCS11 2.14.3 CKM_AES_KEY_WRAP_PAD (RFC 5649)

.. doxygenfunction:: crypto::ckm_aes_key_wrap_pad
  :project: CCF

.. doxygenfunction:: crypto::ckm_aes_key_unwrap_pad
  :project: CCF

PKCS11 2.1.21 CKM_RSA_AES_KEY_WRAP

.. doxygenfunction:: crypto::ckm_rsa_aes_key_wrap

  :project: CCF

.. doxygenfunction:: crypto::ckm_rsa_aes_key_unwrap
  :project: CCF