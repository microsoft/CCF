// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C"
{
#endif

  /// Opaque handle to a signing key (Rust-managed).
  struct CoseEvpKey;

  /// Create a signing key from DER-encoded private key bytes.
  /// Returns an opaque pointer, or NULL on failure.
  /// On failure, if err_ptr/err_len are non-null, an error message
  /// is written there.
  CoseEvpKey* cose_key_from_der_private(
    const uint8_t* key_der_ptr,
    size_t key_der_len,
    uint8_t** err_ptr,
    size_t* err_len);

  /// Free a key created by cose_key_from_der_private.
  void cose_key_free(CoseEvpKey* key);

  /// Sign a CCF ledger signature using a pre-created key handle.
  /// Returns 0 on success, non-zero on failure.
  /// On failure, if err_ptr/err_len are non-null, an error message
  /// is written there.
  int cose_sign_ledger(
    const CoseEvpKey* key,
    const uint8_t* kid_ptr,
    size_t kid_len,
    int64_t iat,
    const uint8_t* issuer_ptr,
    size_t issuer_len,
    const uint8_t* subject_ptr,
    size_t subject_len,
    const uint8_t* txid_ptr,
    size_t txid_len,
    const uint8_t* payload_ptr,
    size_t payload_len,
    uint8_t** out_ptr,
    size_t* out_len,
    uint8_t** err_ptr,
    size_t* err_len);

  /// Sign a CCF identity endorsement (COSE_Sign1, embedded payload).
  /// epoch_end and prev_root may be NULL/0 if not applicable.
  /// Returns 0 on success, non-zero on failure.
  /// On failure, if err_ptr/err_len are non-null, an error message
  /// is written there.
  int cose_sign_endorsement(
    const CoseEvpKey* key,
    int64_t iat,
    const uint8_t* epoch_begin_ptr,
    size_t epoch_begin_len,
    const uint8_t* epoch_end_ptr,
    size_t epoch_end_len,
    const uint8_t* prev_root_ptr,
    size_t prev_root_len,
    const uint8_t* payload_ptr,
    size_t payload_len,
    uint8_t** out_ptr,
    size_t* out_len,
    uint8_t** err_ptr,
    size_t* err_len);

  /// Create a verification key from DER-encoded public key bytes.
  /// Returns an opaque pointer, or NULL on failure.
  /// On failure, if err_ptr/err_len are non-null, an error message
  /// is written there.
  CoseEvpKey* cose_key_from_der_public(
    const uint8_t* key_der_ptr,
    size_t key_der_len,
    uint8_t** err_ptr,
    size_t* err_len);

  /// Verify a COSE_Sign1 using a pre-created key handle.
  /// alg: COSE algorithm integer (e.g. -7 for ES256).
  /// Returns 0 on successful verification, non-zero on failure.
  /// On failure, if err_ptr/err_len are non-null, an error message
  /// is written there.
  int cose_verify1(
    const CoseEvpKey* key,
    int64_t alg,
    const uint8_t* phdr_cbor_ptr,
    size_t phdr_cbor_len,
    const uint8_t* payload_ptr,
    size_t payload_len,
    const uint8_t* sig_ptr,
    size_t sig_len,
    uint8_t** err_ptr,
    size_t* err_len);

  /// Free a byte buffer or error string allocated by any cose_* call.
  void cose_free(uint8_t* ptr, size_t len);

#ifdef __cplusplus
}

#  include <stdexcept>
#  include <string>
#  include <vector>

/// RAII wrapper for a byte buffer allocated by a COSE FFI call.
/// On destruction any held buffer is freed automatically via cose_free.
/// Pass data()/size() to FFI functions that accept ptr/len output pairs.
///
/// Used for both output envelopes and error strings:
///   is_set() / to_vector()  — for sign output buffers.
///   is_set() / to_string() — for error strings.
class CoseBuffer
{
  uint8_t* ptr = nullptr;
  size_t len = 0;

public:
  CoseBuffer() = default;
  CoseBuffer(const CoseBuffer&) = delete;
  CoseBuffer& operator=(const CoseBuffer&) = delete;

  CoseBuffer(CoseBuffer&& other) noexcept : ptr(other.ptr), len(other.len)
  {
    other.ptr = nullptr;
    other.len = 0;
  }

  CoseBuffer& operator=(CoseBuffer&& other) noexcept
  {
    if (this != &other)
    {
      reset();
      ptr = other.ptr;
      len = other.len;
      other.ptr = nullptr;
      other.len = 0;
    }
    return *this;
  }

  ~CoseBuffer()
  {
    reset();
  }

  uint8_t** data()
  {
    return &ptr;
  }

  size_t* size()
  {
    return &len;
  }

  void reset()
  {
    if (ptr != nullptr)
    {
      cose_free(ptr, len);
      ptr = nullptr;
      len = 0;
    }
  }

  // -- Buffer accessors --

  [[nodiscard]] std::vector<uint8_t> to_vector() const
  {
    return {ptr, ptr + len};
  }

  [[nodiscard]] std::string to_string() const
  {
    if (ptr != nullptr && len > 0)
    {
      return {reinterpret_cast<const char*>(ptr), len};
    }
    return {};
  }

  [[nodiscard]] bool is_set() const
  {
    return ptr != nullptr && len > 0;
  }
};

/// RAII wrapper for an opaque COSE key (Rust-managed).
/// Can hold either a private key (for signing) or a public key (for
/// verification). Use the named constructors from_private() / from_public().
/// On destruction the underlying key is freed automatically.
class CoseKey
{
  CoseEvpKey* key = nullptr;

  explicit CoseKey(CoseEvpKey* k) : key(k) {}

public:
  CoseKey() = default;

  /// Create a signing key from DER-encoded private key bytes.
  static CoseKey from_private(
    const uint8_t* der_ptr, size_t der_len, CoseBuffer& err)
  {
    return CoseKey(
      cose_key_from_der_private(der_ptr, der_len, err.data(), err.size()));
  }

  /// Create a verification key from DER-encoded public key bytes.
  static CoseKey from_public(
    const uint8_t* der_ptr, size_t der_len, CoseBuffer& err)
  {
    return CoseKey(
      cose_key_from_der_public(der_ptr, der_len, err.data(), err.size()));
  }

  CoseKey(const CoseKey&) = delete;
  CoseKey& operator=(const CoseKey&) = delete;

  CoseKey(CoseKey&& other) noexcept : key(other.key)
  {
    other.key = nullptr;
  }

  CoseKey& operator=(CoseKey&& other) noexcept
  {
    if (this != &other)
    {
      reset();
      key = other.key;
      other.key = nullptr;
    }
    return *this;
  }

  ~CoseKey()
  {
    reset();
  }

  void reset()
  {
    if (key != nullptr)
    {
      cose_key_free(key);
      key = nullptr;
    }
  }

  [[nodiscard]] const CoseEvpKey* get() const
  {
    return key;
  }

  [[nodiscard]] bool is_set() const
  {
    return key != nullptr;
  }
};

/// Sign a CCF ledger signature using a pre-created key handle.
/// Returns 0 on success, non-zero on failure.
/// On failure the CoseBuffer holds the error message.
inline int cose_sign_ledger(
  const CoseKey& key,
  const uint8_t* kid_ptr,
  size_t kid_len,
  int64_t iat,
  const uint8_t* issuer_ptr,
  size_t issuer_len,
  const uint8_t* subject_ptr,
  size_t subject_len,
  const uint8_t* txid_ptr,
  size_t txid_len,
  const uint8_t* payload_ptr,
  size_t payload_len,
  CoseBuffer& out,
  CoseBuffer& err)
{
  return ::cose_sign_ledger(
    key.get(),
    kid_ptr,
    kid_len,
    iat,
    issuer_ptr,
    issuer_len,
    subject_ptr,
    subject_len,
    txid_ptr,
    txid_len,
    payload_ptr,
    payload_len,
    out.data(),
    out.size(),
    err.data(),
    err.size());
}

/// Sign a CCF identity endorsement (COSE_Sign1, embedded payload).
/// epoch_end and prev_root may be nullptr/0 if not applicable.
/// Returns 0 on success, non-zero on failure.
/// On failure the CoseBuffer holds the error message.
inline int cose_sign_endorsement(
  const CoseKey& key,
  int64_t iat,
  const uint8_t* epoch_begin_ptr,
  size_t epoch_begin_len,
  const uint8_t* epoch_end_ptr,
  size_t epoch_end_len,
  const uint8_t* prev_root_ptr,
  size_t prev_root_len,
  const uint8_t* payload_ptr,
  size_t payload_len,
  CoseBuffer& out,
  CoseBuffer& err)
{
  return ::cose_sign_endorsement(
    key.get(),
    iat,
    epoch_begin_ptr,
    epoch_begin_len,
    epoch_end_ptr,
    epoch_end_len,
    prev_root_ptr,
    prev_root_len,
    payload_ptr,
    payload_len,
    out.data(),
    out.size(),
    err.data(),
    err.size());
}

/// Verify a COSE_Sign1 using a pre-created verification key handle.
/// Returns 0 on successful verification, non-zero on failure.
/// On failure the CoseBuffer holds the error message.
inline int cose_verify1(
  const CoseKey& key,
  int64_t alg,
  const uint8_t* phdr_cbor_ptr,
  size_t phdr_cbor_len,
  const uint8_t* payload_ptr,
  size_t payload_len,
  const uint8_t* sig_ptr,
  size_t sig_len,
  CoseBuffer& err)
{
  return ::cose_verify1(
    key.get(),
    alg,
    phdr_cbor_ptr,
    phdr_cbor_len,
    payload_ptr,
    payload_len,
    sig_ptr,
    sig_len,
    err.data(),
    err.size());
}

#endif
