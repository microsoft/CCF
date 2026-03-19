// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C"
{
#endif

  /// Sign a CCF ledger signature (COSE_Sign1, detached payload).
  /// Returns 0 on success, non-zero on failure.
  int cose_sign_ledger(
    const uint8_t* key_der_ptr,
    size_t key_der_len,
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
    size_t* out_len);

  /// Sign a CCF identity endorsement (COSE_Sign1, embedded payload).
  /// epoch_end and prev_root may be NULL/0 if not applicable.
  /// Returns 0 on success, non-zero on failure.
  int cose_sign_endorsement(
    const uint8_t* key_der_ptr,
    size_t key_der_len,
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
    size_t* out_len);

  /// Verify a COSE_Sign1 from pre-parsed components.
  /// alg: COSE algorithm integer (e.g. -7 for ES256).
  /// phdr_cbor_ptr/phdr_cbor_len: serialized CBOR protected header bytes.
  /// payload_ptr/payload_len: raw payload bytes (not CBOR-wrapped).
  /// sig_ptr/sig_len: the fixed-size signature bytes.
  /// Returns 0 on successful verification, non-zero on failure.
  int cose_verify1(
    const uint8_t* key_pub_der_ptr,
    size_t key_pub_der_len,
    int64_t alg,
    const uint8_t* phdr_cbor_ptr,
    size_t phdr_cbor_len,
    const uint8_t* payload_ptr,
    size_t payload_len,
    const uint8_t* sig_ptr,
    size_t sig_len);

  /// Free a buffer returned by cose_sign_*.
  void cose_free(uint8_t* ptr, size_t len);

#ifdef __cplusplus
}

#  include <stdexcept>
#  include <vector>

/// RAII wrapper for buffers allocated by cose_sign_* FFI functions.
/// Automatically calls cose_free on destruction.
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

  [[nodiscard]] std::vector<uint8_t> to_vector() const
  {
    return {ptr, ptr + len};
  }

  [[nodiscard]] bool ok() const
  {
    return ptr != nullptr && len > 0;
  }
};

inline int cose_sign_ledger(
  const uint8_t* key_der_ptr,
  size_t key_der_len,
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
  CoseBuffer& out)
{
  return ::cose_sign_ledger(
    key_der_ptr,
    key_der_len,
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
    out.size());
}

inline int cose_sign_endorsement(
  const uint8_t* key_der_ptr,
  size_t key_der_len,
  int64_t iat,
  const uint8_t* epoch_begin_ptr,
  size_t epoch_begin_len,
  const uint8_t* epoch_end_ptr,
  size_t epoch_end_len,
  const uint8_t* prev_root_ptr,
  size_t prev_root_len,
  const uint8_t* payload_ptr,
  size_t payload_len,
  CoseBuffer& out)
{
  return ::cose_sign_endorsement(
    key_der_ptr,
    key_der_len,
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
    out.size());
}

#endif
