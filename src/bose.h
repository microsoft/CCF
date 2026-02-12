// This header is for the user of libbose.a.

#ifndef BOSE_H
#define BOSE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Free a buffer previously returned by bose_sign / bose_sign_detached.
 */
void bose_free(uint8_t *ptr, size_t len);

/**
 * Sign with embedded payload.
 *
 * Produces a complete COSE_Sign1 envelope (tag 18).
 *
 * @param phdr        Serialised CBOR map (protected header, without alg).
 * @param phdr_len    Length of phdr.
 * @param uhdr        Serialised CBOR map (unprotected header).
 * @param uhdr_len    Length of uhdr.
 * @param payload     Raw payload bytes.
 * @param payload_len Length of payload.
 * @param key_der     DER-encoded private key.
 * @param key_der_len Length of key_der.
 * @param out_ptr     On success, receives a pointer to the COSE_Sign1 bytes
 *                    (caller must free with bose_free).
 * @param out_len     On success, receives the length of the output.
 * @return            0 on success, -1 on error.
 */
int32_t bose_sign(const uint8_t *phdr, size_t phdr_len, const uint8_t *uhdr,
                  size_t uhdr_len, const uint8_t *payload, size_t payload_len,
                  const uint8_t *key_der, size_t key_der_len, uint8_t **out_ptr,
                  size_t *out_len);

/**
 * Sign with detached payload.
 *
 * Same as bose_sign but the COSE_Sign1 envelope carries a CBOR null instead
 * of the payload.
 *
 * @return 0 on success, -1 on error.
 */
int32_t bose_sign_detached(const uint8_t *phdr, size_t phdr_len,
                           const uint8_t *uhdr, size_t uhdr_len,
                           const uint8_t *payload, size_t payload_len,
                           const uint8_t *key_der, size_t key_der_len,
                           uint8_t **out_ptr, size_t *out_len);

/**
 * Verify a COSE_Sign1 envelope with embedded payload.
 *
 * @param envelope     Full COSE_Sign1 bytes.
 * @param envelope_len Length of envelope.
 * @param key_der      DER-encoded public key (SubjectPublicKeyInfo).
 * @param key_der_len  Length of key_der.
 * @return             1 if valid, 0 if invalid, -1 on error.
 */
int32_t bose_verify(const uint8_t *envelope, size_t envelope_len,
                    const uint8_t *key_der, size_t key_der_len);

/**
 * Verify a COSE_Sign1 envelope with detached payload.
 *
 * @param envelope     COSE_Sign1 bytes (payload slot is CBOR null).
 * @param envelope_len Length of envelope.
 * @param payload      Detached payload bytes.
 * @param payload_len  Length of payload.
 * @param key_der      DER-encoded public key (SubjectPublicKeyInfo).
 * @param key_der_len  Length of key_der.
 * @return             1 if valid, 0 if invalid, -1 on error.
 */
int32_t bose_verify_detached(const uint8_t *envelope, size_t envelope_len,
                             const uint8_t *payload, size_t payload_len,
                             const uint8_t *key_der, size_t key_der_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* BOSE_H */
