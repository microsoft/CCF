/*
 *  t_cose_openssl_crypto.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created 3/31/2019.
 */


#include "t_cose_crypto.h" /* The interface this code implements */

#include <openssl/ecdsa.h> /* Needed for signature format conversion */
#include <openssl/evp.h>
#include <openssl/err.h>


/**
 * \file t_cose_openssl_crypto.c
 *
 * \brief Crypto Adaptation for t_cose to use OpenSSL ECDSA and hashes.
 *
 * This connects up the abstracted crypto services defined in
 * t_cose_crypto.h to the OpenSSL implementation of them.
 *
 * Having this adapter layer doesn't bloat the implementation as everything here
 * had to be done anyway -- the mapping of algorithm IDs, the data format
 * rearranging, the error code translation.
 *
 * This code should just work out of the box if compiled and linked
 * against OpenSSL and with the T_COSE_USE_OPENSSL_CRYPTO preprocessor
 * define set for the build.
 *
 * This works with OpenSSL 1.1.1 and 3.0. It uses the APIs common
 * to these two and that are not marked for future deprecation.
 *
 * A few complaints about OpenSSL in comparison to Mbed TLS:
 *
 * OpenSSL mallocs for various things where MBed TLS does not.
 * This makes the OpenSSL code more complex because checks for malloc
 * failures are necessary.
 *
 * There's a lot of APIs in OpenSSL, but there's a needle to thread to
 * get the APIS that are in 1.1.1, 3.0 and not slated for future
 * deprecation.
 *
 * The APIs that fit the above only work for DER-encoded signatures.
 * t_cose encodes signatures in a more simple way. This difference
 * requires the code here to do conversion which increases its size
 * and complexity and requires intermediate buffers and requires more
 * use of malloc.
 *
 * An older version of t_cose (anything from 2021) uses simpler
 * OpenSSL APIs. They still work but may be deprecated in the
 * future. They could be used in use cases where a particular version
 * of the OpenSSL library is selected and reduce code size
 * a llittle.
 */


/**
 * \brief Convert DER-encoded signature to COSE-serialized signature
 *
 * \param[in] key_len             Size of the key in bytes -- governs sig size.
 * \param[in] der_signature       DER-encoded signature.
 * \param[in] signature_buffer    The buffer for output.
 *
 * \return The pointer and length of serialized signature in \c signature_buffer
           or NULL_Q_USEFUL_BUF_C on error.
 *
 * The serialized format is defined by COSE in RFC 8152 section
 * 8.1. The signature which consist of two integers, r and s,
 * are simply zero padded to the nearest byte length and
 * concatenated.
 */
static inline struct q_useful_buf_c
signature_der_to_cose(unsigned               key_len,
                      struct q_useful_buf_c  der_signature,
                      struct q_useful_buf    signature_buffer)
{
    size_t                r_len;
    size_t                s_len;
    const BIGNUM         *r_bn;
    const BIGNUM         *s_bn;
    struct q_useful_buf_c cose_signature;
    void                 *r_start_ptr;
    void                 *s_start_ptr;
    const unsigned char  *temp_der_sig_pointer;
    ECDSA_SIG            *es;

    /* Put DER-encode sig into an ECDSA_SIG so we can get the r and s out. */
    temp_der_sig_pointer = der_signature.ptr;
    es = d2i_ECDSA_SIG(NULL, &temp_der_sig_pointer, (long)der_signature.len);
    if(es == NULL) {
        cose_signature = NULL_Q_USEFUL_BUF_C;
        goto Done;
    }

    /* Zero the buffer so that bytes r and s are padded with zeros */
    q_useful_buf_set(signature_buffer, 0);

    /* Get the signature r and s as BIGNUMs */
    r_bn = NULL;
    s_bn = NULL;
    ECDSA_SIG_get0(es, &r_bn, &s_bn);
    /* ECDSA_SIG_get0 returns void */


    /* Internal consistency check that the r and s values will fit
     * into the expected size. Be sure the output buffer is not
     * overrun.
     */
    /* Cast is safe because BN_num_bytes() is documented to not return
     * negative numbers.
     */
    r_len = (size_t)BN_num_bytes(r_bn);
    s_len = (size_t)BN_num_bytes(s_bn);
    if(r_len + s_len > signature_buffer.len) {
        cose_signature = NULL_Q_USEFUL_BUF_C;
        goto Done2;
    }

    /* Copy r and s of signature to output buffer and set length */
    r_start_ptr = (uint8_t *)(signature_buffer.ptr) + key_len - r_len;
    BN_bn2bin(r_bn, r_start_ptr);

    s_start_ptr = (uint8_t *)signature_buffer.ptr + 2 * key_len - s_len;
    BN_bn2bin(s_bn, s_start_ptr);

    cose_signature = (UsefulBufC){signature_buffer.ptr, 2 * key_len};

Done2:
    ECDSA_SIG_free(es);

Done:
    return cose_signature;
}


/**
 * \brief Convert  COSE-serialized signature to DER-encoded signature.
 *
 * \param[in] key_len         Size of the key in bytes -- governs sig size.
 * \param[in] cose_signature  The COSE-serialized signature.
 * \param[in] buffer          Place to write DER-format signature.
 * \param[out] der_signature  The returned DER-encoded signature
 *
 * \return one of the \ref t_cose_err_t error codes.
 *
 * The serialized format is defined by COSE in RFC 8152 section
 * 8.1. The signature which consist of two integers, r and s,
 * are simply zero padded to the nearest byte length and
 * concatenated.
 *
 * OpenSSL has a preference for DER-encoded signatures.
 *
 * This uses an ECDSA_SIG as an intermediary to convert
 * between the two.
 */
static enum t_cose_err_t
signature_cose_to_der(unsigned                key_len,
                      struct q_useful_buf_c   cose_signature,
                      struct q_useful_buf     buffer,
                      struct q_useful_buf_c  *der_signature)
{
    enum t_cose_err_t return_value;
    BIGNUM           *signature_r_bn = NULL;
    BIGNUM           *signature_s_bn = NULL;
    int               ossl_result;
    ECDSA_SIG        *signature;
    unsigned char    *der_signature_ptr;
    int               der_signature_len;

    /* Check the signature length against expected */
    if(cose_signature.len != key_len * 2) {
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    }

    /* Put the r and the s from the signature into big numbers */
    signature_r_bn = BN_bin2bn(cose_signature.ptr, (int)key_len, NULL);
    if(signature_r_bn == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    signature_s_bn = BN_bin2bn(((const uint8_t *)cose_signature.ptr)+key_len,
                                    (int)key_len,
                                    NULL);
    if(signature_s_bn == NULL) {
        BN_free(signature_r_bn);
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Put the signature bytes into an ECDSA_SIG */
    signature = ECDSA_SIG_new();
    if(signature == NULL) {
        /* Don't leak memory in error condition */
        BN_free(signature_r_bn);
        BN_free(signature_s_bn);
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Put the r and s bignums into an ECDSA_SIG. Freeing
     * ossl_sig_to_verify will now free r and s.
     */
    ossl_result = ECDSA_SIG_set0(signature,
                                 signature_r_bn,
                                 signature_s_bn);
    if(ossl_result != 1) {
        BN_free(signature_r_bn);
        BN_free(signature_s_bn);
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Now output the ECDSA_SIG structure in DER format.
     *
     * Code safety is the priority here.  i2d_ECDSA_SIG() has two
     * output buffer modes, one where it just writes to the buffer
     * given and the other were it allocates memory.  It would be
     * better to avoid the allocation, but the copy mode is not safe
     * because you can't give it a buffer length. This is bad stuff
     * from last century.
     *
     * So the allocation mode is used on the presumption that it is
     * safe and correct even though there is more copying and memory
     * use.
     */
    der_signature_ptr = NULL;
    der_signature_len = i2d_ECDSA_SIG(signature, &der_signature_ptr);
    ECDSA_SIG_free(signature);
    if(der_signature_len < 0) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    *der_signature = q_useful_buf_copy_ptr(buffer,
                                           der_signature_ptr,
                                           (size_t)der_signature_len);
    if(q_useful_buf_c_is_null_or_empty(*der_signature)) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    OPENSSL_free(der_signature_ptr);

    return_value = T_COSE_SUCCESS;

Done:
    /* All the memory frees happen along the way in the code above. */
    return return_value;
}


/**
 * \brief Common checks and conversions for signing and verification key.
 *
 * \param[in] t_cose_key                 The key to check and convert.
 * \param[out] return_ossl_ec_key        The OpenSSL key in memory.
 * \param[out] return_key_size_in_bytes  How big the key is.
 *
 * \return Error or \ref T_COSE_SUCCESS.
 *
 * It pulls the OpenSSL key out of \c t_cose_key and checks
 * it and figures out the number of bytes in the key rounded up. This
 * is also the size of r and s in the signature.
 */
static enum t_cose_err_t
key_convert_and_size(struct t_cose_key  t_cose_key,
                     EVP_PKEY         **return_ossl_ec_key,
                     unsigned          *return_key_size_in_bytes)
{
    enum t_cose_err_t  return_value;
    int                key_len_bits; /* type unsigned is conscious choice */
    unsigned           key_len_bytes; /* type unsigned is conscious choice */
    EVP_PKEY          *ossl_ec_key;

    /* Check the signing key and get it out of the union */
    if(t_cose_key.crypto_lib != T_COSE_CRYPTO_LIB_OPENSSL) {
        return_value = T_COSE_ERR_INCORRECT_KEY_FOR_LIB;
        goto Done;
    }
    if(t_cose_key.k.key_ptr == NULL) {
        return_value = T_COSE_ERR_EMPTY_KEY;
        goto Done;
    }
    ossl_ec_key = (EVP_PKEY *)t_cose_key.k.key_ptr;

    key_len_bits = EVP_PKEY_bits(ossl_ec_key);

    /* Calculation of size per RFC 8152 section 8.1 -- round up to
     * number of bytes. */
    key_len_bytes = (unsigned)key_len_bits / 8;
    if(key_len_bits % 8) {
        key_len_bytes++;
    }

    *return_key_size_in_bytes = key_len_bytes;
    *return_ossl_ec_key = ossl_ec_key;

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}


/*
 * Public Interface. See documentation in t_cose_crypto.h
 */
enum t_cose_err_t t_cose_crypto_sig_size(int32_t           cose_algorithm_id,
                                         struct t_cose_key signing_key,
                                         size_t           *sig_size)
{
    enum t_cose_err_t return_value;
    unsigned          key_len_bytes;
    EVP_PKEY         *signing_key_evp; /* Unused */

    if(!t_cose_algorithm_is_ecdsa(cose_algorithm_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    return_value = key_convert_and_size(signing_key, &signing_key_evp, &key_len_bytes);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* Double because signature is made of up r and s values */
    *sig_size = key_len_bytes * 2;

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_sign(const int32_t                cose_algorithm_id,
                   const struct t_cose_key      signing_key,
                   const struct q_useful_buf_c  hash_to_sign,
                   const struct q_useful_buf    signature_buffer,
                   struct q_useful_buf_c       *signature)
{
    /* This is the overhead for the DER encoding of an EC signature as
     * described by ECDSA-Sig-Value in RFC 3279.  It is at max 3 * (1
     * type byte and 2 length bytes) + 2 zero pad bytes = 11
     * bytes. We make it 16 to have a little extra. It is expected that
     * EVP_PKEY_sign() will not over write the buffer so there will
     * be no security problem if this is too short. */
    #define DER_SIG_ENCODE_OVER_HEAD 16

    enum t_cose_err_t      return_value;
    EVP_PKEY_CTX          *sign_context;
    EVP_PKEY              *signing_key_evp;
    int                    ossl_result;
    unsigned               key_size_bytes;
    MakeUsefulBufOnStack(  der_format_signature, T_COSE_MAX_SIG_SIZE + DER_SIG_ENCODE_OVER_HEAD);

    /* This implementation supports only ECDSA so far. The
     * interface allows it to support other, but none are implemented.
     *
     * This implementation works for different key lengths and
     * curves. That is, the curve and key length is associated with
     * the signing_key passed in, not the cose_algorithm_id This
     * check looks for ECDSA signing as indicated by COSE and rejects
     * what is not since it only supports ECDSA.
     */
    if(!t_cose_algorithm_is_ecdsa(cose_algorithm_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done2;
    }

    /* Pull the pointer to the OpenSSL-format EVP_PKEY out of the
     * t_cose key structure and get the key size. */
    return_value = key_convert_and_size(signing_key, &signing_key_evp, &key_size_bytes);
    if(return_value != T_COSE_SUCCESS) {
        goto Done2;
    }

    /* Create and initialize the OpenSSL EVP_PKEY_CTX that is the
     * signing context. */
    sign_context = EVP_PKEY_CTX_new(signing_key_evp, NULL);
    if(sign_context == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }
    ossl_result = EVP_PKEY_sign_init(sign_context);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Actually do the signature operation.  */
    ossl_result = EVP_PKEY_sign(sign_context,
                                der_format_signature.ptr, &der_format_signature.len,
                                hash_to_sign.ptr, hash_to_sign.len);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }


    /* The signature produced by OpenSSL is DER-encoded. That encoding
     * has to be removed and turned into the serialization format used
     * by COSE. It is unfortunate that the OpenSSL APIs that create
     * signatures that are not in DER-format are slated for
     * deprecation.
     */
    *signature = signature_der_to_cose((unsigned)key_size_bytes,
                                       q_usefulbuf_const(der_format_signature),
                                       signature_buffer);
    if(q_useful_buf_c_is_null(*signature)) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Everything succeeded */
    return_value = T_COSE_SUCCESS;

Done:
    /* This checks for NULL before free, so it is not
     * necessary to check for NULL here.
     */
    EVP_PKEY_CTX_free(sign_context);

Done2:
    return return_value;
}



/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_verify(const int32_t                cose_algorithm_id,
                     const struct t_cose_key      verification_key,
                     const struct q_useful_buf_c  kid,
                     const struct q_useful_buf_c  hash_to_verify,
                     const struct q_useful_buf_c  cose_signature)
{
    int                    ossl_result;
    enum t_cose_err_t      return_value;
    EVP_PKEY_CTX          *verify_context = NULL;
    EVP_PKEY              *verification_key_evp;
    unsigned               key_size;
    MakeUsefulBufOnStack(  der_format_buffer, T_COSE_MAX_SIG_SIZE + DER_SIG_ENCODE_OVER_HEAD);
    struct q_useful_buf_c  der_format_signature;

    /* This implementation doesn't use any key store with the ability
     * to look up a key based on kid. */
    (void)kid;

    if(!t_cose_algorithm_is_ecdsa(cose_algorithm_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    /* Get the verification key in an EVP_PKEY structure which is what
     * is needed for sig verification. This also gets the key size
     * which is needed to convert the format of the signature. */
    return_value = key_convert_and_size(verification_key,
                                        &verification_key_evp,
                                        &key_size);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* Unfortunately the officially supported OpenSSL API supports
     * only DER-encoded signatures so the COSE format signatures must
     * be converted to DER for verification. This requires a temporary
     * buffer and a fair bit of work inside signature_cose_to_der().
     */
    return_value = signature_cose_to_der(key_size,
                                         cose_signature,
                                         der_format_buffer,
                                        &der_format_signature);
    if(return_value) {
        goto Done;
    }


    /* Create the verification context and set it up with the
     * necessary verification key.
     */
    verify_context = EVP_PKEY_CTX_new(verification_key_evp, NULL);
    if(verify_context == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    ossl_result = EVP_PKEY_verify_init(verify_context);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Actually do the signature verification */
    ossl_result =  EVP_PKEY_verify(verify_context,
                                   der_format_signature.ptr,
                                   der_format_signature.len,
                                   hash_to_verify.ptr,
                                   hash_to_verify.len);


    if(ossl_result == 0) {
        /* The operation succeeded, but the signature doesn't match */
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    } else if (ossl_result != 1) {
        /* Failed before even trying to verify the signature */
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Everything succeeded */
    return_value = T_COSE_SUCCESS;

Done:
    EVP_PKEY_CTX_free(verify_context);

    return return_value;
}




/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                         int32_t                    cose_hash_alg_id)
{
    int           ossl_result;
    int           nid;
    const EVP_MD *message_digest;

    switch(cose_hash_alg_id) {

    case COSE_ALGORITHM_SHA_256:
        nid = NID_sha256;
        break;

#ifndef T_COSE_DISABLE_ES384
    case COSE_ALGORITHM_SHA_384:
        nid = NID_sha384;
        break;
#endif

#ifndef T_COSE_DISABLE_ES512
    case COSE_ALGORITHM_SHA_512:
        nid = NID_sha512;
        break;
#endif

    default:
        return T_COSE_ERR_UNSUPPORTED_HASH;
    }

    message_digest = EVP_get_digestbynid(nid);
    if(message_digest == NULL){
        return T_COSE_ERR_UNSUPPORTED_HASH;
    }

    hash_ctx->evp_ctx = EVP_MD_CTX_new();
    if(hash_ctx->evp_ctx == NULL) {
        return T_COSE_ERR_INSUFFICIENT_MEMORY;
    }

    ossl_result = EVP_DigestInit_ex(hash_ctx->evp_ctx, message_digest, NULL);
    if(ossl_result == 0) {
        EVP_MD_CTX_free(hash_ctx->evp_ctx);
        return T_COSE_ERR_HASH_GENERAL_FAIL;
    }

    hash_ctx->cose_hash_alg_id = cose_hash_alg_id;
    hash_ctx->update_error = 1; /* 1 is success in OpenSSL */

    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
void
t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf_c data_to_hash)
{
    if(hash_ctx->update_error) { /* 1 is no error, 0 means error for OpenSSL */
        if(data_to_hash.ptr) {
            hash_ctx->update_error = EVP_DigestUpdate(hash_ctx->evp_ctx,
                                                      data_to_hash.ptr,
                                                      data_to_hash.len);
        }
    }
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf        buffer_to_hold_result,
                          struct q_useful_buf_c     *hash_result)
{
    int          ossl_result;
    unsigned int hash_result_len;

    if(!hash_ctx->update_error) {
        return T_COSE_ERR_HASH_GENERAL_FAIL;
    }

    hash_result_len = (unsigned int)buffer_to_hold_result.len;
    ossl_result = EVP_DigestFinal_ex(hash_ctx->evp_ctx,
                                     buffer_to_hold_result.ptr,
                                     &hash_result_len);

    *hash_result = (UsefulBufC){buffer_to_hold_result.ptr, hash_result_len};

    EVP_MD_CTX_free(hash_ctx->evp_ctx);

    /* OpenSSL returns 1 for success, not 0 */
    return ossl_result ? T_COSE_SUCCESS : T_COSE_ERR_HASH_GENERAL_FAIL;
}

