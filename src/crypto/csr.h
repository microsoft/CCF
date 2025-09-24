// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/pem.h"

#include <openssl/bio.h>

namespace ccf::crypto
{
  /** Extracts the public key from a certificate signing request (CSR).
   * @param signing_request CSR to extract the public key from
   * @return extracted public key
   */
  inline Pem public_key_pem_from_csr(const Pem& signing_request)
  {
    X509* icrt = NULL;
    OpenSSL::Unique_BIO mem(signing_request);
    OpenSSL::Unique_X509_REQ csr(mem);
    OpenSSL::Unique_BIO buf;

    EVP_PKEY* req_pubkey = X509_REQ_get0_pubkey(csr);

    OpenSSL::CHECK1(PEM_write_bio_PUBKEY(buf, req_pubkey));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
  }
}