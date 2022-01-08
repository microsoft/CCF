// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "cert.h"
#include "crypto/base64.h"
#include "crypto/entropy.h"
#include "ds/logger.h"
#include "tls/openssl/tls.h"

#include <memory>
#include <openssl/bio.h>
#include <openssl/ssl.h>

using namespace crypto;

namespace tls
{
  class Context
  {
  protected:
    crypto::OpenSSL::Unique_SSL_CTX cfg;
    crypto::OpenSSL::Unique_SSL ssl;

  public:
    Context(bool client, bool dtls) :
      cfg(
        dtls ? (client ? DTLS_client_method() : DTLS_server_method()) :
               (client ? TLS_client_method() : TLS_server_method())),
      ssl(cfg)
    {
      // Require at least TLS 1.2, support up to 1.3
      SSL_CTX_set_min_proto_version(
        cfg, dtls ? DTLS1_2_VERSION : TLS1_2_VERSION);
      SSL_set_min_proto_version(ssl, dtls ? DTLS1_2_VERSION : TLS1_2_VERSION);

      // Set cipher for TLS 1.2 (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
      SSL_CTX_set_cipher_list(cfg, "ECDHE-ECDSA-AES128-GCM-SHA256");
      SSL_set_cipher_list(ssl, "ECDHE-ECDSA-AES128-GCM-SHA256");

      // Set cipher for TLS 1.3 (same as above)
      SSL_CTX_set_ciphersuites(cfg, "TLS_AES_128_GCM_SHA256");
      SSL_set_ciphersuites(ssl, "TLS_AES_128_GCM_SHA256");

      // Initialise connection
      if (client)
        SSL_set_connect_state(ssl);
      else
        SSL_set_accept_state(ssl);
    }

    virtual ~Context() {}

    void set_bio(
      void* cb_obj,
      BIO_callback_fn_ex send,
      BIO_callback_fn_ex recv,
      BIO_callback_fn_ex dbg)
    {
      // Read/Write BIOs will be used by TLS
      BIO* rbio = BIO_new(BIO_s_mem());
      BIO_set_mem_eof_return(rbio, -1);
      BIO_set_callback_arg(rbio, (char*)cb_obj);
      BIO_set_callback_ex(rbio, recv);
      SSL_set0_rbio(ssl, rbio);

      BIO* wbio = BIO_new(BIO_s_mem());
      BIO_set_mem_eof_return(wbio, -1);
      BIO_set_callback_arg(wbio, (char*)cb_obj);
      BIO_set_callback_ex(wbio, send);
      SSL_set0_wbio(ssl, wbio);

      // We don't need debug callbacks and the other two already have
      // enough debug messages. Once we get rid of MbedTLS, we can remove this
      // argument.
      (void)dbg;
    }

    int handshake()
    {
      if (SSL_is_init_finished(ssl))
        return 0;

      int rc = SSL_do_handshake(ssl);
      // Success in OpenSSL is 1, MBed is 0
      if (rc > 0)
      {
        LOG_TRACE_FMT("Context::handshake() : Success");
        return 0;
      }

      // Want read/write needs special return
      if (SSL_want_read(ssl))
      {
        return TLS_ERR_WANT_READ;
      }
      else if (SSL_want_write(ssl))
      {
        return TLS_ERR_WANT_WRITE;
      }

      // So does x509 validation
      if (verify_result() != 0)
      {
        return TLS_ERR_X509_VERIFY;
      }

      // Everything else falls here.
      LOG_TRACE_FMT("Context::handshake() : Error code {}", rc);

      // As an MBedTLS emulation, we return negative for errors.
      return -SSL_get_error(ssl, rc);
    }

    int read(uint8_t* buf, size_t len)
    {
      if (len == 0)
        return 0;
      size_t readbytes = 0;
      int rc = SSL_read_ex(ssl, buf, len, &readbytes);
      if (rc > 0)
      {
        return readbytes;
      }
      if (SSL_want_read(ssl))
      {
        return TLS_ERR_WANT_READ;
      }

      // Everything else falls here.
      LOG_TRACE_FMT("Context::read() : Error code {}", rc);

      // As an MBedTLS emulation, we return negative for errors.
      return -SSL_get_error(ssl, rc);
    }

    int write(const uint8_t* buf, size_t len)
    {
      if (len == 0)
        return 0;
      size_t written = 0;
      int rc = SSL_write_ex(ssl, buf, len, &written);
      if (rc > 0)
      {
        return written;
      }
      if (SSL_want_write(ssl))
      {
        return TLS_ERR_WANT_WRITE;
      }

      // Everything else falls here.
      LOG_TRACE_FMT("Context::write() : Error code {}", rc);

      // As an MBedTLS emulation, we return negative for errors.
      return -SSL_get_error(ssl, rc);
    }

    int close()
    {
      LOG_TRACE_FMT("Context::close() : Shutdown");
      return SSL_shutdown(ssl);
    }

    // This is a hack to make it work like MBedTLS (with negative return
    // values as error), and to differentiate in get_verify_error if the error
    // is because we don't have a peer cert or something else.
    // We may find that this is unnecessary (alongside all of the error messages
    // in get_verify_error), but that's a cleanup that will need a bit more
    // research.
#define TLS_ERR_X509_NO_PEER_CERT -1
#define TLS_ERR_X509_INVALID_RESULT -2

    int verify_result()
    {
      if (SSL_get_verify_result(ssl) == X509_V_OK)
      {
        // Verify can return OK when no certificate is presented
        // We want that to be an error
        X509* cert = SSL_get_peer_certificate(ssl);
        if (cert)
        {
          X509_free(cert);
          return 0;
        }
        else
        {
          return TLS_ERR_X509_NO_PEER_CERT;
        }
      }
      return TLS_ERR_X509_INVALID_RESULT;
    }

    void get_verify_error(char* buf, size_t size)
    {
      int rc = verify_result();
      if (rc == TLS_ERR_X509_NO_PEER_CERT)
      {
        memcpy(buf, "Certificate verify error: No peer certificate", size);
        return;
      }

      switch (rc)
      {
        case X509_V_ERR_UNSPECIFIED:
          memcpy(buf, "Unspecified error; should not happen.", size);
          return;

        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
          memcpy(
            buf,
            "The issuer certificate of a looked up certificate could not be "
            "found. This normally means the list of trusted certificates is "
            "not complete.",
            size);
          return;

        case X509_V_ERR_UNABLE_TO_GET_CRL:
          memcpy(buf, "The CRL of a certificate could not be found.", size);
          return;

        case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
          memcpy(
            buf,
            "The certificate signature could not be decrypted. This means that "
            "the actual signature value could not be determined rather than it "
            "not matching the expected value, this is only meaningful for RSA "
            "keys.",
            size);
          return;

        case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
          memcpy(
            buf,
            "The CRL signature could not be decrypted: this means that the "
            "actual signature value could not be determined rather than it not "
            "matching the expected value. Unused.",
            size);
          return;

        case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
          memcpy(
            buf,
            "The public key in the certificate SubjectPublicKeyInfo could not "
            "be read.",
            size);
          return;

        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
          memcpy(buf, "The signature of the certificate is invalid.", size);
          return;

        case X509_V_ERR_CRL_SIGNATURE_FAILURE:
          memcpy(buf, "The signature of the certificate is invalid.", size);
          return;

        case X509_V_ERR_CERT_NOT_YET_VALID:
          memcpy(
            buf,
            "The certificate is not yet valid: the notBefore date is after the "
            "current time.",
            size);
          return;

        case X509_V_ERR_CERT_HAS_EXPIRED:
          memcpy(
            buf,
            "The certificate has expired: that is the notAfter date is before "
            "the current time.",
            size);
          return;

        case X509_V_ERR_CRL_NOT_YET_VALID:
          memcpy(buf, "The CRL is not yet valid.", size);
          return;

        case X509_V_ERR_CRL_HAS_EXPIRED:
          memcpy(buf, "The CRL has expired.", size);
          return;

        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
          memcpy(
            buf,
            "The certificate notBefore field contains an invalid time.",
            size);
          return;

        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
          memcpy(
            buf,
            "The certificate notAfter field contains an invalid time.",
            size);
          return;

        case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
          memcpy(
            buf, "The CRL lastUpdate field contains an invalid time.", size);
          return;

        case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
          memcpy(
            buf, "The CRL nextUpdate field contains an invalid time.", size);
          return;

        case X509_V_ERR_OUT_OF_MEM:
          memcpy(
            buf,
            "An error occurred trying to allocate memory. This should never "
            "happen.",
            size);
          return;

        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
          memcpy(
            buf,
            "The passed certificate is self-signed and the same certificate "
            "cannot be found in the list of trusted certificates.",
            size);
          return;

        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
          memcpy(
            buf,
            "The certificate chain could be built up using the untrusted "
            "certificates but the root could not be found locally.",
            size);
          return;

        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
          memcpy(
            buf,
            "The issuer certificate could not be found: this occurs if the "
            "issuer certificate of an untrusted certificate cannot be found.",
            size);
          return;

        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
          memcpy(
            buf,
            "No signatures could be verified because the chain contains only "
            "one certificate and it is not self signed.",
            size);
          return;

        case X509_V_ERR_CERT_CHAIN_TOO_LONG:
          memcpy(
            buf,
            "The certificate chain length is greater than the supplied maximum "
            "depth. Unused.",
            size);
          return;

        case X509_V_ERR_CERT_REVOKED:
          memcpy(buf, "The certificate has been revoked.", size);
          return;

        case X509_V_ERR_INVALID_CA:
          memcpy(
            buf,
            "A CA certificate is invalid. Either it is not a CA or its "
            "extensions are not consistent with the supplied purpose.",
            size);
          return;

        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
          memcpy(
            buf,
            "The basicConstraints pathlength parameter has been exceeded.",
            size);
          return;

        case X509_V_ERR_INVALID_PURPOSE:
          memcpy(
            buf,
            "The supplied certificate cannot be used for the specified "
            "purpose.",
            size);
          return;

        case X509_V_ERR_CERT_UNTRUSTED:
          memcpy(
            buf,
            "The root CA is not marked as trusted for the specified purpose.",
            size);
          return;

        case X509_V_ERR_CERT_REJECTED:
          memcpy(
            buf,
            "The root CA is marked to reject the specified purpose.",
            size);
          return;

        case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
          memcpy(
            buf,
            "Not used as of OpenSSL 1.1.0 as a result of the deprecation of "
            "the -issuer_checks option.",
            size);
          return;

        case X509_V_ERR_AKID_SKID_MISMATCH:
          memcpy(
            buf,
            "Not used as of OpenSSL 1.1.0 as a result of the deprecation of "
            "the -issuer_checks option.",
            size);
          return;

        case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
          memcpy(
            buf,
            "Not used as of OpenSSL 1.1.0 as a result of the deprecation of "
            "the -issuer_checks option.",
            size);
          return;

        case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
          memcpy(
            buf,
            "Not used as of OpenSSL 1.1.0 as a result of the deprecation of "
            "the -issuer_checks option.",
            size);
          return;

        case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
          memcpy(buf, "Unable to get CRL issuer certificate.", size);
          return;

        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
          memcpy(buf, "Unhandled critical extension.", size);
          return;

        case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
          memcpy(buf, "Key usage does not include CRL signing.", size);
          return;

        case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
          memcpy(buf, "Unhandled critical CRL extension.", size);
          return;

        case X509_V_ERR_INVALID_NON_CA:
          memcpy(buf, "Invalid non-CA certificate has CA markings.", size);
          return;

        case X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
          memcpy(buf, "Proxy path length constraint exceeded.", size);
          return;

        case X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
          memcpy(buf, "Key usage does not include digital signature.", size);
          return;

        case X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
          memcpy(
            buf,
            "Proxy certificates not allowed, please use -allow_proxy_certs.",
            size);
          return;

        case X509_V_ERR_INVALID_EXTENSION:
          memcpy(buf, "Invalid or inconsistent certificate extension.", size);
          return;

        case X509_V_ERR_INVALID_POLICY_EXTENSION:
          memcpy(
            buf, "Invalid or inconsistent certificate policy extension.", size);
          return;

        case X509_V_ERR_NO_EXPLICIT_POLICY:
          memcpy(buf, "No explicit policy.", size);
          return;

        case X509_V_ERR_DIFFERENT_CRL_SCOPE:
          memcpy(buf, "Different CRL scope.", size);
          return;

        case X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE:
          memcpy(buf, "Unsupported extension feature.", size);
          return;

        case X509_V_ERR_UNNESTED_RESOURCE:
          memcpy(
            buf, "RFC 3779 resource not subset of parent's resources.", size);
          return;

        case X509_V_ERR_PERMITTED_VIOLATION:
          memcpy(buf, "Permitted subtree violation.", size);
          return;

        case X509_V_ERR_EXCLUDED_VIOLATION:
          memcpy(buf, "Excluded subtree violation.", size);
          return;

        case X509_V_ERR_SUBTREE_MINMAX:
          memcpy(
            buf, "Name constraints minimum and maximum not supported.", size);
          return;

        case X509_V_ERR_APPLICATION_VERIFICATION:
          memcpy(buf, "Application verification failure. Unused.", size);
          return;

        case X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:
          memcpy(buf, "Unsupported name constraint type.", size);
          return;

        case X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX:
          memcpy(buf, "Unsupported or invalid name constraint syntax.", size);
          return;

        case X509_V_ERR_UNSUPPORTED_NAME_SYNTAX:
          memcpy(buf, "Unsupported or invalid name syntax.", size);
          return;

        case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
          memcpy(buf, "CRL path validation error.", size);
          return;

        case X509_V_ERR_PATH_LOOP:
          memcpy(buf, "Path loop.", size);
          return;

        case X509_V_ERR_SUITE_B_INVALID_VERSION:
          memcpy(buf, "Suite B: certificate version invalid.", size);
          return;

        case X509_V_ERR_SUITE_B_INVALID_ALGORITHM:
          memcpy(buf, "Suite B: invalid public key algorithm.", size);
          return;

        case X509_V_ERR_SUITE_B_INVALID_CURVE:
          memcpy(buf, "Suite B: invalid ECC curve.", size);
          return;

        case X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM:
          memcpy(buf, "Suite B: invalid signature algorithm.", size);
          return;

        case X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED:
          memcpy(buf, "Suite B: curve not allowed for this LOS.", size);
          return;

        case X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256:
          memcpy(buf, "Suite B: cannot sign P-384 with P-256.", size);
          return;

        case X509_V_ERR_HOSTNAME_MISMATCH:
          memcpy(buf, "Hostname mismatch.", size);
          return;

        case X509_V_ERR_EMAIL_MISMATCH:
          memcpy(buf, "Email address mismatch.", size);
          return;

        case X509_V_ERR_IP_ADDRESS_MISMATCH:
          memcpy(buf, "IP address mismatch.", size);
          return;

        case X509_V_ERR_DANE_NO_MATCH:
          memcpy(
            buf,
            "DANE TLSA authentication is enabled, but no TLSA records matched "
            "the certificate chain. This error is only possible in "
            "s_client(1).",
            size);
          return;

        case X509_V_ERR_EE_KEY_TOO_SMALL:
          memcpy(buf, "EE certificate key too weak.", size);
          return;

        case X509_V_ERR_INVALID_CALL:
          memcpy(buf, "nvalid certificate verification context.", size);
          return;

        case X509_V_ERR_STORE_LOOKUP:
          memcpy(buf, "Issuer certificate lookup error.", size);
          return;

        case X509_V_ERR_NO_VALID_SCTS:
          memcpy(
            buf,
            "Certificate Transparency required, but no valid SCTs found.",
            size);
          return;

        case X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION:
          memcpy(buf, "Proxy subject name violation.", size);
          return;

        case X509_V_ERR_OCSP_VERIFY_NEEDED:
          memcpy(
            buf,
            "Returned by the verify callback to indicate an OCSP verification "
            "is needed.",
            size);
          return;

        case X509_V_ERR_OCSP_VERIFY_FAILED:
          memcpy(
            buf,
            "Returned by the verify callback to indicate OCSP verification "
            "failed.",
            size);
          return;

        case X509_V_ERR_OCSP_CERT_UNKNOWN:
          memcpy(
            buf,
            "Returned by the verify callback to indicate that the certificate "
            "is not recognized by the OCSP responder.",
            size);
          return;
      }
    }

    virtual std::string host()
    {
      return {};
    }

    std::vector<uint8_t> peer_cert()
    {
      // Get the certificate into a BIO as DER
      X509* cert = SSL_get_peer_certificate(ssl);
      if (!cert)
      {
        LOG_TRACE_FMT("Empty peer cert");
        return {};
      }
      BIO* bio = BIO_new(BIO_s_mem());
      if (!i2d_X509_bio(bio, cert))
      {
        LOG_TRACE_FMT("Can't convert X509 to DER");
        X509_free(cert);
        return {};
      }
      X509_free(cert);

      // Get the total length of the DER representation
      auto len = BIO_get_mem_data(bio, nullptr);
      if (!len)
      {
        LOG_TRACE_FMT("Null X509 peer cert");
        BIO_free(bio);
        return {};
      }

      // Get the BIO memory pointer
      BUF_MEM* ptr;
      if (!BIO_get_mem_ptr(bio, &ptr))
      {
        LOG_TRACE_FMT("Invalid X509 peer cert");
        return {};
      }
      BIO_set_close(bio, BIO_NOCLOSE); // Need to free ptr later
      BIO_free(bio);

      // Return its contents as a vector
      auto ret = std::vector<uint8_t>(ptr->data, ptr->data + len);
      free(ptr);
      return ret;
    }
  };
}
