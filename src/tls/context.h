// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "cert.h"
#include "crypto/base64.h"
#include "crypto/entropy.h"
#include "ds/logger.h"
#include "tls/tls.h"

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

      // Disable renegotiation to avoid DoS
      SSL_CTX_set_options(
        cfg,
        SSL_OP_CIPHER_SERVER_PREFERENCE |
          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
          SSL_OP_NO_RENEGOTIATION);
      SSL_set_options(
        ssl,
        SSL_OP_CIPHER_SERVER_PREFERENCE |
          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
          SSL_OP_NO_RENEGOTIATION);

      // Set cipher for TLS 1.2 (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
      SSL_CTX_set_cipher_list(
        cfg,
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256");
      SSL_set_cipher_list(
        ssl,
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256");

      // Set cipher for TLS 1.3 (same as above)
      SSL_CTX_set_ciphersuites(
        cfg,
        "TLS_AES_256_GCM_SHA384:"
        "TLS_AES_128_GCM_SHA256");
      SSL_set_ciphersuites(
        ssl,
        "TLS_AES_256_GCM_SHA384:"
        "TLS_AES_128_GCM_SHA256");

      // Restrict the curves to approved ones
      SSL_CTX_set1_curves_list(cfg, "P-521:P-384");
      SSL_set1_curves_list(ssl, "P-521:P-384");

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

    std::string get_verify_error()
    {
      int rc = verify_result();
      if (rc == TLS_ERR_X509_NO_PEER_CERT)
      {
        return "Certificate verify error: No peer certificate";
      }

      switch (rc)
      {
        case X509_V_ERR_UNSPECIFIED:
          return "Unspecified error; should not happen.";

        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
          return "The issuer certificate of a looked up certificate could not "
                 "be found. This normally means the list of trusted "
                 "certificates is not complete.";

        case X509_V_ERR_UNABLE_TO_GET_CRL:
          return "The CRL of a certificate could not be found.";

        case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
          return "The certificate signature could not be decrypted. This means "
                 "that the actual signature value could not be determined "
                 "rather than it not matching the expected value";

        case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
          return "The CRL signature could not be decrypted: this means that "
                 "the actual signature value could not be determined rather "
                 "than it not matching the expected value. Unused.";

        case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
          return "The public key in the certificate SubjectPublicKeyInfo could "
                 "not be read.";

        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
          return "The signature of the certificate is invalid.";

        case X509_V_ERR_CRL_SIGNATURE_FAILURE:
          return "The signature of the certificate is invalid.";

        case X509_V_ERR_CERT_NOT_YET_VALID:
          return "The certificate is not yet valid: the notBefore date is "
                 "after the current time.";

        case X509_V_ERR_CERT_HAS_EXPIRED:
          return "The certificate has expired: that is the notAfter date is "
                 "before the current time.";

        case X509_V_ERR_CRL_NOT_YET_VALID:
          return "The CRL is not yet valid.";

        case X509_V_ERR_CRL_HAS_EXPIRED:
          return "The CRL has expired.";

        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
          return "The certificate notBefore field contains an invalid time.";

        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
          return "The certificate notAfter field contains an invalid time.";

        case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
          return "The CRL lastUpdate field contains an invalid time.";

        case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
          return "The CRL nextUpdate field contains an invalid time.";

        case X509_V_ERR_OUT_OF_MEM:
          return "An error occurred trying to allocate memory. This should "
                 "never happen.";

        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
          return "The passed certificate is self-signed and the same "
                 "certificate cannot be found in the list of trusted "
                 "certificates.";

        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
          return "The certificate chain could be built up using the untrusted "
                 "certificates but the root could not be found locally.";

        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
          return "The issuer certificate could not be found: this occurs if "
                 "the issuer certificate of an untrusted certificate cannot be "
                 "found.";

        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
          return "No signatures could be verified because the chain contains "
                 "only one certificate and it is not self signed.";

        case X509_V_ERR_CERT_CHAIN_TOO_LONG:
          return "The certificate chain length is greater than the supplied "
                 "maximum depth. Unused.";

        case X509_V_ERR_CERT_REVOKED:
          return "The certificate has been revoked.";

        case X509_V_ERR_INVALID_CA:
          return "A CA certificate is invalid. Either it is not a CA or its "
                 "extensions are not consistent with the supplied purpose.";

        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
          return "The basicConstraints pathlength parameter has been exceeded.";

        case X509_V_ERR_INVALID_PURPOSE:
          return "The supplied certificate cannot be used for the specified "
                 "purpose.";

        case X509_V_ERR_CERT_UNTRUSTED:
          return "The root CA is not marked as trusted for the specified "
                 "purpose.";

        case X509_V_ERR_CERT_REJECTED:
          return "The root CA is marked to reject the specified purpose.";

        case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
          return "Not used as of OpenSSL 1.1.0 as a result of the deprecation "
                 "of the -issuer_checks option.";

        case X509_V_ERR_AKID_SKID_MISMATCH:
          return "Not used as of OpenSSL 1.1.0 as a result of the deprecation "
                 "of the -issuer_checks option.";

        case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
          return "Not used as of OpenSSL 1.1.0 as a result of the deprecation "
                 "of the -issuer_checks option.";

        case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
          return "Not used as of OpenSSL 1.1.0 as a result of the deprecation "
                 "of the -issuer_checks option.";

        case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
          return "Unable to get CRL issuer certificate.";

        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
          return "Unhandled critical extension.";

        case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
          return "Key usage does not include CRL signing.";

        case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
          return "Unhandled critical CRL extension.";

        case X509_V_ERR_INVALID_NON_CA:
          return "Invalid non-CA certificate has CA markings.";

        case X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
          return "Proxy path length constraint exceeded.";

        case X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
          return "Key usage does not include digital signature.";

        case X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
          return "Proxy certificates not allowed";

        case X509_V_ERR_INVALID_EXTENSION:
          return "Invalid or inconsistent certificate extension.";

        case X509_V_ERR_INVALID_POLICY_EXTENSION:
          return "Invalid or inconsistent certificate policy extension.";

        case X509_V_ERR_NO_EXPLICIT_POLICY:
          return "No explicit policy.";

        case X509_V_ERR_DIFFERENT_CRL_SCOPE:
          return "Different CRL scope.";

        case X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE:
          return "Unsupported extension feature.";

        case X509_V_ERR_UNNESTED_RESOURCE:
          return "RFC 3779 resource not subset of parent's resources.";

        case X509_V_ERR_PERMITTED_VIOLATION:
          return "Permitted subtree violation.";

        case X509_V_ERR_EXCLUDED_VIOLATION:
          return "Excluded subtree violation.";

        case X509_V_ERR_SUBTREE_MINMAX:
          return "Name constraints minimum and maximum not supported.";

        case X509_V_ERR_APPLICATION_VERIFICATION:
          return "Application verification failure. Unused.";

        case X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:
          return "Unsupported name constraint type.";

        case X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX:
          return "Unsupported or invalid name constraint syntax.";

        case X509_V_ERR_UNSUPPORTED_NAME_SYNTAX:
          return "Unsupported or invalid name syntax.";

        case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
          return "CRL path validation error.";

        case X509_V_ERR_PATH_LOOP:
          return "Path loop.";

        case X509_V_ERR_SUITE_B_INVALID_VERSION:
          return "Suite B: certificate version invalid.";

        case X509_V_ERR_SUITE_B_INVALID_ALGORITHM:
          return "Suite B: invalid public key algorithm.";

        case X509_V_ERR_SUITE_B_INVALID_CURVE:
          return "Suite B: invalid ECC curve.";

        case X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM:
          return "Suite B: invalid signature algorithm.";

        case X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED:
          return "Suite B: curve not allowed for this LOS.";

        case X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256:
          return "Suite B: cannot sign P-384 with P-256.";

        case X509_V_ERR_HOSTNAME_MISMATCH:
          return "Hostname mismatch.";

        case X509_V_ERR_EMAIL_MISMATCH:
          return "Email address mismatch.";

        case X509_V_ERR_IP_ADDRESS_MISMATCH:
          return "IP address mismatch.";

        case X509_V_ERR_DANE_NO_MATCH:
          return "DANE TLSA authentication is enabled";

        case X509_V_ERR_EE_KEY_TOO_SMALL:
          return "EE certificate key too weak.";

        case X509_V_ERR_INVALID_CALL:
          return "nvalid certificate verification context.";

        case X509_V_ERR_STORE_LOOKUP:
          return "Issuer certificate lookup error.";

        case X509_V_ERR_NO_VALID_SCTS:
          return "Certificate Transparency required";

        case X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION:
          return "Proxy subject name violation.";

        case X509_V_ERR_OCSP_VERIFY_NEEDED:
          return "Returned by the verify callback to indicate an OCSP "
                 "verification is needed.";

        case X509_V_ERR_OCSP_VERIFY_FAILED:
          return "Returned by the verify callback to indicate OCSP "
                 "verification failed.";

        case X509_V_ERR_OCSP_CERT_UNKNOWN:
          return "Returned by the verify callback to indicate that the "
                 "certificate is not recognized by the OCSP responder.";
      }
      return "";
    }

    virtual std::string host()
    {
      return {};
    }

    std::vector<uint8_t> peer_cert()
    {
      // Get the certificate into a BIO as DER
      crypto::OpenSSL::Unique_X509 cert(
        SSL_get_peer_certificate(ssl), /*check_null=*/false);
      if (!cert)
      {
        LOG_TRACE_FMT("Empty peer cert");
        return {};
      }
      crypto::OpenSSL::Unique_BIO bio;
      if (!i2d_X509_bio(bio, cert))
      {
        LOG_TRACE_FMT("Can't convert X509 to DER");
        return {};
      }

      // Get the total length of the DER representation
      auto len = BIO_get_mem_data(bio, nullptr);
      if (!len)
      {
        LOG_TRACE_FMT("Null X509 peer cert");
        return {};
      }

      // Get the BIO memory pointer
      BUF_MEM* ptr = nullptr;
      if (!BIO_get_mem_ptr(bio, &ptr))
      {
        LOG_TRACE_FMT("Invalid X509 peer cert");
        return {};
      }

      // Return its contents as a vector
      auto ret = std::vector<uint8_t>(ptr->data, ptr->data + len);
      return ret;
    }
  };
}
