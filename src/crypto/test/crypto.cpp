// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/base64.h"
#include "ccf/crypto/eddsa_key_pair.h"
#include "ccf/crypto/entropy.h"
#include "ccf/crypto/hmac.h"
#include "ccf/crypto/jwk.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/key_wrap.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/x509_time_fmt.h"
#include "crypto/certs.h"
#include "crypto/csr.h"
#include "crypto/openssl/cose_sign.h"
#include "crypto/openssl/cose_verifier.h"
#include "crypto/openssl/key_pair.h"
#include "crypto/openssl/rsa_key_pair.h"
#include "crypto/openssl/symmetric_key.h"
#include "crypto/openssl/verifier.h"
#include "crypto/openssl/x509_time.h"

#include <chrono>
#include <cstring>
#include <ctime>
#include <doctest/doctest.h>
#include <optional>
#include <qcbor/qcbor_spiffy_decode.h>
#include <span>
#include <t_cose/t_cose_sign1_sign.h>
#include <t_cose/t_cose_sign1_verify.h>

using namespace std;
using namespace ccf::crypto;

static const string contents_ =
  "Lorem ipsum dolor sit amet, consectetur adipiscing "
  "elit, sed do eiusmod tempor incididunt ut labore et"
  " dolore magna aliqua. Ut enim ad minim veniam, quis"
  " nostrud exercitation ullamco laboris nisi ut "
  "aliquip ex ea commodo consequat. Duis aute irure "
  "dolor in reprehenderit in voluptate velit esse "
  "cillum dolore eu fugiat nulla pariatur. Excepteur "
  "sint occaecat cupidatat non proident, sunt in culpa "
  "qui officia deserunt mollit anim id est laborum.";

vector<uint8_t> contents(contents_.begin(), contents_.end());

static const string nested_cert =
  "MIIV1zCCFL+"
  "gAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDDChodHRwczovL3NoYXJlZGV1czIuZXV"
  "zMi5hdHRlc3QuYXp1cmUubmV0MCIYDzIwMTkwNTAxMDAwMDAwWhgPMjA1MDEyMzEyMzU5NTlaMDM"
  "xMTAvBgNVBAMMKGh0dHBzOi8vc2hhcmVkZXVzMi5ldXMyLmF0dGVzdC5henVyZS5uZXQwggEiMA0"
  "GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDY0GsRB3BdTNXLan5JnuwGPFtV3iJMY0RAm78638L"
  "Q0LNcgNPoMwQB5VktKhZZxbqhdDzWH7JBa3D6MVb9I+"
  "AbgUZIvVSdU7xlqTzS2Gi9CTR1tkOj72Wyg6c59d89QvRP0CAe2omlSve0J/"
  "JFEt0LQyAXW0DKNlsyPxsd7ZmYn0YtMlPm/0TSLmXdLhZljna8zNlpWl/"
  "HD7T+zm1HNyg8aoisw6df/uS/mPuyKypko2rp8/7gwe8tv+1fIcKRboXNfyZSXDJE3ME/"
  "dHjFpcG/KTMkxoCIJb9iv9PHJx2ebCxNHuF7VDvyrXYqdiou9RWOD+/f39FYZJsWdo/"
  "VhfkfAgMBAAGjghLwMIIS7DAJBgNVHRMEAjAAMB0GA1UdDgQWBBRLSJIoQYE9YTEPZ30bgjdlv/"
  "RNDzAfBgNVHSMEGDAWgBRLSJIoQYE9YTEPZ30bgjdlv/"
  "RNDzCCEp0GCSsGAQQBgjdpAQSCEo4BAAAAAgAAAH4SAAAAAAAAAwACAAAAAAAKAA8Ak5pyM/"
  "ecTKmUCg2zlX8GBz6f+cAQUwPfmJD+H0OHgqMAAAAADg4QD///"
  "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAHAAAAAAAA"
  "AMG+d2W08VnHBjXWJzQgwpztMaXmeuK7Kha4P/"
  "IN14L3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB0ul+"
  "6IIVxz5nh9xWOZTagW7ts54B+749ql/"
  "ZKevZLgwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAnSkA919"
  "dcepZaKaCsfznfAwh2Hn98t7XPq5Jdg9cJrQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "AAyhAAABbJ695qIni/27w8wj0BRxIueJMn4SZTntdR7/"
  "e+s5ajJc+jMXwish9akKmwKqeRdyX3cDnkAjPvY0AjYi/"
  "39FZtwI3hoTxkyWE3Vpk8IdKJU+oomqS8snlNp+oT+"
  "ClCyILcP78X1k0xk5vi2OO44ktNBTyHIVWAKSSdxNj39TBxDg4QD///"
  "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFQAAAAAAAADnAAAAAAAA"
  "AB7AKOTzYYZbiudS8D7kBDlbIscxEdPw8/"
  "tDnGuibpX2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMT1d115ZQPpYTf3fGioKaAF"
  "asje1wFAsIGwlEkMV7/"
  "wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEACgAAAAAAAAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABvByKZT5Gm6A9i+"
  "eXoH22RqqvB4tf80tEosVAMAK0h0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaWdf+"
  "dceUZCkBvD8ZTZQDgzklLWu5NJKI+"
  "QZb3tC4f7ORUBfklfihcUZXLT3Uc4L8jaXnpDYbMplAIsUMueifCAAAAECAwQFBgcICQoLDA0ODx"
  "AREhMUFRYXGBkaGxwdHh8FAGIOAAAtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJRTlEQ0"
  "NCSm1nQXdJQkFnSVZBTkxaR05BSUVTOVN3QVA4ZGFocnlTN0daamVqTUFvR0NDcUdTTTQ5QkFNQw"
  "pNSEF4SWpBZ0JnTlZCQU1NR1VsdWRHVnNJRk5IV0NCUVEwc2dVR3hoZEdadmNtMGdRMEV4R2pBWU"
  "JnTlZCQW9NCkVVbHVkR1ZzSUVOdmNuQnZjbUYwYVc5dU1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRG"
  "JHRnlZVEVMTUFrR0ExVUUKQ0F3Q1EwRXhDekFKQmdOVkJBWVRBbFZUTUI0WERUSTBNRFF3TmpFMU"
  "5EZzFNVm9YRFRNeE1EUXdOakUxTkRnMQpNVm93Y0RFaU1DQUdBMVVFQXd3WlNXNTBaV3dnVTBkWU"
  "lGQkRTeUJEWlhKMGFXWnBZMkYwWlRFYU1CZ0dBMVVFCkNnd1JTVzUwWld3Z1EyOXljRzl5WVhScG"
  "IyNHhGREFTQmdOVkJBY01DMU5oYm5SaElFTnNZWEpoTVFzd0NRWUQKVlFRSURBSkRRVEVMTUFrR0"
  "ExVUVCaE1DVlZNd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRQQpjR2ZYVWpWME"
  "RJUDJMajNUY0pXaHJCMmhTbmlVYkRoWVVOSWozL1pLelRMcGcwUXBzS1NHbkd5amlYRFo5cEg1Cm"
  "IzbE1yMndJMFpBbFBRcCsyVVV0bzRJRERqQ0NBd293SHdZRFZSMGpCQmd3Rm9BVWxXOWR6YjBiNG"
  "VsQVNjblUKOURQT0FWY0wzbFF3YXdZRFZSMGZCR1F3WWpCZ29GNmdYSVphYUhSMGNITTZMeTloY0"
  "drdWRISjFjM1JsWkhObApjblpwWTJWekxtbHVkR1ZzTG1OdmJTOXpaM2d2WTJWeWRHbG1hV05oZE"
  "dsdmJpOTJNeTl3WTJ0amNtdy9ZMkU5CmNHeGhkR1p2Y20wbVpXNWpiMlJwYm1jOVpHVnlNQjBHQT"
  "FVZERnUVdCQlRlWjU1cXR4OEpVMmI4WkFkaTh4aysKQkhReXlUQU9CZ05WSFE4QkFmOEVCQU1DQn"
  "NBd0RBWURWUjBUQVFIL0JBSXdBRENDQWpzR0NTcUdTSWI0VFFFTgpBUVNDQWl3d2dnSW9NQjRHQ2"
  "lxR1NJYjRUUUVOQVFFRUVQVndZZHdoWU1HbHB4Z2dOK0xnaDBFd2dnRmxCZ29xCmhraUcrRTBCRF"
  "FFQ01JSUJWVEFRQmdzcWhraUcrRTBCRFFFQ0FRSUJEakFRQmdzcWhraUcrRTBCRFFFQ0FnSUIKRG"
  "pBUUJnc3Foa2lHK0UwQkRRRUNBd0lCQXpBUUJnc3Foa2lHK0UwQkRRRUNCQUlCQXpBUkJnc3Foa2"
  "lHK0UwQgpEUUVDQlFJQ0FQOHdFUVlMS29aSWh2aE5BUTBCQWdZQ0FnRC9NQkFHQ3lxR1NJYjRUUU"
  "VOQVFJSEFnRUJNQkFHCkN5cUdTSWI0VFFFTkFRSUlBZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSUpBZ0"
  "VBTUJBR0N5cUdTSWI0VFFFTkFRSUsKQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlMQWdFQU1CQUdDeX"
  "FHU0liNFRRRU5BUUlNQWdFQU1CQUdDeXFHU0liNApUUUVOQVFJTkFnRUFNQkFHQ3lxR1NJYjRUUU"
  "VOQVFJT0FnRUFNQkFHQ3lxR1NJYjRUUUVOQVFJUEFnRUFNQkFHCkN5cUdTSWI0VFFFTkFRSVFBZ0"
  "VBTUJBR0N5cUdTSWI0VFFFTkFRSVJBZ0VOTUI4R0N5cUdTSWI0VFFFTkFRSVMKQkJBT0RnTUQvLz"
  "hCQUFBQUFBQUFBQUFBTUJBR0NpcUdTSWI0VFFFTkFRTUVBZ0FBTUJRR0NpcUdTSWI0VFFFTgpBUV"
  "FFQmdCZ2FnQUFBREFQQmdvcWhraUcrRTBCRFFFRkNnRUJNQjRHQ2lxR1NJYjRUUUVOQVFZRUVDVU"
  "JVNGp5CmZ0cnVoMmNvdGVnQXlOSXdSQVlLS29aSWh2aE5BUTBCQnpBMk1CQUdDeXFHU0liNFRRRU"
  "5BUWNCQVFIL01CQUcKQ3lxR1NJYjRUUUVOQVFjQ0FRRUFNQkFHQ3lxR1NJYjRUUUVOQVFjREFRRU"
  "FNQW9HQ0NxR1NNNDlCQU1DQTBrQQpNRVlDSVFDeW9USFpyR3BoSVBnMHczNWJucjJTR3kyMk16T1"
  "ZGODRONUhTR3JPL3B2d0loQVA4WmxOYW9aV2hBCmhibVIyUzNVSHg1SjFSS216bzIwKzZJWmpuM3"
  "lScjhaCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS"
  "0tCk1JSUNsakNDQWoyZ0F3SUJBZ0lWQUpWdlhjMjlHK0hwUUVuSjFQUXp6Z0ZYQzk1VU1Bb0dDQ3"
  "FHU000OUJBTUMKTUdneEdqQVlCZ05WQkFNTUVVbHVkR1ZzSUZOSFdDQlNiMjkwSUVOQk1Sb3dHQV"
  "lEVlFRS0RCRkpiblJsYkNCRApiM0p3YjNKaGRHbHZiakVVTUJJR0ExVUVCd3dMVTJGdWRHRWdRMn"
  "hoY21FeEN6QUpCZ05WQkFnTUFrTkJNUXN3CkNRWURWUVFHRXdKVlV6QWVGdzB4T0RBMU1qRXhNRF"
  "V3TVRCYUZ3MHpNekExTWpFeE1EVXdNVEJhTUhBeElqQWcKQmdOVkJBTU1HVWx1ZEdWc0lGTkhXQ0"
  "JRUTBzZ1VHeGhkR1p2Y20wZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWcwpJRU52Y25CdmNtRjBhVz"
  "l1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4CkN6QUpCZ0"
  "5WQkFZVEFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVOU0IvN3QyMWxYU0"
  "8KMkN1enB4dzc0ZUpCNzJFeURHZ1c1clhDdHgydFZUTHE2aEtrNnorVWlSWkNucVI3cHNPdmdxRm"
  "VTeGxtVGxKbAplVG1pMldZejNxT0J1ekNCdURBZkJnTlZIU01FR0RBV2dCUWlaUXpXV3AwMGlmT0"
  "R0SlZTdjFBYk9TY0dyREJTCkJnTlZIUjhFU3pCSk1FZWdSYUJEaGtGb2RIUndjem92TDJObGNuUn"
  "BabWxqWVhSbGN5NTBjblZ6ZEdWa2MyVnkKZG1salpYTXVhVzUwWld3dVkyOXRMMGx1ZEdWc1UwZF"
  "lVbTl2ZEVOQkxtUmxjakFkQmdOVkhRNEVGZ1FVbFc5ZAp6YjBiNGVsQVNjblU5RFBPQVZjTDNsUX"
  "dEZ1lEVlIwUEFRSC9CQVFEQWdFR01CSUdBMVVkRXdFQi93UUlNQVlCCkFmOENBUUF3Q2dZSUtvWk"
  "l6ajBFQXdJRFJ3QXdSQUlnWHNWa2kwdytpNlZZR1czVUYvMjJ1YVhlMFlKRGoxVWUKbkErVGpEMW"
  "FpNWNDSUNZYjFTQW1ENXhrZlRWcHZvNFVveWlTWXhyRFdMbVVSNENJOU5LeWZQTisKLS0tLS1FTk"
  "QgQ0VSVElGSUNBVEUtLS0tLQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQ2p6Q0NBal"
  "NnQXdJQkFnSVVJbVVNMWxxZE5JbnpnN1NWVXI5UUd6a25CcXd3Q2dZSUtvWkl6ajBFQXdJdwphRE"
  "VhTUJnR0ExVUVBd3dSU1c1MFpXd2dVMGRZSUZKdmIzUWdRMEV4R2pBWUJnTlZCQW9NRVVsdWRHVn"
  "NJRU52CmNuQnZjbUYwYVc5dU1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJHRnlZVEVMTUFrR0ExVU"
  "VDQXdDUTBFeEN6QUoKQmdOVkJBWVRBbFZUTUI0WERURTRNRFV5TVRFd05EVXhNRm9YRFRRNU1USX"
  "pNVEl6TlRrMU9Wb3dhREVhTUJnRwpBMVVFQXd3UlNXNTBaV3dnVTBkWUlGSnZiM1FnUTBFeEdqQV"
  "lCZ05WQkFvTUVVbHVkR1ZzSUVOdmNuQnZjbUYwCmFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQk"
  "RiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKQmdOVkJBWVQKQWxWVE1Ga3dFd1lIS29aSXpqME"
  "NBUVlJS29aSXpqMERBUWNEUWdBRUM2bkV3TURJWVpPai9pUFdzQ3phRUtpNwoxT2lPU0xSRmhXR2"
  "pibkJWSmZWbmtZNHUzSWprRFlZTDBNeE80bXFzeVlqbEJhbFRWWXhGUDJzSkJLNXpsS09CCnV6Q0"
  "J1REFmQmdOVkhTTUVHREFXZ0JRaVpReldXcDAwaWZPRHRKVlN2MUFiT1NjR3JEQlNCZ05WSFI4RV"
  "N6QkoKTUVlZ1JhQkRoa0ZvZEhSd2N6b3ZMMk5sY25ScFptbGpZWFJsY3k1MGNuVnpkR1ZrYzJWeW"
  "RtbGpaWE11YVc1MApaV3d1WTI5dEwwbHVkR1ZzVTBkWVVtOXZkRU5CTG1SbGNqQWRCZ05WSFE0RU"
  "ZnUVVJbVVNMWxxZE5JbnpnN1NWClVyOVFHemtuQnF3d0RnWURWUjBQQVFIL0JBUURBZ0VHTUJJR0"
  "ExVWRFd0VCL3dRSU1BWUJBZjhDQVFFd0NnWUkKS29aSXpqMEVBd0lEU1FBd1JnSWhBT1cvNVFrUi"
  "tTOUNpU0RjTm9vd0x1UFJMc1dHZi9ZaTdHU1g5NEJnd1R3ZwpBaUVBNEowbHJIb01zK1hvNW8vc1"
  "g2TzlRV3hIUkF2WlVHT2RSUTdjdnFSWGFxST0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQoAMA"
  "0GCSqGSIb3DQEBCwUAA4IBAQAWPfe1yj4TfaxWipdcjCX+"
  "NBJQtQOvhu6TbkzwWczIkvcCQ8O6dzsnMDFkxVkZ2ZlcsufSaB74VS//3BzOh/PLWpSX/"
  "TaQHxFKhcK5RxlEq0O/oINnJ7fMhKlrd/hyoD/"
  "P2bSLej5zdh63JciGxNGXkanchgQ8qNxXhs9oRUJINYYinFfRsD3OzX6dsHLPVshkdOZFpM9DgP2"
  "QozqQJ1GC4tAKwbktxU0Ai3BecoPFzYVIygGLY1BAGd112C6cktj7YZTWE/"
  "tCSD+uXWyQieBu5zUN7H/PcxY9VBT/fOkBfaaL+JcpG4/tGrbTTbZUUclzKVQ/5XP6bOa1t6r/"
  "zN/W";

static const string pem_key_for_nested_cert =
  "-----BEGIN PUBLIC "
  "KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2NBrEQdwXUzVy2p+"
  "SZ7s\nBjxbVd4iTGNEQJu/Ot/C0NCzXIDT6DMEAeVZLSoWWcW6oXQ81h+yQWtw+jFW/"
  "SPg\nG4FGSL1UnVO8Zak80thovQk0dbZDo+"
  "9lsoOnOfXfPUL0T9AgHtqJpUr3tCfyRRLd\nC0MgF1tAyjZbMj8bHe2ZmJ9GLTJT5v9E0i5l3S4W"
  "ZY52vMzZaVpfxw+0/s5tRzco\nPGqIrMOnX/7kv5j7sisqZKNq6fP+4MHvLb/"
  "tXyHCkW6FzX8mUlwyRNzBP3R4xaXB\nvykzJMaAiCW/Yr/"
  "TxycdnmwsTR7he1Q78q12KnYqLvUVjg/v39/RWGSbFnaP1YX5\nHwIDAQAB\n-----END "
  "PUBLIC KEY-----\n";

template <typename T>
void corrupt(T& buf)
{
  buf[1]++;
  buf[buf.size() / 2]++;
  buf[buf.size() - 2]++;
}

static constexpr CurveID supported_curves[] = {
  CurveID::SECP384R1, CurveID::SECP256R1};

static constexpr char const* labels[] = {"secp384r1", "secp256r1"};

ccf::crypto::Pem generate_self_signed_cert(
  const KeyPairPtr& kp, const std::string& name)
{
  constexpr size_t certificate_validity_period_days = 365;
  using namespace std::literals;
  auto valid_from =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);

  return ccf::crypto::create_self_signed_cert(
    kp, name, {}, valid_from, certificate_validity_period_days);
}

std::string qcbor_buf_to_string(const UsefulBufC& buf)
{
  return std::string(reinterpret_cast<const char*>(buf.ptr), buf.len);
}

t_cose_err_t verify_detached(
  EVP_PKEY* key, std::span<const uint8_t> buf, std::span<const uint8_t> payload)
{
  t_cose_key cose_key;
  cose_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
  cose_key.k.key_ptr = key;

  t_cose_sign1_verify_ctx verify_ctx;
  t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_TAG_REQUIRED);
  t_cose_sign1_set_verification_key(&verify_ctx, cose_key);

  q_useful_buf_c buf_;
  buf_.ptr = buf.data();
  buf_.len = buf.size();

  q_useful_buf_c payload_;
  payload_.ptr = payload.data();
  payload_.len = payload.size();

  t_cose_err_t error = t_cose_sign1_verify_detached(
    &verify_ctx, buf_, NULL_Q_USEFUL_BUF_C, payload_, nullptr);

  return error;
}

void require_match_headers(
  std::pair<int64_t, std::optional<int64_t>> kv1,
  std::pair<int64_t, std::optional<std::string_view>> kv2,
  std::pair<std::string_view, std::optional<int64_t>> kv3,
  std::pair<std::string_view, std::optional<std::string_view>> kv4,
  const std::vector<uint8_t>& cose_sign)
{
  UsefulBufC msg{cose_sign.data(), cose_sign.size()};

  // 0. Init and verify COSE tag
  QCBORDecodeContext ctx;
  QCBORDecode_Init(&ctx, msg, QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterArray(&ctx, nullptr);
  REQUIRE_EQ(QCBORDecode_GetError(&ctx), QCBOR_SUCCESS);
  REQUIRE_EQ(QCBORDecode_GetNthTagOfLast(&ctx, 0), CBOR_TAG_COSE_SIGN1);

  // 1. Protected headers
  struct q_useful_buf_c protected_parameters;
  QCBORDecode_EnterBstrWrapped(
    &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);
  QCBORDecode_EnterMap(&ctx, NULL);

  QCBORItem header_items[5 + 1];

  // Verify 'alg' is default-encoded.
  header_items[0].label.int64 = 1;
  header_items[0].uLabelType = QCBOR_TYPE_INT64;
  header_items[0].uDataType = QCBOR_TYPE_INT64;

  header_items[1].label.int64 = kv1.first;
  header_items[1].uLabelType = QCBOR_TYPE_INT64;
  header_items[1].uDataType = QCBOR_TYPE_INT64;

  header_items[2].label.int64 = kv2.first;
  header_items[2].uLabelType = QCBOR_TYPE_INT64;
  header_items[2].uDataType = QCBOR_TYPE_TEXT_STRING;

  header_items[3].label.string = {kv3.first.data(), kv3.first.size()};
  header_items[3].uLabelType = QCBOR_TYPE_TEXT_STRING;
  header_items[3].uDataType = QCBOR_TYPE_INT64;

  header_items[4].label.string = {kv4.first.data(), kv4.first.size()};
  header_items[4].uLabelType = QCBOR_TYPE_TEXT_STRING;
  header_items[4].uDataType = QCBOR_TYPE_TEXT_STRING;

  header_items[5].uLabelType = QCBOR_TYPE_NONE;

  QCBORDecode_GetItemsInMap(&ctx, header_items);
  REQUIRE_EQ(QCBORDecode_GetError(&ctx), QCBOR_SUCCESS);

  // 'alg'
  REQUIRE_NE(header_items[0].uDataType, QCBOR_TYPE_NONE);

  if (kv1.second)
    REQUIRE_EQ(header_items[1].val.int64, *kv1.second);
  else
    REQUIRE_EQ(header_items[1].uDataType, QCBOR_TYPE_NONE);

  if (kv2.second)
    REQUIRE_EQ(qcbor_buf_to_string(header_items[2].val.string), *kv2.second);
  else
    REQUIRE_EQ(header_items[2].uDataType, QCBOR_TYPE_NONE);

  if (kv3.second)
    REQUIRE_EQ(header_items[3].val.int64, *kv3.second);
  else
    REQUIRE_EQ(header_items[3].uDataType, QCBOR_TYPE_NONE);

  if (kv4.second)
    REQUIRE_EQ(qcbor_buf_to_string(header_items[4].val.string), *kv4.second);
  else
    REQUIRE_EQ(header_items[4].uDataType, QCBOR_TYPE_NONE);

  QCBORDecode_ExitMap(&ctx);
  QCBORDecode_ExitBstrWrapped(&ctx);

  // 2. Unprotected headers (skip).
  QCBORItem item;
  QCBORDecode_VGetNextConsume(&ctx, &item);

  // 3. Skip payload (detached);
  QCBORDecode_GetNext(&ctx, &item);

  // 4. skip signature (should be verified by cose verifier).
  QCBORDecode_GetNext(&ctx, &item);

  // 5. Decode can be completed.
  QCBORDecode_ExitArray(&ctx);
  REQUIRE_EQ(QCBORDecode_Finish(&ctx), QCBOR_SUCCESS);
}

TEST_CASE("My test jwt")
{
  std::string contents64 =
    "ZXlKaGJHY2lPaUpGVXpJMU5pSXNJbXRwWkNJNkltMTVYMnRsZVY5cFpDSXNJblI1Y0NJNklrcF"
    "hWQ0o5LmV5SnVZbVlpT2pFM016UTBOVGN3T1RRc0ltVjRjQ0k2TVRjek5EUTJNRGN3TkN3aWFY"
    "TnpJam9pYUhSMGNITTZMeTlsZUdGdGNHeGxMbWx6YzNWbGNpSjk=";
  std::string signature64 =
    "YxVLZS1XXr4v6uu8jz4tsoKnU1aSx4Qfv2c5Q3r/zK80/fie5HLn10QJMi4laJCpzkPw/"
    "NxwwXPaF6C53XvcoA==";

  auto contents = ccf::crypto::raw_from_b64(contents64);
  auto signature = ccf::crypto::raw_from_b64(signature64);

  std::string key_pem =
    "-----BEGIN PUBLIC "
    "KEY-----"
    "\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEL6Of9dn7vv5GoP0QtquUKV39scwb\nLBMIfd"
    "blJULg0kY/pxaWt2gxTVQ6ZecqNV7hEX597CUBgRcBODMNo5mbHg==\n-----END PUBLIC "
    "KEY-----\n";

  auto pubkey = ccf::crypto::make_public_key(key_pem);

  const auto res = pubkey->verify(
    contents.data(),
    contents.size(),
    signature.data(),
    signature.size(),
    ccf::crypto::MDType::SHA256);

  std::cout << "res: " << res << std::endl;
}
