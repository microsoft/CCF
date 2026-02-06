// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/openssl/openssl_wrappers.h"
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/base64.h"
#include "ccf/crypto/ec_key_pair.h"
#include "ccf/crypto/eddsa_key_pair.h"
#include "ccf/crypto/entropy.h"
#include "ccf/crypto/hmac.h"
#include "ccf/crypto/jwk.h"
#include "ccf/crypto/key_wrap.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/x509_time_fmt.h"
#include "crypto/cbor.h"
#include "crypto/certs.h"
#include "crypto/cose.h"
#include "crypto/csr.h"
#include "crypto/openssl/cose_sign.h"
#include "crypto/openssl/cose_verifier.h"
#include "crypto/openssl/ec_key_pair.h"
#include "crypto/openssl/rsa_key_pair.h"
#include "crypto/openssl/symmetric_key.h"
#include "crypto/openssl/verifier.h"
#include "crypto/openssl/x509_time.h"

#include <chrono>
#include <cstring>
#include <ctime>
#include <doctest/doctest.h>
#include <optional>
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
  "-----BEGIN PUBLIC KEY-----\n"
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2NBrEQdwXUzVy2p+SZ7s\n"
  "BjxbVd4iTGNEQJu/Ot/C0NCzXIDT6DMEAeVZLSoWWcW6oXQ81h+yQWtw+jFW/SPg\n"
  "G4FGSL1UnVO8Zak80thovQk0dbZDo+9lsoOnOfXfPUL0T9AgHtqJpUr3tCfyRRLd\n"
  "C0MgF1tAyjZbMj8bHe2ZmJ9GLTJT5v9E0i5l3S4WZY52vMzZaVpfxw+0/s5tRzco\n"
  "PGqIrMOnX/7kv5j7sisqZKNq6fP+4MHvLb/tXyHCkW6FzX8mUlwyRNzBP3R4xaXB\n"
  "vykzJMaAiCW/Yr/TxycdnmwsTR7he1Q78q12KnYqLvUVjg/v39/RWGSbFnaP1YX5\n"
  "HwIDAQAB\n"
  "-----END PUBLIC KEY-----\n";

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
  const ECKeyPairPtr& kp, const std::string& name)
{
  constexpr size_t certificate_validity_period_days = 365;
  using namespace std::literals;
  auto valid_from =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);

  return ccf::crypto::create_self_signed_cert(
    kp, name, {}, valid_from, certificate_validity_period_days);
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
  auto decoded = ccf::cbor::parse(cose_sign);

  const auto& as_cose = decoded->tag_at(ccf::cbor::tag::COSE_SIGN_1);
  const auto& raw_phdr = as_cose->array_at(0)->as_bytes();

  auto phdr = ccf::cbor::parse(raw_phdr);

  // 'alg'
  REQUIRE_NOTHROW((void)phdr->map_at(ccf::cbor::make_signed(1)));

  if (kv1.second)
    REQUIRE_EQ(
      phdr->map_at(ccf::cbor::make_signed(kv1.first))->as_signed(),
      *kv1.second);
  else
    REQUIRE_THROWS(
      (void)phdr->map_at(ccf::cbor::make_signed(kv1.first))->as_signed());

  if (kv2.second)
    REQUIRE_EQ(
      phdr->map_at(ccf::cbor::make_signed(kv2.first))->as_string(),
      *kv2.second);
  else
    REQUIRE_THROWS(
      (void)phdr->map_at(ccf::cbor::make_signed(kv2.first))->as_string());

  if (kv3.second)
    REQUIRE_EQ(
      phdr->map_at(ccf::cbor::make_string(kv3.first))->as_signed(),
      *kv3.second);
  else
    REQUIRE_THROWS(
      (void)phdr->map_at(ccf::cbor::make_string(kv3.first))->as_signed());

  if (kv4.second)
    REQUIRE_EQ(
      phdr->map_at(ccf::cbor::make_string(kv4.first))->as_string(),
      *kv4.second);
  else
    REQUIRE_THROWS(
      (void)phdr->map_at(ccf::cbor::make_string(kv4.first))->as_string());
}

TEST_CASE("Check verifier handles nested certs for both PEM and DER inputs")
{
  auto cert_der = ccf::crypto::raw_from_b64(nested_cert);
  auto cert_pem = fmt::format(
    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----", nested_cert);
  auto der_verifier = make_verifier(cert_der);
  auto pem_verifier = make_verifier(cert_pem);
  auto pem_key_from_der = der_verifier->public_key_pem();
  auto pem_key_from_pem = pem_verifier->public_key_pem();
  CHECK(pem_key_from_der.str() == pem_key_from_pem.str());
  CHECK(pem_key_from_der.str() == pem_key_for_nested_cert);
}

TEST_CASE("Sign, verify, with ECKeyPair")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_ec_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);
    CHECK(kp->verify(contents, signature));

    auto kp2 = make_ec_key_pair(kp->private_key_pem());
    CHECK(kp2->verify(contents, signature));

    // Signatures won't necessarily be identical due to entropy, but should be
    // mutually verifiable
    for (auto i = 0; i < 10; ++i)
    {
      const auto new_sig = kp2->sign(contents);
      CHECK(kp->verify(contents, new_sig));
      CHECK(kp2->verify(contents, new_sig));
    }
  }
}

TEST_CASE("Sign, verify, with ECPublicKey")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_ec_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);

    const auto public_key = kp->public_key_pem();
    auto pubk = make_ec_public_key(public_key);
    CHECK(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with bad signature")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_ec_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    const auto public_key = kp->public_key_pem();
    auto pubk = make_ec_public_key(public_key);
    corrupt(signature);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with bad contents")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_ec_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    const auto public_key = kp->public_key_pem();
    auto pubk = make_ec_public_key(public_key);
    corrupt(contents);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with wrong key on correct curve")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_ec_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    auto kp2 = make_ec_key_pair(curve);
    const auto public_key = kp2->public_key_pem();
    auto pubk = make_ec_public_key(public_key);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with wrong key on wrong curve")
{
  constexpr size_t num_supported_curves =
    static_cast<size_t>(sizeof(supported_curves) / sizeof(CurveID));
  for (auto i = 0; i < num_supported_curves; ++i)
  {
    const auto curve = supported_curves[i];
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_ec_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    const auto wrong_curve = supported_curves[(i + 1) % num_supported_curves];
    auto kp2 = make_ec_key_pair(wrong_curve);
    const auto public_key = kp2->public_key_pem();
    auto pubk = make_ec_public_key(public_key);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

template <typename T, typename S, CurveID CID>
void run_alt()
{
  T kp1(CID);
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  vector<uint8_t> signature = kp1.sign(contents);

  S kp2(kp1.public_key_pem());
  CHECK(kp2.verify(contents, signature));
}

TEST_CASE("Sign, verify with certificate")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_ec_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);

    auto cert = generate_self_signed_cert(kp, "CN=name");
    auto verifier = make_verifier(cert);
    CHECK(verifier->verify(contents, signature));
  }
}

TEST_CASE("Sign, verify. Fail to verify with bad contents")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_ec_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);

    auto cert = generate_self_signed_cert(kp, "CN=name");
    auto verifier = make_verifier(cert);
    CHECK(verifier->verify(contents, signature));
    corrupt(contents);
    CHECK_FALSE(verifier->verify(contents, signature));
  }
}

ccf::crypto::HashBytes bad_manual_hash(const std::vector<uint8_t>& data)
{
  // secp256r1 requires 32-byte hashes, other curves don't care. So use 32 for
  // general hasher
  constexpr auto n = 32;
  ccf::crypto::HashBytes hash(n);

  for (size_t i = 0; i < data.size(); ++i)
  {
    hash[i % n] ^= data[i];
  }

  return hash;
}

TEST_CASE("Manually hash, sign, verify, with ECPublicKey")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_ec_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    ccf::crypto::HashBytes hash = bad_manual_hash(contents);
    const vector<uint8_t> signature = kp->sign_hash(hash.data(), hash.size());

    const auto public_key = kp->public_key_pem();
    auto pubk = make_ec_public_key(public_key);
    CHECK(pubk->verify_hash(hash, signature, MDType::SHA256));
    corrupt(hash);
    CHECK_FALSE(pubk->verify_hash(hash, signature, MDType::SHA256));
  }
}

TEST_CASE("Manually hash, sign, verify, with certificate")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_ec_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    ccf::crypto::HashBytes hash = bad_manual_hash(contents);
    const vector<uint8_t> signature = kp->sign_hash(hash.data(), hash.size());

    auto cert = generate_self_signed_cert(kp, "CN=name");
    auto verifier = make_verifier(cert);
    CHECK(verifier->verify_hash(hash, signature, MDType::SHA256));
    corrupt(hash);
    CHECK_FALSE(verifier->verify(hash, signature, MDType::SHA256));
  }
}

TEST_CASE("Sign, verify, with ECKeyPair of EdDSA")
{
  constexpr auto curve = "curve25519";
  constexpr auto curve_id = CurveID::CURVE25519;
  INFO("With curve: " << curve);
  auto kp = make_eddsa_key_pair(curve_id);
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  const vector<uint8_t> signature = kp->sign(contents);
  CHECK(kp->verify(contents, signature));
}

TEST_CASE("Sign, verify, with ECPublicKey of EdDSA")
{
  constexpr auto curve = "curve25519";
  constexpr auto curve_id = CurveID::CURVE25519;
  INFO("With curve: " << curve);
  auto kp = make_eddsa_key_pair(curve_id);
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  const vector<uint8_t> signature = kp->sign(contents);

  const auto public_key = kp->public_key_pem();
  auto pubk = make_eddsa_public_key(public_key);
  CHECK(pubk->verify(contents, signature));
}

TEST_CASE("Sign, fail to verify with bad signature (EdDSA)")
{
  constexpr auto curve = "curve25519";
  constexpr auto curve_id = CurveID::CURVE25519;
  INFO("With curve: " << curve);
  auto kp = make_eddsa_key_pair(curve_id);
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  vector<uint8_t> signature = kp->sign(contents);

  const auto public_key = kp->public_key_pem();
  auto pubk = make_eddsa_public_key(public_key);
  corrupt(signature);
  CHECK_FALSE(pubk->verify(contents, signature));
}

TEST_CASE("Sign, fail to verify with bad contents (EdDSA)")
{
  constexpr auto curve = "curve25519";
  constexpr auto curve_id = CurveID::CURVE25519;
  INFO("With curve: " << curve);
  auto kp = make_eddsa_key_pair(curve_id);
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  vector<uint8_t> signature = kp->sign(contents);

  const auto public_key = kp->public_key_pem();
  auto pubk = make_eddsa_public_key(public_key);
  corrupt(contents);
  CHECK_FALSE(pubk->verify(contents, signature));
}

TEST_CASE("Sign, fail to verify with wrong key on correct curve (EdDSA)")
{
  constexpr auto curve = "curve25519";
  constexpr auto curve_id = CurveID::CURVE25519;
  INFO("With curve: " << curve);
  auto kp = make_eddsa_key_pair(curve_id);
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  vector<uint8_t> signature = kp->sign(contents);

  auto kp2 = make_eddsa_key_pair(curve_id);
  const auto public_key = kp2->public_key_pem();
  auto pubk = make_eddsa_public_key(public_key);
  CHECK_FALSE(pubk->verify(contents, signature));
}

TEST_CASE("base64")
{
  for (size_t length = 1; length < 20; ++length)
  {
    std::vector<uint8_t> raw(length);
    std::generate(raw.begin(), raw.end(), rand);

    const auto encoded = b64_from_raw(raw.data(), raw.size());
    const auto decoded = raw_from_b64(encoded);
    REQUIRE(decoded == raw);
  }
}

TEST_CASE("base64url")
{
  for (size_t length = 1; length < 20; ++length)
  {
    std::vector<uint8_t> raw(length);
    std::generate(raw.begin(), raw.end(), rand);

    auto encoded = b64_from_raw(raw.data(), raw.size());
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');
    encoded.erase(
      std::find(encoded.begin(), encoded.end(), '='), encoded.end());
    const auto decoded = raw_from_b64url(encoded);
    REQUIRE(decoded == raw);
  }
}

TEST_CASE("Wrap, unwrap with RSAKeyPair")
{
  size_t input_len = 64;
  std::vector<uint8_t> input = get_entropy()->random(input_len);

  INFO("Cannot make RSA key from EC key");
  {
    for (const auto curve : supported_curves)
    {
      auto rsa_kp = make_ec_key_pair(curve); // EC Key

      REQUIRE_THROWS_AS(
        make_rsa_public_key(rsa_kp->public_key_pem()), std::logic_error);
    }
  }

  INFO("Without label");
  {
    auto rsa_kp = make_rsa_key_pair();
    auto rsa_pub = make_rsa_public_key(rsa_kp->public_key_pem());

    // Public key can wrap
    auto wrapped = rsa_pub->rsa_oaep_wrap(input);

    // Only private key can unwrap
    auto unwrapped = rsa_kp->rsa_oaep_unwrap(wrapped);
    // rsa_pub->unwrap(wrapped); // Doesn't compile
    REQUIRE(input == unwrapped);

    // Raw data
    wrapped = rsa_pub->rsa_oaep_wrap(input.data(), input.size());
    unwrapped = rsa_kp->rsa_oaep_unwrap(wrapped);
    REQUIRE(input == unwrapped);
  }

  INFO("With label");
  {
    auto rsa_kp = make_rsa_key_pair();
    auto rsa_pub = make_rsa_public_key(rsa_kp->public_key_pem());
    std::string lblstr = "my_label";
    std::vector<uint8_t> label(lblstr.begin(), lblstr.end());
    auto wrapped = rsa_pub->rsa_oaep_wrap(input, label);
    auto unwrapped = rsa_kp->rsa_oaep_unwrap(wrapped, label);
    REQUIRE(input == unwrapped);
  }
}

TEST_CASE("Extract public key from cert")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_ec_key_pair(curve);
    auto pk = kp->public_key_der();
    auto cert = generate_self_signed_cert(kp, "CN=name");
    auto cert_der = make_verifier(cert.raw())->cert_der();
    auto pubk = public_key_der_from_cert(cert_der);
    REQUIRE(pk == pubk);
  }
}

template <typename T>
void create_csr_and_extract_pubk()
{
  T kp(CurveID::SECP384R1);
  auto pk = kp.public_key_pem();
  auto csr = kp.create_csr("CN=name", {});
  auto pubk = public_key_pem_from_csr(csr);
  REQUIRE(pk == pubk);
}

TEST_CASE("Extract public key from csr")
{
  create_csr_and_extract_pubk<ECKeyPair_OpenSSL>();
}

template <typename T, typename S>
void run_csr(bool corrupt_csr = false)
{
  T kpm(CurveID::SECP384R1);

  const char* subject_name = "CN=myname";
  std::string valid_from, valid_to;

  std::vector<SubjectAltName> subject_alternative_names;

  subject_alternative_names.push_back({"email:my-other-name", false});
  subject_alternative_names.push_back({"www.microsoft.com", false});
  subject_alternative_names.push_back({"192.168.0.1", true});
  valid_from = "20210311000000Z";
  valid_to = "20230611235959Z";

  auto csr = kpm.create_csr(subject_name, subject_alternative_names);

  if (corrupt_csr)
  {
    constexpr size_t corrupt_byte_pos_from_end = 66;
    auto& corrupt_byte = csr.data()[csr.size() - corrupt_byte_pos_from_end];
    corrupt_byte++;
  }

  auto icrt = kpm.self_sign("CN=issuer", valid_from, valid_to);

  if (corrupt_csr)
  {
    REQUIRE_THROWS([&]() {
      auto discard = kpm.sign_csr(icrt, csr, valid_from, valid_to);
    }());
    return;
  }

  auto crt = kpm.sign_csr(icrt, csr, valid_from, valid_to);
  std::vector<uint8_t> content = {0, 1, 2, 3, 4};
  auto signature = kpm.sign(content);

  S v(crt.raw());
  REQUIRE(v.verify(content, signature));

  std::string valid_from_, valid_to_;
  std::tie(valid_from_, valid_to_) = v.validity_period();
  REQUIRE(valid_from_.find(valid_from) != std::string::npos);
  REQUIRE(valid_to_.find(valid_to) != std::string::npos);
}

TEST_CASE("2-digit years")
{
  auto time_str = "220405175422Z";
  auto tp = ccf::ds::time_point_from_string(time_str);
  auto conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == std::string("20") + time_str);
}

TEST_CASE("Non-ASN.1 timepoint formats")
{
  auto time_str = "2022-04-05 18:53:27";
  auto tp = ccf::ds::time_point_from_string(time_str);
  auto conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220405185327Z");

  time_str = "2022-04-05 18:53:27.190380";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220405185327Z");

  time_str = "2022-04-05 18:53:27 +03:00";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220405155327Z");

  time_str = "2022-04-05 18:53:27 +0300";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220405155327Z");

  time_str = "2022-04-05 18:53:27.190380+03:00";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220405155327Z");

  time_str = "2022-04-05 18:53:27 -03:00";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220405215327Z");

  time_str = "2022-04-07T10:37:49.567612";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220407103749Z");

  time_str = "2022-04-07T10:37:49.567612+03:00";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220407073749Z");

  time_str = "2022-04-07T10:37:49.567612Z";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220407103749Z");

  time_str = "220425165619+0000";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220425165619Z");

  time_str = "220425165619+0200";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220425145619Z");

  time_str = "20220425165619-0300";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220425195619Z");
}

TEST_CASE("Timepoint bounds")
{
  auto time_str = "1677-09-21 00:12:44";
  auto tp = ccf::ds::time_point_from_string(time_str);
  auto conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "16770921001244Z");

  time_str = "1677-09-21 00:12:43";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  CHECK(conv == "16770921001243Z");

  time_str = "2262-04-11 23:47:16";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  REQUIRE(conv == "22620411234716Z");

  time_str = "2262-04-11 23:47:17";
  tp = ccf::ds::time_point_from_string(time_str);
  conv = ccf::ds::to_x509_time_string(tp);
  CHECK(conv == "22620411234717Z");
}

TEST_CASE("Create sign and verify certificates")
{
  bool corrupt_csr = false;
  do
  {
    run_csr<ECKeyPair_OpenSSL, Verifier_OpenSSL>(corrupt_csr);
    corrupt_csr = !corrupt_csr;
  } while (corrupt_csr);
}

static const vector<uint8_t>& get_raw_key()
{
  static const vector<uint8_t> v(16, '$');
  return v;
}

TEST_CASE("ExtendedIv0")
{
  auto k = ccf::crypto::make_key_aes_gcm(get_raw_key());

  // setup plain text
  std::vector<uint8_t> plain(100);
  std::iota(plain.begin(), plain.end(), 0);

  // test large IV
  using LargeIVGcmHeader = FixedSizeGcmHeader<128>;
  LargeIVGcmHeader h;

  SUBCASE("Null IV") {}

  SUBCASE("Random IV")
  {
    h.set_random_iv();
  }

  std::vector<uint8_t> cipher;
  k->encrypt(h.get_iv(), plain, {}, cipher, h.tag);

  auto k2 = ccf::crypto::make_key_aes_gcm(get_raw_key());
  std::vector<uint8_t> decrypted_plain;
  REQUIRE(k2->decrypt(h.get_iv(), h.tag, cipher, {}, decrypted_plain));
  REQUIRE(plain == decrypted_plain);
}

TEST_CASE("AES Key wrap with padding")
{
  auto key = get_raw_key();
  std::vector<uint8_t> aad(123, 'y');

  std::vector<uint8_t> key_to_wrap = get_entropy()->random(997);

  auto ossl = std::make_unique<KeyAesGcm_OpenSSL>(key);

  std::vector<uint8_t> wrapped = ossl->ckm_aes_key_wrap_pad(key_to_wrap);
  std::vector<uint8_t> unwrapped = ossl->ckm_aes_key_unwrap_pad(wrapped);

  REQUIRE(wrapped != unwrapped);
  REQUIRE(key_to_wrap == unwrapped);
}

TEST_CASE("CKM_RSA_PKCS_OAEP")
{
  auto key = get_raw_key();

  auto rsa_kp = make_rsa_key_pair();
  auto rsa_pk = make_rsa_public_key(rsa_kp->public_key_pem());

  auto wrapped = ccf::crypto::ckm_rsa_pkcs_oaep_wrap(rsa_pk, key);
  auto wrapped_ = ccf::crypto::ckm_rsa_pkcs_oaep_wrap(rsa_pk, key);

  // CKM_RSA_PKCS_OAEP wrap is non deterministic
  REQUIRE(wrapped != wrapped_);

  auto unwrapped = ccf::crypto::ckm_rsa_pkcs_oaep_unwrap(rsa_kp, wrapped);
  auto unwrapped_ = ccf::crypto::ckm_rsa_pkcs_oaep_unwrap(rsa_kp, wrapped_);

  REQUIRE(unwrapped == unwrapped_);
}

TEST_CASE("CKM_RSA_AES_KEY_WRAP")
{
  std::vector<uint8_t> key_to_wrap = get_entropy()->random(256);

  auto rsa_kp = make_rsa_key_pair();
  auto rsa_pk = make_rsa_public_key(rsa_kp->public_key_pem());

  std::vector<uint8_t> wrapped = ckm_rsa_aes_key_wrap(128, rsa_pk, key_to_wrap);
  std::vector<uint8_t> unwrapped = ckm_rsa_aes_key_unwrap(rsa_kp, wrapped);

  REQUIRE(wrapped != unwrapped);
  REQUIRE(unwrapped == key_to_wrap);
}

TEST_CASE("AES-GCM convenience functions")
{
  EntropyPtr entropy = get_entropy();
  std::vector<uint8_t> key = entropy->random(GCM_DEFAULT_KEY_SIZE);
  auto encrypted = aes_gcm_encrypt(key, contents);
  auto decrypted = aes_gcm_decrypt(key, encrypted);
  REQUIRE(decrypted == contents);
}

TEST_CASE("x509 time")
{
  auto time = std::chrono::system_clock::now();

  auto next_minute_time = time + 1min;
  auto next_day_time = time + 24h;
  auto next_year_time = time + 24h * 365;

  INFO("Chronological time");
  {
    struct TimeTest
    {
      struct Input
      {
        std::chrono::system_clock::time_point from;
        std::chrono::system_clock::time_point to;
        std::optional<uint32_t> maximum_validity_period_days = std::nullopt;
      };
      Input input;

      bool expected_verification_result;
    };

    std::vector<TimeTest> test_vector{
      {{time, next_day_time}, true}, // Valid: Next day
      {{time, time}, false}, // Invalid: Same date
      {{next_day_time, time}, false}, // Invalid: to is before from
      {{time, next_day_time, 100}, true}, // Valid: Next day within 100 days
      {{time, next_year_time, 100},
       false}, // Valid: Next day not within 100 days
      {{time, next_minute_time}, true}, // Valid: Next minute
      {{next_minute_time, time}, false}, // Invalid: to is before from
      {{time, next_minute_time, 1}, true} // Valid: Next min within 1 day
    };

    for (auto& data : test_vector)
    {
      const auto& from = data.input.from;
      const auto& to = data.input.to;
      REQUIRE(
        ccf::crypto::OpenSSL::validate_chronological_times(
          ccf::crypto::OpenSSL::Unique_X509_TIME(from),
          ccf::crypto::OpenSSL::Unique_X509_TIME(to),
          data.input.maximum_validity_period_days) ==
        data.expected_verification_result);
    }
  }

  INFO("Adjust time");
  {
    std::vector<std::chrono::system_clock::time_point> times = {
      time, next_day_time, next_day_time};
    size_t days_offset = 100;

    for (auto& t : times)
    {
      auto adjusted_time = t + std::chrono::days(days_offset);

      auto from = ccf::crypto::OpenSSL::Unique_X509_TIME(t);
      auto to = ccf::crypto::OpenSSL::Unique_X509_TIME(adjusted_time);

      // Convert to string and back to time_points
      auto from_conv = ccf::ds::time_point_from_string(
        ccf::crypto::OpenSSL::to_x509_time_string(from));
      auto to_conv = ccf::ds::time_point_from_string(
        ccf::crypto::OpenSSL::to_x509_time_string(to));

      // Diff is still the same amount of days
      auto days_diff =
        std::chrono::duration_cast<std::chrono::days>(to_conv - from_conv)
          .count();
      REQUIRE(days_diff == days_offset);
    }
  }

  INFO("String to time conversion and back");
  {
    std::vector<size_t> days_offsets = {0, 1, 10, 100, 365, 1000, 10000};

    for (auto const& days_offset : days_offsets)
    {
      auto adjusted_time = time + std::chrono::days(days_offset);
      auto adjusted_str = ccf::ds::to_x509_time_string(adjusted_time);
      auto asn1_time = ccf::crypto::OpenSSL::Unique_X509_TIME(adjusted_str);
      auto converted_str = ccf::crypto::OpenSSL::to_x509_time_string(asn1_time);
      REQUIRE(converted_str == adjusted_str);
    }
  }
}

TEST_CASE("hmac")
{
  std::vector<uint8_t> key(32, 0);
  std::vector<uint8_t> zeros(64, 0);
  std::vector<uint8_t> mostly_zeros(64, 0);
  mostly_zeros[0] = 1;

  INFO("Same inputs, same hmac");
  {
    auto r0 = ccf::crypto::hmac(MDType::SHA256, key, zeros);
    auto r1 = ccf::crypto::hmac(MDType::SHA256, key, zeros);
    REQUIRE(r0 == r1);
  }

  INFO("Different inputs, different hmacs");
  {
    auto r0 = ccf::crypto::hmac(MDType::SHA256, key, zeros);
    auto r1 = ccf::crypto::hmac(MDType::SHA256, key, mostly_zeros);
    REQUIRE(r0 != r1);
  }
}

TEST_CASE("PEM to JWK and back")
{
  // More complete tests in end-to-end JS modules test
  // to compare with JWK reference implementation.
  auto kid = "my_kid";

  INFO("EC");
  {
    auto curves = {CurveID::SECP384R1, CurveID::SECP256R1};

    for (auto const& curve : curves)
    {
      auto kp = make_ec_key_pair(curve);
      auto pubk = make_ec_public_key(kp->public_key_pem());

      INFO("Public");
      {
        auto jwk = pubk->public_key_jwk();
        REQUIRE_FALSE(jwk.kid.has_value());
        jwk = pubk->public_key_jwk(kid);
        REQUIRE(jwk.kid.value() == kid);

        auto pubk2 = make_ec_public_key(jwk);
        auto jwk2 = pubk2->public_key_jwk(kid);
        REQUIRE(jwk == jwk2);
      }

      INFO("Private");
      {
        auto jwk = kp->private_key_jwk();
        REQUIRE_FALSE(jwk.kid.has_value());
        jwk = kp->private_key_jwk(kid);
        REQUIRE(jwk.kid.value() == kid);

        auto kp2 = make_ec_key_pair(jwk);
        auto jwk2 = kp2->private_key_jwk(kid);
        REQUIRE(jwk == jwk2);
      }
    }
  }

  INFO("RSA");
  {
    auto kp = make_rsa_key_pair();

    auto pubk = make_rsa_public_key(kp->public_key_pem());

    INFO("DER");
    {
      auto pubk_der = make_rsa_public_key(kp->public_key_der());
      REQUIRE(pubk_der->public_key_pem() == kp->public_key_pem());
    }

    INFO("Public");
    {
      auto jwk = pubk->public_key_jwk();
      REQUIRE_FALSE(jwk.kid.has_value());
      jwk = pubk->public_key_jwk(kid);
      REQUIRE(jwk.kid.value() == kid);

      auto pubk2 = make_rsa_public_key(jwk);
      auto jwk2 = pubk2->public_key_jwk(kid);
      REQUIRE(jwk == jwk2);
    }

    INFO("Private");
    {
      auto jwk = kp->private_key_jwk();
      REQUIRE_FALSE(jwk.kid.has_value());
      jwk = kp->private_key_jwk(kid);
      REQUIRE(jwk.kid.value() == kid);

      auto kp2 = make_rsa_key_pair(jwk);
      auto jwk2 = kp2->private_key_jwk(kid);

      REQUIRE(jwk == jwk2);
    }
  }

  INFO("EdDSA");
  {
    auto kp = make_eddsa_key_pair(CurveID::CURVE25519);
    auto pubk = make_eddsa_public_key(kp->public_key_pem());

    INFO("Public");
    {
      auto jwk = pubk->public_key_jwk_eddsa();
      REQUIRE_FALSE(jwk.kid.has_value());
      jwk = pubk->public_key_jwk_eddsa(kid);
      REQUIRE(jwk.kid.value() == kid);

      auto pubk2 = make_eddsa_public_key(jwk);
      auto jwk2 = pubk2->public_key_jwk_eddsa(kid);
      REQUIRE(jwk == jwk2);
    }

    INFO("Private");
    {
      auto jwk = kp->private_key_jwk_eddsa();
      REQUIRE_FALSE(jwk.kid.has_value());
      jwk = kp->private_key_jwk_eddsa(kid);
      REQUIRE(jwk.kid.value() == kid);

      auto kp2 = make_eddsa_key_pair(jwk);
      auto jwk2 = kp2->private_key_jwk_eddsa(kid);
      REQUIRE(jwk == jwk2);
    }
  }
}

TEST_CASE("Incremental hash")
{
  auto simple_hash = ccf::crypto::Sha256Hash(contents);

  INFO("Incremental hash");
  {
    INFO("Finalise before any update");
    {
      auto ihash = make_incremental_sha256();
      auto final_hash = ihash->finalise();
      REQUIRE(final_hash != simple_hash);
    }

    INFO("Update one by one");
    {
      auto ihash = make_incremental_sha256();
      for (auto const& c : contents)
      {
        ihash->update(c);
      }
      auto final_hash = ihash->finalise();
      REQUIRE(final_hash == simple_hash);

      REQUIRE_THROWS_AS(ihash->finalise(), std::logic_error);
    }

    INFO("Update in large chunks");
    {
      constexpr size_t chunk_size = 10;
      auto ihash = make_incremental_sha256();
      for (auto it = contents.begin(); it < contents.end(); it += chunk_size)
      {
        auto end =
          it + chunk_size > contents.end() ? contents.end() : it + chunk_size;
        ihash->update(std::vector<uint8_t>{it, end});
      }
      auto final_hash = ihash->finalise();
      REQUIRE(final_hash == simple_hash);

      REQUIRE_THROWS_AS(ihash->finalise(), std::logic_error);
    }
  }
}

TEST_CASE("Sign and verify with RSA key")
{
  const auto kp = ccf::crypto::make_rsa_key_pair();
  const auto pub = ccf::crypto::make_rsa_public_key(kp->public_key_pem());
  const auto mdtype = ccf::crypto::MDType::SHA256;
  vector<uint8_t> contents(contents_.begin(), contents_.end());

  {
    constexpr size_t salt_length = 0;
    const auto sig = kp->sign(contents, mdtype, salt_length);
    REQUIRE(pub->verify(
      contents.data(),
      contents.size(),
      sig.data(),
      sig.size(),
      mdtype,
      RSAPadding::PKCS_PSS,
      salt_length));
  }

  {
    constexpr size_t sign_salt_length = 0, verify_salt_legth = 32;
    const auto sig = kp->sign(contents, mdtype, sign_salt_length);
    REQUIRE(!pub->verify(
      contents.data(),
      contents.size(),
      sig.data(),
      sig.size(),
      mdtype,
      RSAPadding::PKCS_PSS,
      verify_salt_legth));
  }

  {
    constexpr size_t sign_salt_length = 32, verify_salt_legth = 32;
    const auto sig = kp->sign(contents, mdtype, sign_salt_length);
    REQUIRE(pub->verify(
      contents.data(),
      contents.size(),
      sig.data(),
      sig.size(),
      mdtype,
      RSAPadding::PKCS_PSS,
      verify_salt_legth));
  }
}

TEST_CASE("COSE sign & verify")
{
  std::shared_ptr<ECKeyPair_OpenSSL> kp =
    std::dynamic_pointer_cast<ECKeyPair_OpenSSL>(
      ccf::crypto::make_ec_key_pair(CurveID::SECP384R1));

  std::vector<uint8_t> payload{1, 10, 42, 43, 44, 45, 100};

  using namespace ccf;
  std::vector<cbor::MapItem> phdr;

  phdr.emplace_back(cbor::make_signed(35), cbor::make_signed(53));
  phdr.emplace_back(cbor::make_signed(36), cbor::make_string("thirsty six"));
  phdr.emplace_back(cbor::make_string("hungry seven"), cbor::make_signed(47));
  phdr.emplace_back(
    cbor::make_string("string key"), cbor::make_string("string value"));

  auto phdr_map = cbor::make_map(std::move(phdr));
  auto cose_sign = cose_sign1(*kp, phdr_map, payload);

  if constexpr (false) // enable to see the whole cose_sign as byte string
  {
    std::cout << "Public key: " << kp->public_key_pem().str() << std::endl;
    std::cout << "Serialised cose: " << std::hex << std::uppercase
              << std::setw(2) << std::setfill('0');
    for (uint8_t x : cose_sign)
      std::cout << static_cast<int>(x) << ' ';
    std::cout << std::endl;
    std::cout << "Raw payload: ";
    for (uint8_t x : payload)
      std::cout << static_cast<int>(x) << ' ';
    std::cout << std::endl;
  }

  require_match_headers(
    {35, 53},
    {36, "thirsty six"},
    {"hungry seven", 47},
    {"string key", "string value"},
    cose_sign);

  auto cose_verifier =
    ccf::crypto::make_cose_verifier_from_key(kp->public_key_pem());

  REQUIRE(cose_verifier->verify_detached(cose_sign, payload));

  // Wrong payload, must not pass verification.
  REQUIRE_FALSE(
    cose_verifier->verify_detached(cose_sign, std::vector<uint8_t>{1, 2, 3}));

  // Empty headers and payload handled correctly
  cose_sign = cose_sign1(*kp, ccf::cbor::make_map({}), {});
  require_match_headers(
    {35, std::nullopt},
    {36, std::nullopt},
    {"hungry seven", std::nullopt},
    {"string key", std::nullopt},
    cose_sign);

  REQUIRE(cose_verifier->verify_detached(cose_sign, {}));
}

TEST_CASE("COSE algorithm validation")
{
  INFO("EC key curves must match COSE algorithm");
  {
    // P-256 (secp256r1) requires COSE alg -7
    auto p256_kp = ccf::crypto::make_ec_key_pair(CurveID::SECP256R1);
    auto p256_pubkey = std::dynamic_pointer_cast<ECPublicKey_OpenSSL>(
      ccf::crypto::make_ec_public_key(p256_kp->public_key_pem()));

    // Correct algorithm should work
    REQUIRE_NOTHROW(p256_pubkey->check_is_cose_compatible(-7));

    // Wrong algorithms should throw
    REQUIRE_THROWS_WITH(
      p256_pubkey->check_is_cose_compatible(-35),
      "secp256r1 key cannot be used with COSE algorithm -35");
    REQUIRE_THROWS_WITH(
      p256_pubkey->check_is_cose_compatible(-36),
      "secp256r1 key cannot be used with COSE algorithm -36");

    // Unknown COSE algorithm for EC keys should throw
    REQUIRE_THROWS_WITH(
      p256_pubkey->check_is_cose_compatible(-999),
      "secp256r1 key cannot be used with COSE algorithm -999");
    REQUIRE_THROWS_WITH(
      p256_pubkey->check_is_cose_compatible(42),
      "secp256r1 key cannot be used with COSE algorithm 42");

    // P-384 (secp384r1) requires COSE alg -35
    auto p384_kp = ccf::crypto::make_ec_key_pair(CurveID::SECP384R1);
    auto p384_pubkey = std::dynamic_pointer_cast<ECPublicKey_OpenSSL>(
      ccf::crypto::make_ec_public_key(p384_kp->public_key_pem()));

    // Correct algorithm should work
    REQUIRE_NOTHROW(p384_pubkey->check_is_cose_compatible(-35));

    // Wrong algorithms should throw
    REQUIRE_THROWS_WITH(
      p384_pubkey->check_is_cose_compatible(-7),
      "secp384r1 key cannot be used with COSE algorithm -7");
    REQUIRE_THROWS_WITH(
      p384_pubkey->check_is_cose_compatible(-36),
      "secp384r1 key cannot be used with COSE algorithm -36");

    // Unknown COSE algorithm for EC keys should throw
    REQUIRE_THROWS_WITH(
      p384_pubkey->check_is_cose_compatible(0),
      "secp384r1 key cannot be used with COSE algorithm 0");
    REQUIRE_THROWS_WITH(
      p384_pubkey->check_is_cose_compatible(-100),
      "secp384r1 key cannot be used with COSE algorithm -100");
  }

  INFO("RSA keys accept PS256, PS384, and PS512");
  {
    auto rsa_kp = ccf::crypto::make_rsa_key_pair();
    auto rsa_pubkey = std::dynamic_pointer_cast<RSAPublicKey_OpenSSL>(
      ccf::crypto::make_rsa_public_key(rsa_kp->public_key_pem()));

    // All PS algorithms should work
    REQUIRE_NOTHROW(rsa_pubkey->check_is_cose_compatible(-37)); // PS256
    REQUIRE_NOTHROW(rsa_pubkey->check_is_cose_compatible(-38)); // PS384
    REQUIRE_NOTHROW(rsa_pubkey->check_is_cose_compatible(-39)); // PS512

    // Non-PS algorithms should throw
    REQUIRE_THROWS_WITH(
      rsa_pubkey->check_is_cose_compatible(-7),
      "Incompatible cose algorithm -7 for RSA");
    REQUIRE_THROWS_WITH(
      rsa_pubkey->check_is_cose_compatible(-35),
      "Incompatible cose algorithm -35 for RSA");

    // Unknown COSE algorithm for RSA keys should throw
    REQUIRE_THROWS_WITH(
      rsa_pubkey->check_is_cose_compatible(1),
      "Incompatible cose algorithm 1 for RSA");
    REQUIRE_THROWS_WITH(
      rsa_pubkey->check_is_cose_compatible(-256),
      "Incompatible cose algorithm -256 for RSA");
    REQUIRE_THROWS_WITH(
      rsa_pubkey->check_is_cose_compatible(999),
      "Incompatible cose algorithm 999 for RSA");
  }
}

TEST_CASE("Sign and verify a chain with an intermediate and different subjects")
{
  auto root_kp = ccf::crypto::make_ec_key_pair(CurveID::SECP384R1);
  auto root_cert = generate_self_signed_cert(root_kp, "CN=root");

  auto intermediate_kp = ccf::crypto::make_ec_key_pair(CurveID::SECP384R1);
  auto intermediate_csr = intermediate_kp->create_csr("CN=intermediate", {});

  std::string valid_from = "20210311000000Z";
  std::string valid_to = "20230611235959Z";
  auto intermediate_cert =
    root_kp->sign_csr(root_cert, intermediate_csr, valid_from, valid_to, true);

  auto leaf_kp = ccf::crypto::make_ec_key_pair(CurveID::SECP384R1);
  auto leaf_csr = leaf_kp->create_csr("CN=leaf", {});
  auto leaf_cert = intermediate_kp->sign_csr(
    intermediate_cert, leaf_csr, valid_from, valid_to, true);

  auto verifier = ccf::crypto::make_verifier(leaf_cert.raw());
  auto rc = verifier->verify_certificate(
    {&root_cert}, {&intermediate_cert}, true /* ignore time */
  );

  // Failed with pathlen: 0
  REQUIRE(rc);

  // Missing intermediate
  rc = verifier->verify_certificate(
    {&root_cert}, {}, true /* ignore time */
  );

  REQUIRE(!rc);

  // Invalid root
  rc = verifier->verify_certificate(
    {&leaf_cert}, {}, true /* ignore time */
  );

  REQUIRE(!rc);
}

TEST_CASE("Decrypt should validate integrity")
{
  auto key = get_entropy()->random(16);
  std::vector<uint8_t> expected_plaintext = {0xde, 0xad, 0xbe, 0xef};
  auto ciphertext = ccf::crypto::aes_gcm_encrypt(key, expected_plaintext);
  auto decrypted_plaintext = ccf::crypto::aes_gcm_decrypt(key, ciphertext);

  CHECK_EQ(expected_plaintext, decrypted_plaintext);

  // corrupt part of ciphertext
  auto broken_ciphertext = std::vector<uint8_t>(ciphertext);
  broken_ciphertext[ciphertext.size() / 2] =
    ~broken_ciphertext[ciphertext.size() / 2];

  CHECK_THROWS(ccf::crypto::aes_gcm_decrypt(key, broken_ciphertext));
}

TEST_CASE("Do not trust non-ca certs")
{
  auto kp = ccf::crypto::make_ec_key_pair(CurveID::SECP384R1);
  auto ca_cert = generate_self_signed_cert(kp, "CN=name");

  auto ca_cert_verifier = ccf::crypto::make_verifier(ca_cert.raw());
  // CA cert is accepted as a trusted root (self-signed, CA:TRUE).
  REQUIRE(ca_cert_verifier->verify_certificate({&ca_cert}, {}, true));

  ccf::crypto::Pem non_ca_cert;
  {
    constexpr size_t certificate_validity_period_days = 365;
    using namespace std::literals;
    auto valid_from =
      ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);
    auto valid_to = compute_cert_valid_to_string(
      valid_from, certificate_validity_period_days);
    std::vector<SubjectAltName> subject_alt_names = {};
    non_ca_cert =
      kp->self_sign("CN=name", valid_from, valid_to, subject_alt_names, false);
  }

  auto non_ca_cert_verifier = ccf::crypto::make_verifier(non_ca_cert.raw());
  // Non-CA cert must NOT be accepted as a trusted root (self-signed but
  // CA:FALSE).
  REQUIRE_FALSE(
    non_ca_cert_verifier->verify_certificate({&non_ca_cert}, {}, true));
}

TEST_CASE("Sha256 hex conversions")
{
  {
    INFO("Sha256 via operator<<");

    const std::string hex{
      "f3d25d4670b742f035c1f1d9fffa2eba676ddc491c5288403fa1091e62f26dd6"};
    auto hash = ccf::crypto::Sha256Hash::from_hex_string(hex);

    std::stringstream ss;
    ss << hash;

    REQUIRE(ss.str() == hex);
  }
}

TEST_CASE("Carriage returns in PEM certificates")
{
  const std::string single_cert =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIByDCCAU6gAwIBAgIQOBe5SrcwReWmSzTjzj2HDjAKBggqhkjOPQQDAzATMREw\n"
    "DwYDVQQDDAhDQ0YgTm9kZTAeFw0yMzA1MTcxMzUwMzFaFw0yMzA1MTgxMzUwMzBa\n"
    "MBMxETAPBgNVBAMMCENDRiBOb2RlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE74qL\n"
    "Ac/45tiriN5MuquYhHVdMGQRvYSm08HBfYcODtET88qC0A39o6Y2TmfbIn6BdjMG\n"
    "kD58o377ZMTaApQu/oJcwt7qZ9/LE8j8WU2qHn0cPTlpwH/2tiud2w+U3voSo2cw\n"
    "ZTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS9FJNwWSXtUpHaBV57EwTW\n"
    "oM8vHjAfBgNVHSMEGDAWgBS9FJNwWSXtUpHaBV57EwTWoM8vHjAPBgNVHREECDAG\n"
    "hwR/xF96MAoGCCqGSM49BAMDA2gAMGUCMQDKxpjPToJ7VSqKqQSeMuW9tr4iL+9I\n"
    "7gTGdGwiIYV1qTSS35Sk9XQZ0VpSa58c/5UCMEgmH71k7XlTGVUypm4jAgjpC46H\n"
    "s+hJpGMvyD9dKzEpZgmZYtghbyakUkwBiqmFQA==\n"
    "-----END CERTIFICATE-----";
  Pem cert_pem(single_cert);
  auto cert_vec = cert_pem.raw();
  OpenSSL::Unique_BIO certbio(cert_vec);
  OpenSSL::Unique_X509 cert(certbio, true);
  REQUIRE_NE(cert, nullptr);

  const std::string single_cert_cr =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIByDCCAU6gAwIBAgIQOBe5SrcwReWmSzTjzj2HDjAKBggqhkjOPQQDAzATMREw\r\n"
    "DwYDVQQDDAhDQ0YgTm9kZTAeFw0yMzA1MTcxMzUwMzFaFw0yMzA1MTgxMzUwMzBa\r\n"
    "MBMxETAPBgNVBAMMCENDRiBOb2RlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE74qL\r\n"
    "Ac/45tiriN5MuquYhHVdMGQRvYSm08HBfYcODtET88qC0A39o6Y2TmfbIn6BdjMG\r\n"
    "kD58o377ZMTaApQu/oJcwt7qZ9/LE8j8WU2qHn0cPTlpwH/2tiud2w+U3voSo2cw\r\n"
    "ZTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS9FJNwWSXtUpHaBV57EwTW\r\n"
    "oM8vHjAfBgNVHSMEGDAWgBS9FJNwWSXtUpHaBV57EwTWoM8vHjAPBgNVHREECDAG\r\n"
    "hwR/xF96MAoGCCqGSM49BAMDA2gAMGUCMQDKxpjPToJ7VSqKqQSeMuW9tr4iL+9I\r\n"
    "7gTGdGwiIYV1qTSS35Sk9XQZ0VpSa58c/5UCMEgmH71k7XlTGVUypm4jAgjpC46H\r\n"
    "s+hJpGMvyD9dKzEpZgmZYtghbyakUkwBiqmFQA==\r\n"
    "-----END CERTIFICATE-----";
  Pem cert_pem_cr(single_cert_cr);
  auto cert_vec_cr = cert_pem_cr.raw();
  OpenSSL::Unique_BIO certbio_cr(cert_vec_cr);
  OpenSSL::Unique_X509 cert_cr(certbio_cr, true);
  REQUIRE_NE(cert_cr, nullptr);
}