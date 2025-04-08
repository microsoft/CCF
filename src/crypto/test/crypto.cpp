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
#include "ccf/pal/snp_ioctl6.h"
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

void funky_memory_dancing(size_t how_long)
{
  std::vector<uint8_t> v;
  for (size_t i = 0; i < how_long; i++)
  {
    v.push_back(rand() % 256);
  }
  for (size_t i = 0; i < how_long; i++)
  {
    std::cout << "Dance with me " << v[i] << '\n';
  }
}

TEST_CASE("Sign and verify a chain with an intermediate and different subjects")
{
  using namespace ccf::pal::snp::ioctl6;

  std::vector<uint8_t> report_data(32, 0x8);
  AttestationReq req = {};
  std::copy(report_data.begin(), report_data.end(), req.report_data);

  int fd = open(DEVICE, O_RDWR | O_CLOEXEC);
  if (fd < 0)
  {
    throw std::logic_error(
      fmt::format("Failed to open \"{}\" ({})", DEVICE, fd));
  }

  // Documented at
  // https://www.kernel.org/doc/html/latest/virt/coco/sev-guest.html
  SafetyPadding<AttestationResp> padded_resp = {};
  GuestRequestAttestation payload = {
    .req_data = &req, .resp_wrapper = &padded_resp, .exit_info = {0}};

  int rc = ioctl(fd, SEV_SNP_GUEST_MSG_REPORT, &payload);
  if (rc < 0)
  {
    const auto msg = fmt::format(
      "Failed to issue ioctl SEV_SNP_GUEST_MSG_REPORT: {} fw_error: {} "
      "vmm_error: {}",
      strerror(errno),
      payload.exit_info.errors.fw,
      payload.exit_info.errors.vmm);
    throw std::logic_error(msg);
  }

  if (!safety_padding_intact(padded_resp))
  {
    // This occurs if a kernel/firmware upgrade causes the response to
    // overflow the struct so it is better to fail early than deal with
    // memory corruption.
    throw std::logic_error("IOCTL overwrote safety padding.");
  }

  funky_memory_dancing(64);
  funky_memory_dancing(128);
  funky_memory_dancing(256);
  funky_memory_dancing(2048);
  funky_memory_dancing(4096);
  funky_memory_dancing(8192);
  funky_memory_dancing(8192 * 8);
}