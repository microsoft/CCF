// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/attestation_sev_snp.h"

#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

// Based on the SEV-SNP ABI Spec document at
// https://www.amd.com/system/files/TechDocs/56860.pdf

/* linux kernel 6.* versions of the ioctls that talk to the PSP */

namespace ccf::pal::snp::ioctl6
{
  constexpr auto DEVICE = "/dev/sev-guest";

  // Table 20
  struct AttestationReq
  {
    uint8_t report_data[snp_attestation_report_data_size];
    uint32_t vmpl = 0;
    uint8_t reserved[28]; // needs to be zero
  }; // aka snp_report_req in (linux) include/uapi/linux/sev-guest.h

  // Table 23
#pragma pack(push, 1)
  struct AttestationResp
  {
    uint32_t status;
    uint32_t report_size;
    uint8_t reserved[0x20 - 0x8];
    struct Attestation report;
    uint8_t padding[64];
    // padding to the size of SEV_SNP_REPORT_RSP_BUF_SZ (i.e., 1280 bytes)
  };

  static_assert(sizeof(AttestationResp) < 4000);
  struct AttestationRespWrapper
  {
    struct AttestationResp resp;
    uint8_t padding[4000 - sizeof(struct AttestationResp)];
  };
#pragma pack(pop)

  struct ExitInfoErrors
  {
    uint32_t fw;
    uint32_t vmm;
  };

  union ExitInfo
  {
    uint64_t whole;
    ExitInfoErrors errors;
  };

  // https://www.kernel.org/doc/html/v6.4/virt/coco/sev-guest.html#api-description
  struct GuestRequest
  {
    /* Message version number */
    uint32_t msg_version;

    /* Request and response structure address */
    AttestationReq* req_data;
    AttestationRespWrapper* resp_wrapper;

    /* bits[63:32]: VMM error code, bits[31:0] firmware error code (see
     * psp-sev.h) */
    ExitInfo exit_info;
  };

  constexpr char SEV_GUEST_IOC_TYPE = 'S';
  constexpr int SEV_SNP_GUEST_MSG_REPORT =
    _IOWR(SEV_GUEST_IOC_TYPE, 0x0, struct snp::ioctl6::GuestRequest);

  static inline bool is_sev_snp()
  {
    return access(DEVICE, W_OK) == 0;
  }

  class Attestation : public AttestationInterface
  {
    AttestationReq req = {};
    AttestationRespWrapper resp_wrapper = {};

  public:
    Attestation(const PlatformAttestationReportData& report_data)
    {
      if (report_data.data.size() <= snp_attestation_report_data_size)
      {
        std::copy(
          report_data.data.begin(), report_data.data.end(), req.report_data);
      }
      else
      {
        throw std::logic_error(
          "User-defined report data is larger than available space");
      }

      int fd = open(DEVICE, O_RDWR | O_CLOEXEC);
      if (fd < 0)
      {
        throw std::logic_error(fmt::format("Failed to open \"{}\"", DEVICE));
      }

      // Documented at
      // https://www.kernel.org/doc/html/latest/virt/coco/sev-guest.html
      GuestRequest payload = {
        .msg_version = 1,
        .req_data = &req,
        .resp_wrapper = &resp_wrapper,
        .exit_info = {0}};

      int rc = ioctl(fd, SEV_SNP_GUEST_MSG_REPORT, &payload);
      if (rc < 0)
      {
        CCF_APP_FAIL("IOCTL call failed: {}", strerror(errno));
        CCF_APP_FAIL(
          "Exit info, fw_error: {} vmm_error: {}",
          payload.exit_info.errors.fw,
          payload.exit_info.errors.vmm);
        throw std::logic_error(
          "Failed to issue ioctl SEV_SNP_GUEST_MSG_REPORT");
      }
    }

    const snp::Attestation& get() const override
    {
      return resp_wrapper.resp.report;
    }

    std::vector<uint8_t> get_raw() override
    {
      auto quote_bytes = reinterpret_cast<uint8_t*>(&resp_wrapper.resp.report);
      return {quote_bytes, quote_bytes + resp_wrapper.resp.report_size};
    }
  };
}