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
  constexpr auto DEVICE = "/dev/sev";

  struct GuestRequest
  {
    uint8_t msg_version; // message version number (must be non-zero)
    uint64_t req_data;
    uint64_t resp_data;
    uint64_t fw_err; // firmware error code on failure (see psp-sev.h)
  };

  // Table 99
  enum MsgType
  {
    MSG_TYPE_INVALID = 0,
    MSG_CPUID_REQ,
    MSG_CPUID_RSP,
    MSG_KEY_REQ,
    MSG_KEY_RSP,
    MSG_REPORT_REQ,
    MSG_REPORT_RSP,
    MSG_EXPORT_REQ,
    MSG_EXPORT_RSP,
    MSG_IMPORT_REQ,
    MSG_IMPORT_RSP,
    MSG_ABSORB_REQ,
    MSG_ABSORB_RSP,
    MSG_VMRK_REQ,
    MSG_VMRK_RSP,
    MSG_TYPE_MAX
  };

  // Table 20
  struct AttestationReq
  {
    uint8_t report_data[snp_attestation_report_data_size];
    uint32_t vmpl;
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

  struct AttestationRespWrapper
  {
    struct AttestationResp resp;
    uint8_t padding[4000 - sizeof(struct AttestationResp)];
  };
#pragma pack(pop)

  constexpr char SEV_GUEST_IOC_TYPE = 'S';
  constexpr int SEV_SNP_GUEST_MSG_REPORT =
    _IOWR(SEV_GUEST_IOC_TYPE, 0x1, struct snp::ioctl6::GuestRequest);

  static inline bool is_sev_snp()
  {
    return access(DEVICE, F_OK) == 0;
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
        .req_data = reinterpret_cast<uint64_t>(&req),
        .resp_data = reinterpret_cast<uint64_t>(&resp_wrapper),
        .fw_err = 0};

      int rc = ioctl(fd, SEV_SNP_GUEST_MSG_REPORT, &payload);
      if (rc < 0)
      {
        CCF_APP_FAIL("IOCTL call failed: {}", strerror(errno));
        CCF_APP_FAIL("Payload error: {}", payload.fw_err);
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