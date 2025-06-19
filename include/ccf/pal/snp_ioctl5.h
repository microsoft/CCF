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

/* linux kernel 5.15.* versions of the ioctls that talk to the PSP */

namespace ccf::pal::snp::ioctl5
{
  constexpr auto DEVICE = "/dev/sev";

  struct GuestRequest
  {
    uint8_t req_msg_type;
    uint8_t rsp_msg_type;
    uint8_t msg_version;
    uint16_t request_len;
    uint64_t request_uaddr;
    uint16_t response_len;
    uint64_t response_uaddr;
    uint32_t error; /* firmware error code on failure (see psp-sev.h) */
  };

  // Table 102
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

  // Table 22
#pragma pack(push, 1)
  struct AttestationReq
  {
    uint8_t report_data[snp_attestation_report_data_size];
    uint32_t vmpl = 0;
    uint8_t reserved[28];
  };
#pragma pack(pop)

  // Table 25
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
#pragma pack(pop)

  constexpr char SEV_GUEST_IOC_TYPE = 'S';
  constexpr int SEV_SNP_GUEST_MSG_REPORT =
    _IOWR(SEV_GUEST_IOC_TYPE, 0x1, struct snp::ioctl5::GuestRequest);

  static inline bool is_sev_snp()
  {
    return access(DEVICE, W_OK) == 0;
  }

  class Attestation : public AttestationInterface
  {
    AttestationReq req = {};
    AttestationResp resp = {};

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
        throw std::logic_error(
          fmt::format("Failed to open \"{}\" ({})", DEVICE, fd));
      }
      auto close_fd = [&fd]() {
        if (fd >= 0)
        {
          close(fd);
        }
      };
      std::unique_ptr<int, decltype(close_fd)> fd_guard(&fd, close_fd);

      // Documented at
      // https://www.kernel.org/doc/html/latest/virt/coco/sev-guest.html
      GuestRequest payload = {
        .req_msg_type = MSG_REPORT_REQ,
        .rsp_msg_type = MSG_REPORT_RSP,
        .msg_version = 1,
        .request_len = sizeof(req),
        .request_uaddr = reinterpret_cast<uint64_t>(&req),
        .response_len = sizeof(resp),
        .response_uaddr = reinterpret_cast<uint64_t>(&resp),
        .error = 0};

      int rc = ioctl(fd, SEV_SNP_GUEST_MSG_REPORT, &payload);
      if (rc < 0)
      {
        const auto msg = fmt::format(
          "Failed to issue ioctl SEV_SNP: {} payload error: {}",
          strerror(errno),
          payload.error);
        throw std::logic_error(msg);
      }
    }

    const snp::Attestation& get() const override
    {
      return resp.report;
    }

    std::vector<uint8_t> get_raw() override
    {
      auto quote_bytes = reinterpret_cast<uint8_t*>(&resp.report);
      return {quote_bytes, quote_bytes + resp.report_size};
    }
  };
}
