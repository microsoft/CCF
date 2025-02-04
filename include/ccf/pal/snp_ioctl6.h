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

  // Table 22
#pragma pack(push, 1)
  struct AttestationReq
  {
    uint8_t report_data[snp_attestation_report_data_size];
    uint32_t vmpl = 0;
    uint8_t reserved[28]; // needs to be zero
  }; // snp_report_req in (linux) include/uapi/linux/sev-guest.h
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

  static_assert(sizeof(AttestationResp) < 4000);
  struct AttestationRespWrapper
  {
    struct AttestationResp resp;
    uint8_t padding[4000 - sizeof(struct AttestationResp)];
  };
#pragma pack(pop)

#pragma pack(push, 1)
  // Table 20 
  // bit 0 is the first bit
  struct DerivedKeyGuestFieldSelect
  {
    uint32_t guest_policy : 1;
    uint32_t image_id : 1;
    uint32_t family_id : 1;
    uint32_t measurement : 1;
    uint32_t guest_svn : 1;
    uint32_t tcb_version : 1;
    uint64_t reserved : 58;
  };
  static_assert(sizeof(DerivedKeyGuestFieldSelect) == 8);

  // Table 19
  struct KeySelect
  {
    uint8_t root_key_sel : 1;
    uint8_t key_sel : 2;
    uint32_t reserved : 29;
  };
  static_assert(sizeof(KeySelect) == 4);

  struct DerivedKeyReq
  {
    KeySelect key_select;
    uint32_t reserved;
    DerivedKeyGuestFieldSelect guest_field_select;
    uint32_t vmpl = 0;
    uint32_t guest_svn;
    uint64_t tcb_version;
  }; // snp_derived_key_req in (linux) include/uapi/linux/sev-guest.h
#pragma pack(pop)

// Table 21
#pragma pack(push, 1)
  struct DerivedKeyResp
  {
    uint32_t status;
    uint8_t reserved[0x20 - 0x04];
    uint8_t data[32];
  }; // snp_derived_key_req in (linux) include/uapi/linux/sev-guest.h
  static_assert(sizeof(DerivedKeyResp) < 4000);
  struct DerivedKeyRespWrapper
  {
    struct DerivedKeyResp resp;
    uint8_t padding[4000 - sizeof(struct DerivedKeyResp)];
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
  template <typename Req, typename Resp>
  struct GuestRequest
  {
    /* Message version number */
    uint32_t msg_version = 1;

    /* Request and response structure address */
    Req* req_data;
    Resp* resp_wrapper;

    /* bits[63:32]: VMM error code, bits[31:0] firmware error code (see
     * psp-sev.h) */
    ExitInfo exit_info;
  };
  using GuestRequestAttestation =
    GuestRequest<AttestationReq, AttestationRespWrapper>;
  using GuestRequestDerivedKey =
    GuestRequest<DerivedKeyReq, DerivedKeyRespWrapper>;

  // From linux/include/uapi/linux/sev-guest.h
  constexpr char SEV_GUEST_IOC_TYPE = 'S';
  constexpr int SEV_SNP_GUEST_MSG_REPORT =
    _IOWR(SEV_GUEST_IOC_TYPE, 0x0, GuestRequestAttestation);
  constexpr int SEV_SNP_GUEST_MSG_DERIVED_KEY =
    _IOWR(SEV_GUEST_IOC_TYPE, 0x1, GuestRequestDerivedKey);

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
        throw std::logic_error(
          fmt::format("Failed to open \"{}\" ({})", DEVICE, fd));
      }

      // Documented at
      // https://www.kernel.org/doc/html/latest/virt/coco/sev-guest.html
      GuestRequestAttestation payload = {
        .req_data = &req, .resp_wrapper = &resp_wrapper, .exit_info = {0}};

      int rc = ioctl(fd, SEV_SNP_GUEST_MSG_REPORT, &payload);
      if (rc < 0)
      {
        LOG_FAIL_FMT("IOCTL call failed: {}", strerror(errno));
        LOG_FAIL_FMT(
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

  class DerivedKey
  {
    DerivedKeyRespWrapper resp_wrapper = {};

  public:
    DerivedKey()
    {
      int fd = open(DEVICE, O_RDWR | O_CLOEXEC);
      if (fd < 0)
      {
        throw std::logic_error(
          fmt::format("Failed to open \"{}\" ({})", DEVICE, fd));
      }

      // This req by default mixes in HostData and the CPU VCEK
      DerivedKeyReq req = {};
      // We must also mix in the measurement
      req.guest_field_select.measurement = 1;
      GuestRequestDerivedKey payload = {
        .req_data = &req, .resp_wrapper = &resp_wrapper, .exit_info = {0}};
      int rc = ioctl(fd, SEV_SNP_GUEST_MSG_DERIVED_KEY, &payload);
      if (rc < 0)
      {
        LOG_FAIL_FMT("IOCTL call failed: {}", strerror(errno));
        LOG_FAIL_FMT(
          "Exit info, fw_error: {} vmm_error: {}",
          payload.exit_info.errors.fw,
          payload.exit_info.errors.vmm);
        throw std::logic_error(
          "Failed to issue ioctl SEV_SNP_GUEST_MSG_DERIVED_KEY");
      }
      if ((*payload.resp_wrapper).resp.status != 0)
      {
        LOG_FAIL_FMT(
          "SNP_GUEST_DERIVED_KEY failed: {}", resp_wrapper.resp.status);
        throw std::logic_error(
          "Failed to issue ioctl SEV_SNP_GUEST_MSG_DERIVED_KEY");
      }
    }

    const std::span<const uint8_t> get_raw()
    {
      return std::span<const uint8_t>{resp_wrapper.resp.data};
    }
  };
}