// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/pal/attestation_sev_snp.h"

#include <algorithm>
#include <array>
#include <fcntl.h>
#include <openssl/crypto.h>
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

#pragma pack(push, 1)
  template <typename T>
  struct SafetyPadding
  {
    T data;
    uint8_t safety_padding[1024] = {0};
  };

  template <typename T>
  bool safety_padding_intact(SafetyPadding<T> data)
  {
    return std::all_of(
      std::begin(data.safety_padding),
      std::end(data.safety_padding),
      [](uint8_t e) { return e == 0; });
  }
#pragma pack(pop)

  // Table 22
#pragma pack(push, 1)
  struct AttestationReq
  {
    uint8_t report_data[snp_attestation_report_data_size];
    uint32_t vmpl = 0;
    uint8_t reserved[28] = {0};
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
    uint32_t reserved = 0;
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
    GuestRequest<AttestationReq, SafetyPadding<AttestationResp>>;
  using GuestRequestDerivedKey =
    GuestRequest<DerivedKeyReq, SafetyPadding<DerivedKeyResp>>;

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
    SafetyPadding<AttestationResp> padded_resp = {};

  public:
    Attestation(const PlatformAttestationReportData& report_data)
    {
      AttestationReq req = {};
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
    }

    const snp::Attestation& get() const override
    {
      return padded_resp.data.report;
    }

    std::vector<uint8_t> get_raw() override
    {
      auto quote_bytes = reinterpret_cast<uint8_t*>(&padded_resp.data.report);
      return {quote_bytes, quote_bytes + padded_resp.data.report_size};
    }
  };

  class DerivedKey
  {
    SafetyPadding<DerivedKeyResp> padded_resp = {};

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
        .req_data = &req, .resp_wrapper = &padded_resp, .exit_info = {0}};
      int rc = ioctl(fd, SEV_SNP_GUEST_MSG_DERIVED_KEY, &payload);
      if (rc < 0)
      {
        const auto msg = fmt::format(
          "Failed to issue ioctl SEV_SNP_GUEST_MSG_DERIVED_KEY: {} fw_error: "
          "{} vmm_error: {}",
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

      if (padded_resp.data.status != 0)
      {
        const auto msg = fmt::format(
          "Failed to issue ioctl SEV_SNP_GUEST_MSG_DERIVED_KEY: {}",
          padded_resp.data.status);
        throw std::logic_error(msg);
      }
    }

    ~DerivedKey()
    {
      OPENSSL_cleanse(padded_resp.data.data, sizeof(padded_resp.data.data));
    }

    std::span<const uint8_t> get_raw()
    {
      return std::span<const uint8_t>{padded_resp.data.data};
    }
  };
}