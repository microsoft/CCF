// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"
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
  // Helper to add padding to a struct, so that the resulting struct has some
  // minimum size. As a minor detail, the padding will be initialised to 0.
  template <typename T, size_t N>
  struct PaddedTo : public T
  {
    static_assert(
      sizeof(T) < N, "No padding possible - struct is already N bytes");
    static constexpr size_t num_padding_bytes = N - sizeof(T);
    uint8_t padding[num_padding_bytes] = {0};
  };

  // Helper which surrounds a struct with some sentinel bytes, to aid detection
  // of out-of-bounds writes.
  template <typename T>
  struct IoctlSentinel
  {
    static constexpr size_t num_sentinel_bytes = 1024;

    static constexpr uint8_t default_sentinel = 0x42;

    static constexpr uint8_t pre_sentinel_first = 0xAA;
    static constexpr uint8_t pre_sentinel_last = 0xBB;

    static constexpr uint8_t post_sentinel_first = 0xCC;
    static constexpr uint8_t post_sentinel_last = 0xDD;

    uint8_t pre_sentinels[num_sentinel_bytes] = {0};
    T data;
    uint8_t post_sentinels[num_sentinel_bytes] = {0};

    IoctlSentinel()
    {
      memset(pre_sentinels, default_sentinel, num_sentinel_bytes);
      pre_sentinels[0] = pre_sentinel_first;
      pre_sentinels[num_sentinel_bytes - 1] = pre_sentinel_last;

      memset(post_sentinels, default_sentinel, num_sentinel_bytes);
      post_sentinels[0] = post_sentinel_first;
      post_sentinels[num_sentinel_bytes - 1] = post_sentinel_last;
    }

    bool sentinels_intact() const
    {
      if (pre_sentinels[0] != pre_sentinel_first)
      {
        return false;
      }
      if (pre_sentinels[num_sentinel_bytes - 1] != pre_sentinel_last)
      {
        return false;
      }

      if (post_sentinels[0] != post_sentinel_first)
      {
        return false;
      }
      if (post_sentinels[num_sentinel_bytes - 1] != post_sentinel_last)
      {
        return false;
      }

      return std::all_of(
               std::next(std::begin(pre_sentinels)),
               std::prev(std::end(pre_sentinels)),
               [](uint8_t e) { return e == default_sentinel; }) &&
        std::all_of(
               std::next(std::begin(post_sentinels)),
               std::prev(std::end(post_sentinels)),

               [](uint8_t e) { return e == default_sentinel; });
    }
  };
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

  // Table 20 of the SEVSNP ABI
  constexpr uint8_t GUEST_FIELD_SELECT_GUEST_POLICY = 0b00000001;
  constexpr uint8_t GUEST_FIELD_SELECT_IMAGE_ID = 0b00000010;
  constexpr uint8_t GUEST_FIELD_SELECT_FAMILY_ID = 0b00000100;
  constexpr uint8_t GUEST_FIELD_SELECT_MEASUREMENT = 0b00001000;
  constexpr uint8_t GUEST_FIELD_SELECT_GUEST_SVN = 0b00010000;
  constexpr uint8_t GUEST_FIELD_SELECT_TCB_VERSION = 0b00100000;

#pragma pack(push, 1)
  struct DerivedKeyReq
  {
    uint32_t key_select = 0;
    uint32_t reserved = 0;
    uint64_t guest_field_select = 0;
    uint32_t vmpl = 0;
    uint32_t guest_svn = 0;
    TcbVersion tcb_version = TcbVersion();
  }; // snp_derived_key_req in (linux) include/uapi/linux/sev-guest.h
#pragma pack(pop)
  static_assert(
    sizeof(DerivedKeyReq) == 0x20,
    "DerivedKeyReq struct size does not match expected size of 32 bytes");

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

  // This 4000 comes from the definition of snp_report_resp in
  // https://github.com/torvalds/linux/blob/master/include/uapi/linux/sev-guest.h
  using PaddedAttestationResp = PaddedTo<AttestationResp, 4000>;
  using PaddedDerivedKeyResp = PaddedTo<DerivedKeyResp, 4000>;

  using GuestRequestAttestation =
    GuestRequest<AttestationReq, PaddedAttestationResp>;
  using GuestRequestDerivedKey =
    GuestRequest<DerivedKeyReq, PaddedDerivedKeyResp>;

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
    IoctlSentinel<PaddedAttestationResp> resp_with_sentinel = {};
    PaddedAttestationResp& padded_resp = resp_with_sentinel.data;

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
      auto close_guard = nonstd::make_close_fd_guard(&fd);

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

      if (!resp_with_sentinel.sentinels_intact())
      {
        // This occurs if a kernel/firmware upgrade causes the response to
        // overflow our struct. If that happens, it is better to fail early than
        // deal with memory corruption.
        throw std::logic_error(
          "SEV_SNP_GUEST_MSG_REPORT IOCTL overwrote safety sentinels.");
      }
    }

    const snp::Attestation& get() const override
    {
      return padded_resp.report;
    }

    std::vector<uint8_t> get_raw() override
    {
      auto quote_bytes = reinterpret_cast<uint8_t*>(&padded_resp.report);
      return {quote_bytes, quote_bytes + padded_resp.report_size};
    }
  };

  class DerivedKey
  {
    IoctlSentinel<PaddedDerivedKeyResp> resp_with_sentinel = {};
    PaddedDerivedKeyResp& padded_resp = resp_with_sentinel.data;

  public:
    DerivedKey(TcbVersion tcb = {})
    {
      int fd = open(DEVICE, O_RDWR | O_CLOEXEC);
      if (fd < 0)
      {
        throw std::logic_error(
          fmt::format("Failed to open \"{}\" ({})", DEVICE, fd));
      }
      auto close_guard = nonstd::make_close_fd_guard(&fd);

      // This req by default mixes in HostData and the CPU VCEK
      DerivedKeyReq req = {};

      req.guest_field_select =
        GUEST_FIELD_SELECT_MEASUREMENT | GUEST_FIELD_SELECT_TCB_VERSION;
      req.tcb_version = tcb;

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

      if (!resp_with_sentinel.sentinels_intact())
      {
        // This occurs if a kernel/firmware upgrade causes the response to
        // overflow our struct. If that happens, it is better to fail early than
        // deal with memory corruption.
        throw std::logic_error(
          "SEV_SNP_GUEST_MSG_DERIVED_KEY IOCTL overwrote safety sentinels.");
      }

      if (padded_resp.status != 0)
      {
        const auto msg = fmt::format(
          "Failed to issue ioctl SEV_SNP_GUEST_MSG_DERIVED_KEY: {}",
          padded_resp.status);
        throw std::logic_error(msg);
      }
    }

    ~DerivedKey()
    {
      OPENSSL_cleanse(padded_resp.data, sizeof(padded_resp.data));
    }

    std::span<const uint8_t> get_raw()
    {
      return std::span<const uint8_t>{padded_resp.data};
    }
  };
}