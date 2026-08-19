// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"
#include "ccf/pal/attestation_sev_snp.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <fcntl.h>
#include <fmt/ranges.h>
#include <openssl/crypto.h>
#include <optional>
#include <stdint.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

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

    [[nodiscard]] bool sentinels_intact() const
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
    uint8_t report_data[snp_attestation_report_data_size] = {0};
    uint32_t vmpl = 0;
    uint8_t reserved[28] = {0};
  }; // snp_report_req in (linux) include/uapi/linux/sev-guest.h
#pragma pack(pop)

  // Table 25
#pragma pack(push, 1)
  struct AttestationResp
  {
    uint32_t status = 0;
    uint32_t report_size = 0;
    uint8_t reserved[0x20 - 0x8] = {0};
    Attestation report;
    uint8_t padding[64] = {0};
    // padding to the size of SEV_SNP_REPORT_RSP_BUF_SZ (i.e., 1280 bytes)
  };
#pragma pack(pop)

#pragma pack(push, 1)
  struct ExtendedAttestationReq
  {
    AttestationReq data;
    uint64_t certs_address = 0;
    uint32_t certs_len = 0;
  }; // snp_ext_report_req in (linux) include/uapi/linux/sev-guest.h
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
    TcbVersionRaw tcb_version;
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
    uint32_t fw = 0;
    uint32_t vmm = 0;
  };

  union ExitInfo
  {
    uint64_t whole = 0;
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
    ExitInfo exit_info = {};
  };

  // This 4000 comes from the definition of snp_report_resp in
  // https://github.com/torvalds/linux/blob/master/include/uapi/linux/sev-guest.h
  using PaddedAttestationResp = PaddedTo<AttestationResp, 4000>;
  using PaddedDerivedKeyResp = PaddedTo<DerivedKeyResp, 4000>;

  using GuestRequestAttestation =
    GuestRequest<AttestationReq, PaddedAttestationResp>;
  using GuestRequestExtendedAttestation =
    GuestRequest<ExtendedAttestationReq, PaddedAttestationResp>;
  using GuestRequestDerivedKey =
    GuestRequest<DerivedKeyReq, PaddedDerivedKeyResp>;

  // From linux/include/uapi/linux/sev-guest.h
  constexpr char SEV_GUEST_IOC_TYPE = 'S';
  constexpr int SEV_SNP_GUEST_MSG_REPORT =
    _IOWR(SEV_GUEST_IOC_TYPE, 0x0, GuestRequestAttestation);
  constexpr int SEV_SNP_GUEST_MSG_DERIVED_KEY =
    _IOWR(SEV_GUEST_IOC_TYPE, 0x1, GuestRequestDerivedKey);
  constexpr int SEV_SNP_GUEST_MSG_EXT_REPORT =
    _IOWR(SEV_GUEST_IOC_TYPE, 0x2, GuestRequestExtendedAttestation);

  static constexpr uint32_t VMM_ERROR_INVALID_CERTIFICATE_PAGE_LENGTH = 1;
  static constexpr size_t MAX_CERTIFICATE_TABLE_SIZE = 1024 * 1024;

#pragma pack(push, 1)
  struct CertificateTableEntry
  {
    std::array<uint8_t, 16> guid = {};
    uint32_t offset = 0;
    uint32_t length = 0;
  };
#pragma pack(pop)
  static_assert(sizeof(CertificateTableEntry) == 24);

  // Certificate table GUIDs are published either in the mixed-endian
  // EFI_GUID layout or, as on AWS, in plain big-endian byte order, so both
  // encodings of each GUID must be recognised.
  static constexpr std::array<uint8_t, 16> VLEK_CERTIFICATE_GUID = {
    0xa8,
    0x07,
    0x4b,
    0xc2,
    0xa2,
    0x5a,
    0x48,
    0x3e,
    0xaa,
    0xe6,
    0x39,
    0xc0,
    0x45,
    0xa0,
    0xb8,
    0xa1};

  static constexpr std::array<uint8_t, 16> VLEK_CERTIFICATE_GUID_MIXED_ENDIAN =
    {0xc2,
     0x4b,
     0x07,
     0xa8,
     0x5a,
     0xa2,
     0x3e,
     0x48,
     0xaa,
     0xe6,
     0x39,
     0xc0,
     0x45,
     0xa0,
     0xb8,
     0xa1};

  // Some hosts publish the endorsement key certificate under the VCEK GUID
  // even when the report is VLEK-signed, so both slots must be considered.
  static constexpr std::array<uint8_t, 16> VCEK_CERTIFICATE_GUID = {
    0x63,
    0xda,
    0x75,
    0x8d,
    0xe6,
    0x64,
    0x45,
    0x64,
    0xad,
    0xc5,
    0xf4,
    0xb9,
    0x3b,
    0xe8,
    0xac,
    0xcd};

  static constexpr std::array<uint8_t, 16> VCEK_CERTIFICATE_GUID_MIXED_ENDIAN =
    {0x8d,
     0x75,
     0xda,
     0x63,
     0x64,
     0xe6,
     0x64,
     0x45,
     0xad,
     0xc5,
     0xf4,
     0xb9,
     0x3b,
     0xe8,
     0xac,
     0xcd};

  // Renders the bytes in the order they are stored, which is the canonical
  // textual form for big-endian GUIDs.
  static std::string format_certificate_guid(
    const std::array<uint8_t, 16>& guid)
  {
    return fmt::format(
      "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}"
      "{:02x}{:02x}{:02x}{:02x}{:02x}",
      guid[0],
      guid[1],
      guid[2],
      guid[3],
      guid[4],
      guid[5],
      guid[6],
      guid[7],
      guid[8],
      guid[9],
      guid[10],
      guid[11],
      guid[12],
      guid[13],
      guid[14],
      guid[15]);
  }

  using CertificateTable =
    std::vector<std::pair<std::array<uint8_t, 16>, std::vector<uint8_t>>>;

  static CertificateTable parse_certificate_table(
    std::span<const uint8_t> certificate_table)
  {
    size_t entry_offset = 0;
    CertificateTable entries;

    while (true)
    {
      if (
        entry_offset > certificate_table.size() ||
        certificate_table.size() - entry_offset < sizeof(CertificateTableEntry))
      {
        throw std::logic_error(
          "SEV-SNP certificate table is missing its terminator");
      }

      CertificateTableEntry entry;
      memcpy(
        &entry,
        certificate_table.data() + entry_offset,
        sizeof(CertificateTableEntry));
      entry_offset += sizeof(CertificateTableEntry);

      if (
        std::all_of(
          entry.guid.begin(),
          entry.guid.end(),
          [](uint8_t b) { return b == 0; }) &&
        entry.offset == 0 && entry.length == 0)
      {
        break;
      }

      if (
        entry.offset > certificate_table.size() ||
        entry.length > certificate_table.size() - entry.offset)
      {
        throw std::logic_error(
          "SEV-SNP certificate table entry is out of bounds");
      }

      entries.emplace_back(
        entry.guid,
        std::vector<uint8_t>(
          certificate_table.begin() + entry.offset,
          certificate_table.begin() + entry.offset + entry.length));
    }

    return entries;
  }

  static std::optional<std::vector<uint8_t>> extract_certificate(
    const CertificateTable& entries, const std::array<uint8_t, 16>& guid)
  {
    std::optional<std::vector<uint8_t>> found = std::nullopt;
    for (const auto& [entry_guid, certificate] : entries)
    {
      if (entry_guid != guid)
      {
        continue;
      }
      if (found.has_value())
      {
        throw std::logic_error(fmt::format(
          "SEV-SNP certificate table contains multiple {} certificates",
          format_certificate_guid(guid)));
      }
      found = certificate;
    }
    return found;
  }

  static std::optional<std::vector<uint8_t>> extract_vlek_certificate(
    std::span<const uint8_t> certificate_table)
  {
    return extract_certificate(
      parse_certificate_table(certificate_table), VLEK_CERTIFICATE_GUID);
  }

  static inline bool supports_sev_snp()
  {
    return access(DEVICE, W_OK) == 0;
  }

  class Attestation : public AttestationInterface
  {
    IoctlSentinel<PaddedAttestationResp> resp_with_sentinel;
    PaddedAttestationResp& padded_resp = resp_with_sentinel.data;
    std::vector<std::vector<uint8_t>> endorsements;

    void get_extended_report(int fd, const AttestationReq& report_req)
    {
      ExtendedAttestationReq ext_req = {.data = report_req};
      GuestRequestExtendedAttestation payload = {
        .req_data = &ext_req, .resp_wrapper = &padded_resp, .exit_info = {0}};

      int rc = ioctl(fd, SEV_SNP_GUEST_MSG_EXT_REPORT, &payload);
      if (
        payload.exit_info.errors.fw != 0 ||
        (payload.exit_info.errors.vmm != 0 &&
         payload.exit_info.errors.vmm !=
           VMM_ERROR_INVALID_CERTIFICATE_PAGE_LENGTH) ||
        (rc < 0 && ext_req.certs_len == 0) ||
        (rc >= 0 &&
         payload.exit_info.errors.vmm !=
           VMM_ERROR_INVALID_CERTIFICATE_PAGE_LENGTH))
      {
        throw std::logic_error(fmt::format(
          "Failed to query SEV_SNP_GUEST_MSG_EXT_REPORT certificate table "
          "size: {} fw_error: {} vmm_error: {}",
          nonstd::strerror(errno),
          payload.exit_info.errors.fw,
          payload.exit_info.errors.vmm));
      }
      if (
        ext_req.certs_len == 0 ||
        ext_req.certs_len > MAX_CERTIFICATE_TABLE_SIZE)
      {
        throw std::logic_error(fmt::format(
          "Invalid SEV-SNP certificate table size: {}", ext_req.certs_len));
      }

      std::vector<uint8_t> certificate_table(ext_req.certs_len);
      ext_req.certs_address =
        reinterpret_cast<uint64_t>(certificate_table.data());
      payload.exit_info.whole = 0;

      rc = ioctl(fd, SEV_SNP_GUEST_MSG_EXT_REPORT, &payload);
      if (rc < 0 || payload.exit_info.whole != 0)
      {
        throw std::logic_error(fmt::format(
          "Failed to issue ioctl SEV_SNP_GUEST_MSG_EXT_REPORT: {} fw_error: "
          "{} vmm_error: {}",
          nonstd::strerror(errno),
          payload.exit_info.errors.fw,
          payload.exit_info.errors.vmm));
      }

      auto entries = parse_certificate_table(certificate_table);
      std::optional<std::vector<uint8_t>> vek = std::nullopt;
      // The report is VLEK-signed, so an endorsement key certificate
      // published under the VCEK GUID is still the VLEK.
      for (const auto& guid :
           {VLEK_CERTIFICATE_GUID,
            VLEK_CERTIFICATE_GUID_MIXED_ENDIAN,
            VCEK_CERTIFICATE_GUID,
            VCEK_CERTIFICATE_GUID_MIXED_ENDIAN})
      {
        vek = extract_certificate(entries, guid);
        if (vek.has_value())
        {
          break;
        }
      }
      if (!vek.has_value())
      {
        std::vector<std::string> guids;
        guids.reserve(entries.size());
        for (const auto& [guid, certificate] : entries)
        {
          guids.emplace_back(fmt::format(
            "{} ({} bytes)",
            format_certificate_guid(guid),
            certificate.size()));
        }
        throw std::logic_error(fmt::format(
          "SEV-SNP certificate table does not contain a VLEK certificate. "
          "Table is {} bytes and contains {} entries: [{}]",
          certificate_table.size(),
          entries.size(),
          fmt::join(guids, ", ")));
      }
      endorsements.emplace_back(std::move(vek.value()));
    }

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
          nonstd::strerror(errno),
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

      if (
        padded_resp.report.flags.signing_key ==
        snp::attestation_flags_signing_key_vlek)
      {
        get_extended_report(fd, req);
        if (!resp_with_sentinel.sentinels_intact())
        {
          throw std::logic_error(
            "SEV_SNP_GUEST_MSG_EXT_REPORT IOCTL overwrote safety sentinels.");
        }
      }
    }

    [[nodiscard]] const snp::Attestation& get() const override
    {
      return padded_resp.report;
    }

    std::vector<uint8_t> get_raw() override
    {
      auto* quote_bytes = reinterpret_cast<uint8_t*>(&padded_resp.report);
      return {quote_bytes, quote_bytes + padded_resp.report_size};
    }

    std::vector<std::vector<uint8_t>> get_endorsements() override
    {
      return endorsements;
    }
  };

  class DerivedKey
  {
    IoctlSentinel<PaddedDerivedKeyResp> resp_with_sentinel;
    PaddedDerivedKeyResp& padded_resp = resp_with_sentinel.data;

  public:
    DerivedKey(const TcbVersionRaw tcb = {})
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
          nonstd::strerror(errno),
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