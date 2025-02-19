#include <stdint.h>

namespace ccf::pal::snp
{
#pragma pack(push, 1)
  // Table 3
  struct TcbVersion
  {
    uint8_t boot_loader;
    uint8_t tee;
    uint8_t reserved[4];
    uint8_t snp;
    uint8_t microcode;

    bool operator==(const TcbVersion&) const = default;
  };
#pragma pack(pop)
  static_assert(
    sizeof(TcbVersion) == sizeof(uint64_t),
    "Can't cast TcbVersion to uint64_t");

  DECLARE_JSON_TYPE(TcbVersion);
  DECLARE_JSON_REQUIRED_FIELDS(TcbVersion, boot_loader, tee, snp, microcode);

  } // namespace ccf::pal::snp