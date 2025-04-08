#include "ccf/pal/snp_ioctl6.h"

#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <optional>
#include <span>

using namespace std;
using namespace ccf::crypto;

int main()
{
  using namespace ccf::pal::snp::ioctl6;

  std::vector<uint8_t> report_data(32, 0x8);
  AttestationReq req = {};
  std::copy(report_data.begin(), report_data.end(), req.report_data);

  std::cout << "OK 1" << std::endl;

  int fd = open(DEVICE, O_RDWR | O_CLOEXEC);
  if (fd < 0)
  {
    throw std::logic_error(
      fmt::format("Failed to open \"{}\" ({})", DEVICE, fd));
  }

  std::cout << "OK 2" << std::endl;

  // Documented at
  // https://www.kernel.org/doc/html/latest/virt/coco/sev-guest.html
  SafetyPadding<AttestationResp> padded_resp = {};
  GuestRequestAttestation payload = {
    .req_data = &req, .resp_wrapper = &padded_resp, .exit_info = {0}};

  std::cout << "payload.exit_info.errors.fw: " << payload.exit_info.errors.fw
            << std::endl;
  std::cout << "payload.exit_info.errors.vmm: " << payload.exit_info.errors.vmm
            << std::endl;

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

  std::cout << "OK 3" << std::endl;

  std::cout << "payload.exit_info.errors.fw: " << payload.exit_info.errors.fw
            << std::endl;
  std::cout << "payload.exit_info.errors.vmm: " << payload.exit_info.errors.vmm
            << std::endl;

  if (!safety_padding_intact(padded_resp))
  {
    // This occurs if a kernel/firmware upgrade causes the response to
    // overflow the struct so it is better to fail early than deal with
    // memory corruption.
    throw std::logic_error("IOCTL overwrote safety padding.");
  }

  std::cout << "OK 4" << std::endl;
}
