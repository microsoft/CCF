# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from enum import StrEnum
from os import getenv, path
import sys


class Platform(StrEnum):
    VIRTUAL = "virtual"
    SNP = "snp"


_CURRENT_PLATFORM = getenv(
    "CCF_PLATFORM_OVERRIDE",
    default=None,
)


# Path to the SEV guest device on patched 5.x kernels
_SEV_DEVICE_LINUX_5 = "/dev/sev"

# Path to the SEV guest device from 6.0 onwards
# https://www.kernel.org/doc/html/v6.0/virt/coco/sev-guest.html
_SEV_DEVICE_LINUX_6 = "/dev/sev-guest"

SNP_SUPPORT = any(
    path.exists(dev) for dev in [_SEV_DEVICE_LINUX_5, _SEV_DEVICE_LINUX_6]
)


def get_platform():
    global _CURRENT_PLATFORM
    if _CURRENT_PLATFORM is None:
        if SNP_SUPPORT:
            _CURRENT_PLATFORM = Platform.SNP
        else:
            _CURRENT_PLATFORM = Platform.VIRTUAL

    return _CURRENT_PLATFORM


def is_snp():
    return get_platform() == Platform.SNP


def is_virtual():
    return get_platform() == Platform.VIRTUAL


if __name__ == "__main__":
    current = get_platform()
    if len(sys.argv) == 1:
        print(f"Detected platform is: {current}")
    elif len(sys.argv) == 2:
        expectation = sys.argv[1]
        if expectation == current:
            print(f"Confirmed running on expected platform: {current}")
        else:
            print(
                f"Not running on expected platform! Expected: {expectation}. Actual: {current}",
                file=sys.stderr,
            )
            sys.exit(1)
