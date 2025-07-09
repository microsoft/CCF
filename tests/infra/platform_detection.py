# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from enum import StrEnum
from os import getenv, path
import sys


class Platform(StrEnum):
    VIRTUAL = "virtual"
    SNP = "snp"


# Path to the SEV guest device on patched 5.x kernels
_SEV_DEVICE_LINUX_5 = "/dev/sev"

# Path to the SEV guest device from 6.0 onwards
# https://www.kernel.org/doc/html/v6.0/virt/coco/sev-guest.html
_SEV_DEVICE_LINUX_6 = "/dev/sev-guest"

SNP_SUPPORT = any(
    path.exists(dev) for dev in [_SEV_DEVICE_LINUX_5, _SEV_DEVICE_LINUX_6]
)

def _detect_platform():
    default_value = Platform.SNP if SNP_SUPPORT else Platform.VIRTUAL
    return getenv(
        "CCF_PLATFORM_OVERRIDE",
        default=default_value,
    )

_CURRENT_PLATFORM = _detect_platform()


def get_platform():
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
