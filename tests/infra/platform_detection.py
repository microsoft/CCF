# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from enum import StrEnum
from os import getenv, path
import sys
import re


class Platform(StrEnum):
    VIRTUAL = "virtual"
    SNP = "snp"


# Path to the SEV guest device from 6.0 onwards
# https://www.kernel.org/doc/html/v6.0/virt/coco/sev-guest.html
_SEV_DEVICE_LINUX_6 = "/dev/sev-guest"

SNP_SUPPORT = any(path.exists(dev) for dev in [_SEV_DEVICE_LINUX_6])


def _detect_platform():
    default_value = Platform.SNP if SNP_SUPPORT else Platform.VIRTUAL
    return getenv(
        "CCF_PLATFORM_OVERRIDE",
        default=default_value,
    )


def _detect_amd_platform_name():
    pattern = re.compile(r"model name\s*:\s*AMD EPYC (....) ")
    milan = re.compile(r"7..3")
    genoa = re.compile(r"9..4")
    with open("/proc/cpuinfo", "r") as cpuinfo_file:
        for line in cpuinfo_file:
            match = pattern.match(line)
            if match:
                num = match.group(1)
                if milan.match(num):
                    return "milan"
                elif genoa.match(num):
                    return "genoa"
    return "unknown"


_CURRENT_PLATFORM = _detect_platform()
_CURRENT_PLATFORM_AMD_NAME = _detect_amd_platform_name()


def get_platform():
    return _CURRENT_PLATFORM


def get_amd_platform_name():
    return _CURRENT_PLATFORM_AMD_NAME


def is_snp():
    return get_platform() == Platform.SNP


def is_virtual():
    return get_platform() == Platform.VIRTUAL


if __name__ == "__main__":
    current = get_platform()
    amd_name = get_amd_platform_name()
    if len(sys.argv) == 1:
        print(f"Detected platform is: {current} {amd_name}")
    elif len(sys.argv) in (2, 3):
        expectation = sys.argv[1:]
        if expectation == [current, amd_name] or expectation == [current]:
            print(f"Confirmed running on expected platform: {current}")
        else:
            print(
                f"Not running on expected platform. Expected: {" ".join(expectation)}. Actual: {current} {amd_name}",
                file=sys.stderr,
            )
            sys.exit(1)
