# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from enum import StrEnum
from snp import SNP_SUPPORT
from os import getenv


class Platform(StrEnum):
    VIRTUAL = "Virtual"
    SNP = "SNP"


_CURRENT_PLATFORM = getenv(
    "CCF_PLATFORM_OVERRIDE",
    default=None,
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
    print(get_platform())
