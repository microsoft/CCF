# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# pylint: disable=import-error, no-name-in-module
from setuptools.extern.packaging.version import (  # type: ignore
    Version,
    InvalidVersion,
)


def remove_prefix(s, prefix):
    if s.startswith(prefix):
        return s[len(prefix) :]
    return s


def replace_char(s, n, c):
    return s[:n] + str(c) + s[n + 1 :]


def to_python_version(original):
    unprefixed = remove_prefix(original, "ccf-")

    # Try to parse this as a Version (with automatic normalisation).
    # If it fails, try making part of the suffix a local version specifier (+foo).
    # Keep expanding this suffix until you get a valid version, or run out of attempts.
    next_attempt = unprefixed
    next_replace = len(next_attempt)
    plus_remover = str.maketrans({ord("+"): ""})
    while True:
        try:
            version = Version(next_attempt)
            return version
        except InvalidVersion:
            next_replace = unprefixed.rfind("-", 0, next_replace)
            if next_replace == -1:
                break
            # Remove any existing +s, and convert one - to a +
            next_attempt = replace_char(
                unprefixed.translate(plus_remover), next_replace, "+"
            )

    raise ValueError(f"Cannot convert '{original}' to a Version")


if __name__ == "__main__":
    # Run some tests that expected versions are correctly parsed
    v = to_python_version("1")
    assert v.release == (1,)

    v = to_python_version("1.2.3")
    assert v.release == (1, 2, 3)
    assert v == to_python_version("ccf-1.2.3")

    v = to_python_version("ccf-1.2.3")
    assert v.release == (1, 2, 3)
    assert v == to_python_version("ccf-1.2.3")

    v = to_python_version("ccf-1.2.3-a42")
    assert v.release == (1, 2, 3)
    assert v.pre == ("a", 42)
    assert v < to_python_version("ccf-1.2.3")  # -x precedes main release

    v = to_python_version("ccf-1.2.3-rc1")
    assert v.release == (1, 2, 3)
    assert v.pre == ("rc", 1)
    assert v < to_python_version("ccf-1.2.3")  # RC precedes main release

    v = to_python_version("ccf-1.2.3-dev2")
    assert v.release == (1, 2, 3)
    assert v.dev == 2
    assert v < to_python_version("ccf-1.2.3")  # dev precedes main release

    v = to_python_version("ccf-1.2.3-dev3-5-deadbeef")
    assert v.release == (1, 2, 3)
    assert v.dev == 3
    assert v.local == "5.deadbeef"
    assert v < to_python_version("ccf-1.2.3")  # dev precedes main release

    v = to_python_version("ccf-1.2.3-42-deadbeef")
    assert v.release == (1, 2, 3)
    assert v.post == 42
    assert v.local == "deadbeef"
    assert v > to_python_version("ccf-1.2.3")  # -N comes after main release

    v = to_python_version("ccf-2.0.0-rc4-26-g49d7b7941+unsafe")
    assert v.release == (2, 0, 0)
    assert v.pre == ("rc", 4)
    assert v.post == 26
    assert v.local == "g49d7b7941unsafe"
    assert v < to_python_version("ccf-2.0.0")  # RC precedes main release
