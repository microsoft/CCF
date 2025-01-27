# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import re
import sys

PLAUSIBLE_CLANG = re.compile(r"^.*/clang((\+\+)?-\d+)?$")
NOT_IN_TCB = re.compile(".*/(tests?|perf)/.*")


class Checker:
    def __init__(self, platform):
        assert platform == "SNPCC"
        self.platform = platform
        self.total_lines = 0
        self.checked_lines = 0

    def check_line(self, line):
        self.total_lines += 1
        words = line.split(" ")
        for index, word in enumerate(words):
            if PLAUSIBLE_CLANG.match(word):
                break

        # Not a build line
        if index == len(words) - 1:
            return

        options = words[index + 1 :]

        if any(NOT_IN_TCB.match(option) for option in options):
            return

        if "-shared" in options:
            pass
        elif any(option for option in options if option.startswith("-l")):
            pass
        else:
            pass

    def stats(self):
        print(f"Checked {self.checked_lines} out of {self.total_lines} lines")


if __name__ == "__main__":
    checker = Checker(sys.argv[1])
    for line in sys.stdin:
        checker.check_line(line)
    checker.stats()
