import re
import sys

PLAUSIBLE_CLANG = re.compile(r"^.*/clang((\+\+)?-\d+)?$")
NOT_ENCLAVE = re.compile(".*/(tests?|perf|host)/.*")  

class Checker:
    platform = None

    def check_line(self, line):
        if "Compile target platform:" in line:
            assert self.platform is None, f"Compile target platform already set to {self.platform}, but found {line}"
            self.platform = line.split(":")[1].strip()
            return

        words = line.split(" ")
        for index, word in enumerate(words):
            if PLAUSIBLE_CLANG.match(word):
                break

        # Not a build line
        if index == len(words) - 1:
            return

        # Need to know what the target is to check the flags
        assert self.platform, self.__dict__
        
        options = words[index+1:]

        # Don't worry about testcases, tools etc
        if any(NOT_ENCLAVE.match(option) for option in options):
            return

        if "-shared" in options:
            pass
        elif any(option for option in options if option.startswith("-l")):
            if self.platform == "sgx":
                assert "-mlvi-cfg" in options, f"Missing -mlvi-cfi in {line}"
            # TODO: check -lvi-cfg oe libraries for sgx
        else:
            # Build line
            if self.platform == "snp":
                assert "-x86-speculative-load-hardening" in options, f"Missing -x86-speculative-load-hardening in {line}"

if __name__ == "__main__":
    checker = Checker()
    for line in sys.stdin:
        checker.check_line(line)