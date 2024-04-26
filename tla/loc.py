import dataclasses
import sys

@dataclasses.dataclass
class LOC:
    code: int = 0
    comment: int = 0
    blank: int = 0

    @property
    def total(self):
        return sum(dataclasses.astuple(self))

    def __str__(self):
        return f"code: {self.code} comments: {self.comment} blank: {self.blank} total: {self.total}"

    def __add__(self, other):
        return LOC(
            self.code + other.code,
            self.comment + other.comment,
            self.blank + other.blank
        )

def count_loc(lines) -> LOC:
    loc = LOC()
    for line in lines:
        line_no_ws = line.strip()
        if not line_no_ws:
            loc.blank += 1
        elif line_no_ws.startswith("\*"):
            loc.comment += 1
        else:
            loc.code += 1
    return loc

if __name__ == "__main__":
    locs = []
    for arg in sys.argv[1:]:
        with open(arg) as f:
            lines = f.readlines()
        locs.append(count_loc(lines))
        print(f"{arg} {locs[-1]}")
    print(f"Total {sum(locs, LOC())}")