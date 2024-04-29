# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

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

def is_comment(line: str) -> bool:
    if line.startswith(r"\*"):
        return True
    if all(c == "-" for c in line):
        return True
    if line.startswith("(*") and line.endswith("*)"):
        return True
    return False

def is_multiline_comment_start(line: str) -> bool:
    return line.startswith("(*")

def is_footer(line: str) -> bool:
    return all(c == "=" for c in line)

def is_multiline_comment_end(line: str) -> bool:
    return line.endswith("*)")

def count_loc(lines) -> LOC:
    loc = LOC()
    in_comment = False
    in_footer = False
    for line in lines:
        line_no_ws = line.strip()
        if in_comment or in_footer:
            loc.comment += 1
            if is_multiline_comment_end(line_no_ws):
                in_comment = False
            continue

        if not line_no_ws:
            loc.blank += 1
        elif is_comment(line_no_ws):
            loc.comment += 1
        elif is_multiline_comment_start(line_no_ws):
            in_comment = True
            loc.comment += 1
        elif is_footer(line_no_ws):
            in_footer = True
            loc.comment += 1
        else:
            loc.code += 1
    return loc

JUST_CODE = r"""
---------- MODULE MCccfraft ----------
EXTENDS ccfraft, StatsFile, MCAliases

CONSTANTS
    NodeOne, NodeTwo, NodeThree
"""

CODE_AND_COMMENTS = r"""
\* Atomic reconfiguration from NodeOne to NodeTwo
2Configurations == <<{NodeOne}, {NodeTwo}>>
\* Incremental reconfiguration from NodeOne to NodeOne and NodeTwo, and then to NodeTwo
3Configurations == <<{NodeOne}, {NodeOne, NodeTwo}, {NodeTwo}>>
"""

FOOTER = r"""
=============================================================================

## Repeatedly run TLC in simulation mode to shorten a counterexample (the depth parameter will successively be reduced based on the length of the previous counterexample).
$ echo 500 > depth.txt
## Loop while the depth.txt file exists and is not empty.
$ while [ -s depth.txt ];
    do 
        TS=$(date +%s) && tlc SIMccfraft -simulate -workers auto -depth $(cat depth.txt) -postcondition 'SIMPostCondition!SIMPostCondition' 2>&1 | tee SIMccfraft_TTrace_$TS.out && sleep 5; 
    done
"""

MULTILINE_COMMENT = r"""
Nil ==
  (*************************************************************************)
  (* This defines Nil to be an unspecified value that is not a server.     *)
  (*************************************************************************)
  CHOOSE v : v \notin Servers

------------------------------------------------------------------------------
"""

MULTILINE_COMMENT_2 = r"""
IsAppendEntriesRequest(msg, dst, src, logline) ==
    (*
    | ccfraft.tla   | json               | raft.h             |
    |---------------|--------------------|--------------------|
    | type          | .msg               | raftType           |
    | term          | .term              | state->currentTerm |
    | prevLogTerm   | .prev_term         | prev_term          |
    | prevLogIndex  | .prev_idx          | prev_idx           |
    | commitIndex   | .leader_commit_idx | state->commit_idx  |
    |               | .idx               | end_idx            |
    |               | .term_of_idx       | term_of_idx        |
    |               | .contains_new_view | contains_new_view  |
    *)
    /\ IsHeader(msg, dst, src, logline, AppendEntriesRequest)
    /\ msg.commitIndex = logline.msg.packet.leader_commit_idx
    /\ msg.prevLogTerm = logline.msg.packet.prev_term
    /\ Len(msg.entries) = logline.msg.packet.idx - logline.msg.packet.prev_idx
    /\ msg.prevLogIndex + Len(msg.entries) = logline.msg.packet.idx
    /\ msg.prevLogIndex = logline.msg.packet.prev_idx
"""

def test_loc():
    """
    Run with py.test loc.py
    """
    assert count_loc(JUST_CODE.splitlines()) == LOC(code=4, comment=0, blank=2)
    assert count_loc(CODE_AND_COMMENTS.splitlines()) == LOC(code=2, comment=2, blank=1)
    assert count_loc(FOOTER.splitlines()) == LOC(code=0, comment=9, blank=1)
    assert count_loc(MULTILINE_COMMENT.splitlines()) == LOC(code=2, comment=4, blank=2)
    assert count_loc(MULTILINE_COMMENT_2.splitlines()) == LOC(code=7, comment=12, blank=1)

if __name__ == "__main__":
    locs = []
    for arg in sys.argv[1:]:
        with open(arg) as f:
            lines = f.readlines()
        locs.append(count_loc(lines))
        print(f"{arg} {locs[-1]}")
    print(f"Total {sum(locs, LOC())}")