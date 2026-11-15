# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Print a consensus scenario as a compact Mermaid sequence diagram.

Usage: cft_scenarios_mermaid.py <cft_driver> <Scenarios/name.lean>

Messages are arrows, and consecutive local steps of a node share a note.
Symbols replace what the driver prints, and anything else is left as it is.
"""

import itertools
import re
import subprocess
import sys
from pathlib import Path

MARKER = "<CftDriver>"

# Symbols
LEADER = "\N{CROWN}"
FOLLOWER = "\N{GUARDSMAN}"
CANDIDATE = "\N{HAPPY PERSON RAISING ONE HAND}"
NO_ROLE = "\N{JAPANESE SYMBOL FOR BEGINNER}"
YES = "\N{WHITE HEAVY CHECK MARK}"
NO = "\N{CROSS MARK}"
SIGNATURE = "\N{MEMO}"
RECONFIGURATION = "\N{BLACK UNIVERSAL RECYCLING SYMBOL}\N{VARIATION SELECTOR-16}"
ENTRY = "\N{PAGE FACING UP}"
PRE_VOTE = "\N{RAISED HAND}"
NOMINATION = "\N{WHITE RIGHT POINTING BACKHAND INDEX}"
ENTRIES = "\N{PACKAGE}"
LEDGER = "\N{FLOPPY DISK}"
COMMIT = "\N{LOCK}"
TRUNCATION = "\N{BLACK SCISSORS}\N{VARIATION SELECTOR-16}"
ROLLBACK = "\N{BLACK LEFT-POINTING DOUBLE TRIANGLE}"
TIME = "\N{HOURGLASS WITH FLOWING SAND}"
CREATED = "\N{SQUARED NEW}"
TRUSTED = "\N{HANDSHAKE}"
RETIRED = "\N{WAVING HAND SIGN}"
UNCHECKED = "\N{SEE-NO-EVIL MONKEY}"
CONNECTED = "\N{LINK SYMBOL}"
DISCONNECTED = "\N{NO ENTRY}"

# What the driver prints, and the symbols which replace it
LABELS = [
    (r"\[KV\] initialising in term ", LEADER),
    (r"replicate (\S+) = \[\d+ bytes\] signature \[raw\]", rf"{SIGNATURE}\1"),
    (r"replicate (\S+) = .* \[reconfiguration\]", rf"{RECONFIGURATION}\1"),
    (r"replicate (\S+) = .* \[raw\]", rf"{ENTRY}\1"),
    (r"\[ledger\] appending: (\S+?)=.*", rf"{LEDGER}\1"),
    (r"\[ledger\] truncating to ", TRUNCATION),
    (r"\[KV\] rolling back to (\S+), in term \d+", rf"{ROLLBACK}\1"),
    (r"\[KV\] compacting to ", COMMIT),
    (r"periodic for (\d+) ms", rf"{TIME}\1ms"),
    (
        r"append_entries (\(.*\]) \(term (\d+), commit (\d+)\)",
        rf"{ENTRIES}\1 {LEADER}\2 {COMMIT}\3",
    ),
    (r"append_entries_response ACK for ", YES),
    (r"append_entries_response NACK for ", NO),
    (r"propose_request_vote for term ", NOMINATION),
    (r"request_pre_vote(_response)? for term ", PRE_VOTE),
    (r"request_vote(_response)? for term ", CANDIDATE),
    (r", at tx ", " @"),
    (r"= Y$", YES),
    (r"= N$", NO),
    (r"Node \S+ created", CREATED),
    (r"Node \S+ trusted", TRUSTED),
    (r"Node \S+ retired", RETIRED),
    (r"Node \S+ nominates a successor", NOMINATION),
    (r"Ignoring from sync check, due to retirement", UNCHECKED),
    (r"disconnect$", DISCONNECTED),
    (r"(re)?connect$", CONNECTED),
    (r"leadership P", LEADER),
    (r"leadership F", FOLLOWER),
    (r"leadership C", CANDIDATE),
    (r"leadership \?", NO_ROLE),
    (r" membership A", ""),
    (r"membership R", RETIRED),
    (r"\(committed (\d+)\)", rf"{COMMIT}\1"),
]

# A step which only involves one node, such as an append to its ledger
LOCAL = re.compile(r"(?:(\S+)->>\1|Note over (\S+)): (.*)")


def label(step: str) -> str:
    """Replace what the driver prints in `step` with symbols."""
    for printed, symbols in LABELS:
        step = re.sub(printed, symbols, step)
    return step.strip()


def local(step: str) -> tuple[str | None, str]:
    """Split a local step into its node and what that node does there."""
    match = LOCAL.fullmatch(step)
    return (match[1] or match[2], match[3]) if match else (None, step)


def diagram(output: str) -> str:
    """Return the diagram of the scenario for which the driver wrote `output`."""
    steps = (
        local(label(line.removeprefix(MARKER)))
        for line in output.splitlines()
        if line.startswith(MARKER)
    )
    lines = ["sequenceDiagram"]
    for node, group in itertools.groupby(steps, key=lambda step: step[0]):
        texts = [text for _, text in group]
        lines += [f"Note over {node}:wrap: {' '.join(texts)}"] if node else texts
    return "\n  ".join(lines) + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    run = subprocess.run(
        [sys.argv[1], Path(sys.argv[2]).stem],
        stdout=subprocess.PIPE,
        text=True,
        check=False,
    )
    sys.stdout.write(diagram(run.stdout))
    sys.exit(run.returncode)
