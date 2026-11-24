# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Print a consensus scenario as a compact Mermaid sequence diagram.

Usage: cft_scenarios_mermaid.py <cft_driver> <Scenarios/name.lean>

Messages are arrows, as are the actions of a node, such as appending to its
ledger, which go from that node to itself. Updates to the state of a node, such
as its role or commit index, are notes. Consecutive actions of a node share an
arrow, and consecutive updates share a note.
Symbols replace what the driver prints, and anything else is left as it is.
"""

import itertools
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

MARKER = "<CftDriver>"
HEADER = "sequenceDiagram"

# Symbols
LEADER = "\N{CROWN}"
FOLLOWER = "\N{GUARDSMAN}"
CANDIDATE = "\N{HAPPY PERSON RAISING ONE HAND}"
NO_ROLE = "\N{SLEEPING SYMBOL}"
YES = "\N{WHITE HEAVY CHECK MARK}"
NO = "\N{CROSS MARK}"
SIGNATURE = "\N{WRITING HAND}\N{VARIATION SELECTOR-16}"
RECONFIGURATION = "\N{GEAR}\N{VARIATION SELECTOR-16}"
ENTRY = "\N{PAGE FACING UP}"
PRE_VOTE = "\N{BAR CHART}"
NOMINATION = "\N{WHITE RIGHT POINTING BACKHAND INDEX}"
APPEND_ENTRIES = "\N{PACKAGE}"
COMMIT = "\N{LOCK}"
ROLLBACK = "\N{BLACK LEFT-POINTING DOUBLE TRIANGLE}"
TIME = "\N{HOURGLASS WITH FLOWING SAND}"
CREATED = "\N{SQUARED NEW}"
TRUSTED = "\N{HANDSHAKE}"
RETIRED = "\N{WAVING HAND SIGN}"
UNCHECKED = "\N{SEE-NO-EVIL MONKEY}"
CONNECTED = "\N{LINK SYMBOL}"
DISCONNECTED = "\N{BRICK}"

# What the driver prints, and the symbols which replace it
LABELS = [
    (r"becomes Leader in term ", LEADER),
    (r"becomes Follower in term ", FOLLOWER),
    (r"becomes PreVoteCandidate in term ", PRE_VOTE),
    (r"becomes Candidate in term ", CANDIDATE),
    (r"becomes None in term ", NO_ROLE),
    (r"\[ledger\] truncating to ", ROLLBACK),
    (r"\[KV\] rolling back to (\S+), in term \d+", rf"{ROLLBACK}\1"),
    (r"\[KV\] compacting to ", COMMIT),
    (r"periodic for (\d+) ms", rf"{TIME}\1ms"),
    (
        r"append_entries (\(.*\]) \(term (\d+), commit (\d+)\)",
        rf"{APPEND_ENTRIES}\1 {LEADER}\2 {COMMIT}\3",
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

# What a primary prints for an entry which it replicates, with the nodes which a
# reconfiguration removes and adds, and what any node prints for an entry which it
# appends to its ledger
REPLICATED = re.compile(
    r"(?P<node>\S+)->>(?P=node): replicate (?P<txid>\S+) = \[\d+ bytes\] "
    r".* \[(?P<kind>\w+)(?: (?P<delta>\(.*\)))?\]"
)
APPENDED = re.compile(
    r"(?P<node>\S+)->>(?P=node): \[ledger\] appending: (?P<txid>\S+?)=.*"
)
KINDS = {"signature": SIGNATURE, "reconfiguration": RECONFIGURATION}

# A rollback, which a node prints for its KV and then for its ledger
ROLLED_BACK = re.compile(
    r"^((?P<node>\S+)->>(?P=node): \[KV\] rolling back to \S+\.(?P<index>\d+),"
    r" in term \d+)\n(?P=node)->>(?P=node): \[ledger\] truncating to (?P=index)$",
    re.MULTILINE,
)

# A step which only involves one node: what it prints as a message to itself is an
# action, unless it updates its state, and what it prints as a note is an update,
# unless it is an action
SELF = re.compile(r"(\S+)->>\1: (.*)")
NOTE = re.compile(r"Note (?:over|right of) (\S+): (.*)")
UPDATES = re.compile(r"\[KV\] compacting to .*")
ACTIONS = re.compile(r"Node \S+ nominates a successor")

# What a node prints when it becomes primary, which the note for its role shows
INITIALISED = re.compile(r"\S+->>\S+: \[KV\] initialising in term \d+")


def entries(steps: list[str]) -> Iterator[str]:
    """Show each entry where it is appended, with the symbol for its kind.

    Its primary prints that kind, and the change to the configuration if it is a
    reconfiguration, when it replicates the entry, a step which is only shown if
    the append does not follow.
    """
    appended = {
        match.group("node", "txid") for match in map(APPENDED.fullmatch, steps) if match
    }
    symbols: dict[str, tuple[str, str]] = {}
    for step in steps:
        if entry := REPLICATED.fullmatch(step):
            symbol = KINDS.get(entry["kind"], ENTRY)
            symbols[entry["txid"]] = (symbol, entry["delta"] or "")
            if entry.group("node", "txid") in appended:
                continue
        elif entry := APPENDED.fullmatch(step):
            symbol, delta = symbols.get(entry["txid"], (ENTRY, ""))
            step = f"{entry['node']}->>{entry['node']}: {symbol}{entry['txid']}{delta}"
        yield step


def label(step: str) -> str:
    """Replace what the driver prints in `step` with symbols."""
    for printed, symbols in LABELS:
        step = re.sub(printed, symbols, step)
    return step


def local(step: str) -> tuple[str | None, bool, str]:
    """Split a local step into its node, whether it is an action, and its text."""
    if match := SELF.fullmatch(step):
        node, text = match.groups()
        action = not UPDATES.fullmatch(text)
    elif match := NOTE.fullmatch(step):
        node, text = match.groups()
        action = bool(ACTIONS.fullmatch(text))
    else:
        return None, False, label(step)
    return node, action, label(text)


def diagram(output: str) -> str:
    """Return the diagram of the scenario for which the driver wrote `output`."""
    printed = "\n".join(
        line.removeprefix(MARKER).strip()
        for line in output.splitlines()
        if line.startswith(MARKER)
    )
    printed = ROLLED_BACK.sub(r"\1", printed)
    kept = [step for step in printed.splitlines() if not INITIALISED.fullmatch(step)]
    steps = (local(step) for step in entries(kept))
    lines = [HEADER]
    for (node, action), group in itertools.groupby(steps, key=lambda s: s[:2]):
        texts = [text for _, _, text in group]
        if node is None:
            lines += texts
        elif action:
            lines.append(f"{node}->>{node}:wrap: {' '.join(texts)}")
        else:
            lines.append(f"Note over {node}:wrap: {' '.join(texts)}")
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
