# Trace replay

`disaster-recovery-replay` checks the node logs of one e2e recovery scenario
against the model:

```text
node logs -(Replay/Records.lean)-> records
          -(Replay/Reduction.lean)-> actions and observations, in commit order
          -(Replay.lean)-> success or discrepancy
```

Run it from `lean/disaster-recovery`:

```bash
lake exe disaster-recovery-replay --participants N --open-kind QUORUM|FAILOVER [--wait-ms N] LOG...
```

By default it waits up to 20 seconds for the nodes to log a complete
scenario; `--wait-ms 0` makes any incompleteness fail immediately. It replays
the reduced trace through `Model.transitionSystem`, prints how many actions
and observations it replayed, and checks the scenario. Malformed records,
records that no commit order explains, impossible local handler steps,
disabled actions and observation mismatches fail it immediately. Each
instruction names the log line and the rule it comes from, so a failure
points back to both.

The SNP Genoa CI job runs its tests with `CCF_RECOVERY_TRACE=1`, which
`tests/infra/remote.py` passes on to the nodes, so the recovery decision
protocol scenarios only run traced there. After the quorum, failover and
multiple-timeout scenarios in `tests/e2e_operations.py`,
`tests/infra/recovery_trace.py` runs the replayer on the nodes' logs.
`.github/workflows/lean.yml` also builds the replayer and runs
`tests/infra/recovery_trace_mutations.py` against committed fixtures of those
three scenarios.

## Records

When the `CCF_RECOVERY_TRACE` environment variable is set to a non-empty
value, `src/node/recovery_decision_protocol.cpp` logs
`RDP_TRACE` followed by one JSON object. Every record has `node`,
`expected_locations`, `sequence`, a per-node counter from 0, and `kind`:

| Kind                                                              | Emitted when                                                   |
| ----------------------------------------------------------------- | -------------------------------------------------------------- |
| `committed`                                                       | The global hook sees a phase write in `post`, at `version`     |
| `gossip_accepted`, `vote_accepted`, `iamopen_accepted`, `timeout` | A handler succeeded, before its transaction commits            |
| `send`                                                            | A retry is about to dispatch one message, named by `send`      |
| `timeout_request`                                                 | The failover timer is about to send its node a timeout request |

Handler records hold the phase and timeout phase that `advance()` read and
wrote (`pre`, `pre_timeout`, `post`, `post_timeout`), the KV versions of the
`sm_state` and `timeout_sm_state` values it read (`pre_version`,
`pre_timeout_version`), the `gossips` or `votes` it evaluated, and any
`chosen` node, `open_kind` or `restart` it read, wrote or requested. An
IAmOpen's `pre` and `chosen` are its own Joining writes, before the
subsequent `advance()` reads them. Gossip and vote records include the
execution's own insert in `gossips` or `votes`. `caused_by` names the send of
a received message, or the timeout request of a timeout, as `NODE:SEQUENCE`.
Receives name their sender in `source`. The sends of one retry share a `batch`
and the `sm_state` version the retry read, in `pre_version`. Gossip records
and sends carry the gossiped `txid`, as `"view.seqno"`. The C++ omits a
version only when tracing fails, and a log line containing `Failed to trace
recovery-decision-protocol` fails the replay, so versions are required.

## Rules

The reduction derives the order in which each node committed its executions,
and tells logs that are still growing, which it waits for, from logs that no
order explains, which fail. The replay checks the reduced global execution,
and the reduction also checks every record that it does not replay.

| Rule            | Effect                                                                                                                                                                                                               |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `config`        | Every record carries the same `expected_locations`                                                                                                                                                                   |
| `participation` | A node's first `committed` record is for Gossiping, and its version is the initial version of both `sm_state` and `timeout_sm_state`                                                                                 |
| `local-step`    | Every handler record, replayed or not, is one valid local `advance()` step from the recorded snapshot, with the recorded notifications and post-state                                                                |
| `rolled-back`   | Of the executions with one `caused_by`, only the last can have committed; the others are not replayed                                                                                                                |
| `segment`       | The version pairs that executions read, `(pre_version, pre_timeout_version)`, form one chain from the initial pair, in which each pair writes one or both keys at a new version                                      |
| `writer`        | One final execution that read a pair, up to identical copies, writes the keys changing at the next pair, and is replayed after the pair's other executions; other writers did not commit                             |
| `set-chain`     | In Gossiping and Voting, executions follow the insert of the gossips or votes they read; a reader off the committed set chain fails, and an insert off it is accepted only if the set before its own insert is on it |
| `committed`     | Every `committed` record matches the replayed `sm_state` chain, and committed versions rise in sequence order                                                                                                        |
| `retry`         | A retry runs where the `sm_state` version it read is first read                                                                                                                                                      |
| `scenario`      | Each participant ends Opening or Open with the expected open kind, or Joining after a restart request, and one opens                                                                                                 |

The newest pair has no next pair. Its writer is replayed if it is the only
execution that writes, or if a retry read a later `sm_state` version, which it
must then have written. A later `committed` record, if present, confirms that
the newest writer committed and, when a later retry read its `sm_state`
version, must agree with that version. A replayed execution is its state
observation, its action, the notifications it emitted and the state it
recorded writing. A retry is its action and the messages it sent. Messages of
executions that are not replayed stay in the network, as any undelivered
message does. Items of different nodes are interleaved so that each message
is received after it is sent.

The e2e tests check the open kind, which the move to Opening decides, and do
not wait for the timeout from Opening to Open, so the scenario accepts
Opening. An opening of another kind fails the scenario without waiting for
more records. The scenario is checked after the replay, so its failures report
how many actions and observations replayed.

## Why this is the commit order

- After a conflict, `src/node/rpc/frontend.h` runs the same request again, so
  all attempts of a message or timeout request record the same `caused_by`,
  and only the last one can commit.
- Every execution reads `sm_state` and `timeout_sm_state`, in `advance()` or,
  for IAmOpen, before its write. The KV commits a transaction only if what it
  read is unchanged, under the map locks that assign its version
  (`src/kv/apply_changes.h`, `src/kv/untyped_map.h`). So a committed execution
  commits within the pair it read, and the first write to either key ends that
  pair. The writer of each pair but the newest reads it, so the pairs that
  executions read, ordered by version, are the committed chain, and the next
  pair shows which keys the writer wrote. Transactions without writes are not
  validated, but read one consistent snapshot, which lies in the pair they
  read.
- In Gossiping and Voting, `advance()` iterates the gossips or votes, which
  makes every transaction that changes them conflict with every other one that
  reads them. So they commit one after the other, each inserting at most one
  location, and each execution records the set it read, with its own insert. A
  sequence is taken after the reads and before the commit, so a reader of a
  set has a higher sequence than the insert that wrote it. Walking back from
  the set the writer read, the lowest-sequence insert that recorded each set
  therefore added its last location. A final insert off that chain conflicted
  with the writer, and its re-execution was rejected, so the set before its
  own insert must still be on the committed chain. A reader off it read no
  committed state, so the trace fails.
- A retry reads one snapshot, and its messages depend only on the phase and
  chosen node, which are written together. A receive of its messages reads a
  later snapshot, so running the retry where its version is first read puts it
  before them.
- The `sm_state` commit hook logs every committed phase write that it sees.
  Earlier writers are matched to the next pair's `sm_state` version. For the
  newest writer, a later `committed` record is the only source of its exact
  committed version.

The reduction does not choose between candidates. Identical copies of a writer,
with the same action and recorded fields, are the exception: they are
concurrent executions of the same message, or of timeout requests that found
the same state. The model replays any of them alike, since it delivers any
queued copy of an envelope, so the lowest sequence is replayed. Otherwise
several different writers of one pair, several largest sets when the writer
read none, a retry from a version that no execution read or wrote, or pairs
that no single write links, fail. Different writers can still write the same
keys from one pair when the loser's re-execution is rejected rather than
traced. For example, in Gossiping an IAmOpen and a gossip that completes the
gossips both read one pair, and if the IAmOpen commits, the gossip's
re-execution finds a chosen node and fails before `advance()`. Such traces fail
as invalid, or as incomplete when no later record shows the next versions.

A successful replay shows that one model execution explains every replayed
record: each action is enabled, and each observation matches. It also checks
that every discarded handler record is one valid local step from the snapshot
it logged, and that committed and configuration records agree with the replayed
chain. It still does not show behaviour that no record shows, or liveness.
Review the rules against the C++ they name.

## Mutation test

`tests/infra/recovery_trace_mutations.py` is the maintained regression test
for the validator. It replays the committed fixtures in
`lean/disaster-recovery/replay/fixtures/`, checks targeted negative and benign
mutations with explicit expectations, and then sweeps sampled records with
single-field perturbations. The sweep may pass only for a small explicit
allowlist of harmless cases where no other record can constrain the changed
value.

Run it from the repository root after building the replayer:

```bash
cd lean/disaster-recovery
lake build disaster-recovery-replay
cd ../..
python3 tests/infra/recovery_trace_mutations.py \
  lean/disaster-recovery/.lake/build/bin/disaster-recovery-replay \
  lean/disaster-recovery/replay/fixtures
```

To refresh the fixtures from a traced SNP run's `logs-caci-snp-genoa`
artifact, download and extract it, then keep only the `RDP_TRACE ` lines from
the three recovery-decision-protocol scenarios:

```bash
gh api repos/microsoft/CCF/actions/artifacts/ARTIFACT_ID/zip > artifact.zip
python3 - <<'PY'
import json
import pathlib
import zipfile

workspace = pathlib.Path("artifact-extracted")
with zipfile.ZipFile("artifact.zip") as zf:
    zf.extractall(workspace)

sources = {
    "quorum": (
        3,
        "QUORUM",
        [
            "platform_snp_platform_tests_recovery_decision_protocol_3/out",
            "platform_snp_platform_tests_recovery_decision_protocol_4/out",
            "platform_snp_platform_tests_recovery_decision_protocol_5/out",
        ],
    ),
    "timeout": (
        1,
        "FAILOVER",
        ["platform_snp_platform_tests_recovery_decision_protocol_timeout_3/out"],
    ),
    "multiple-timeout": (
        3,
        "FAILOVER",
        [
            "platform_snp_platform_tests_recovery_decision_protocol_multiple_timeout_3/out",
            "platform_snp_platform_tests_recovery_decision_protocol_multiple_timeout_4/out",
            "platform_snp_platform_tests_recovery_decision_protocol_multiple_timeout_5/out",
        ],
    ),
}

marker = "RDP_TRACE "
fixtures = pathlib.Path("lean/disaster-recovery/replay/fixtures")
for name, (participants, open_kind, relpaths) in sources.items():
    scenario = fixtures / name
    scenario.mkdir(parents=True, exist_ok=True)
    (scenario / "scenario.json").write_text(
        json.dumps({"participants": participants, "open_kind": open_kind}, indent=2) + "\n",
        encoding="utf-8",
    )
    for relpath in relpaths:
        source = workspace / "build/workspace" / relpath
        lines = []
        with source.open(encoding="utf-8", errors="surrogateescape") as f:
            for line in f:
                index = line.find(marker)
                if index >= 0:
                    lines.append(line[index:])
        (scenario / f"{source.parent.name}.out").write_text("".join(lines), encoding="utf-8")
PY
```

`Config.isValid` requires an instance identifier, which traces do not carry,
so the replayer uses a fixed one. A node that never gossips never reads its
recovered TxID, so the replayer uses `0.0` for it. The model does not store
notifications in the network state, so the replayer re-runs the node's local
step to check them, as the properties do.
