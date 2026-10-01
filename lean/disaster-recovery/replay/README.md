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
records that no commit order explains, disabled actions and observation
mismatches fail it immediately. Each
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
value, `src/node/recovery_decision_protocol.cpp` logs `RDP_TRACE` followed by
one JSON object. Every record has `node`, `sequence`, a per-node counter from
0, and `kind`:

| Kind                                                              | Emitted when                                                       |
| ----------------------------------------------------------------- | ------------------------------------------------------------------ |
| `start`                                                           | The global hook sees the protocol start in Gossiping, at `version` |
| `gossip_accepted`, `vote_accepted`, `iamopen_accepted`, `timeout` | The local commit handler of a request whose transaction committed  |
| `send`                                                            | A retry is about to dispatch one message, named by `send`          |

`start` also carries the `expected_locations`. Handler records are logged by
the endpoint's locally committed function, so only executions that committed
are logged. Their `version` is the seqno of the TxID that CCF reported for the
transaction: the version it committed at if it wrote, as `wrote` says, and the
version it read at otherwise. They hold the phase and timeout phase that
`advance()` read and wrote (`pre`, `pre_timeout`, `post`, `post_timeout`), the
`gossips` or `votes` it evaluated, and any `chosen` node, `open_kind` or
`restart` it read, wrote or requested. An IAmOpen's `pre` and `chosen` are its
own Joining writes, before the subsequent `advance()` reads them. Gossip and
vote records include the execution's own insert in `gossips` or `votes`.
`caused_by` names the send of a received message as `NODE:SEQUENCE`, and
receives name their sender in `source`. The sends of one retry share a `batch`
and the version of the `sm_state` value the retry read, in `pre_version`.
Gossip records and sends carry the gossiped `txid`, as `"view.seqno"`.

## Rules

The reduction orders each node's records as they committed, and tells logs
that are still growing, which it waits for, from logs that no order explains,
which fail. The replay checks everything else.

| Rule           | Effect                                                                                                               |
| -------------- | -------------------------------------------------------------------------------------------------------------------- |
| `config`       | Every node's `start` record carries the same `expected_locations`                                                    |
| `start`        | Each node starts once, and every execution is at or after its start version                                          |
| `causes`       | Each receive names a send to it, from its `source`, of the same message                                              |
| `commit-order` | A node's executions run in version order; an execution that wrote nothing runs after the write at its version        |
| `retry`        | A retry runs right after the `sm_state` write at the version it read                                                 |
| `scenario`     | Each participant ends Opening or Open with the expected open kind, or Joining after a restart request, and one opens |

A replayed execution is its state observation, its action, the notifications
it emitted and the state it recorded writing. A retry is its action and the
messages it sent. Items of different nodes are interleaved so that each
message is received after it is sent.

The e2e tests check the open kind, which the move to Opening decides, and do
not wait for the timeout from Opening to Open, so the scenario accepts
Opening. An opening of another kind fails the scenario without waiting for
more records. The scenario is checked after the replay, so its failures report
how many actions and observations replayed.

## Why this is the commit order

CCF gives each transaction that writes a new version, in the order in which
transactions commit, and a transaction that writes nothing reads the state at
the version it reports. So ordering a node's executions by version, with each
write before the transactions that read it, is the order in which they took
effect. A retry reads one snapshot, and its messages depend only on the phase
and chosen node, which are written together, so it can run right after the
`sm_state` write it read. Executions whose transactions did not commit are not
logged, and have no effect on the KV.

A successful replay shows that one model execution explains every record:
each action is enabled, and each observation matches. It does not show
behaviour that no record shows, or liveness.

## Mutation test

`tests/infra/recovery_trace_mutations.py` is the maintained regression test
for the validator. It replays the committed fixtures in
`lean/disaster-recovery/replay/fixtures/`, checks targeted negative and benign
mutations with explicit expectations, and then sweeps sampled records with
single-field perturbations. A sweep mutant may pass only if it changes a
`version` or `wrote` field in a way that admits no commit order the original
does not admit, which the harness checks.

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
