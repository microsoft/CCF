# Replay fixtures

The [Lean package workflow](../../../../.github/workflows/lean-package.yml) runs these fixtures through the real replay executable.
Every [valid](valid) fixture must be accepted, and every [invalid](invalid) fixture must be rejected with exit status 1.

| Valid fixture                                                             | Behaviour                                                      |
| ------------------------------------------------------------------------- | -------------------------------------------------------------- |
| [Write and commit](valid/write-commit.ndjson)                             | Write executed, responded and committed                        |
| [Forwarded read](valid/forwarded-read.ndjson)                             | Read-only request after a committed write                      |
| [Read backfill](valid/read-backfill.ndjson)                               | Read in a later view, backfilling elections and ledger entries |
| [Election drops invalid](valid/election-drops-invalid.ndjson)             | Election discards a known-invalid write before filling a gap   |
| [Election without rollback](valid/election_no_rollback.ndjson)            | Election preserves the committed prefix                        |
| [Non-contiguous view election](valid/election_non_contiguous_view.ndjson) | Election skips intermediate views                              |
| [Rollback at the same sequence number](valid/rollback_same_seqno.ndjson)  | Election replaces an invalid write                             |
| [Rollback of two transactions](valid/rollback_two_transactions.ndjson)    | Election replaces an invalid suffix and commits a new write    |
| [Consensus election](valid/consensus-election.ndjson)                     | Consensus trace: election drops a write reported invalid       |
| [Consensus election from older view](valid/consensus-older-view.ndjson)   | Consensus trace: leader's ledger predates the last view        |

| Invalid fixture                                                   | Expected failure                                   |
| ----------------------------------------------------------------- | -------------------------------------------------- |
| [Empty](invalid/empty.ndjson)                                     | Trace has no records                               |
| [Malformed JSON](invalid/malformed-json.ndjson)                   | Record is not valid JSON                           |
| [Unknown action](invalid/unknown-action.ndjson)                   | Unsupported action/type pair                       |
| [Action/type mismatch](invalid/action-type-mismatch.ndjson)       | Action and type disagree                           |
| [Missing field](invalid/missing-field.ndjson)                     | Request has no `tx`                                |
| [Request ID gap](invalid/request-id-gap.ndjson)                   | Request IDs must start at zero and increase by one |
| [Missing request](invalid/missing-request.ndjson)                 | Execution of an unknown request                    |
| [Missing execution](invalid/missing-execution.ndjson)             | Response to an unexecuted write                    |
| [Reserved view](invalid/reserved-view.ndjson)                     | View 1 cannot process requests                     |
| [Zero sequence number](invalid/zero-seqno.ndjson)                 | Sequence numbers are one-based                     |
| [Response ID mismatch](invalid/response-id-mismatch.ndjson)       | Response ID differs from the executed position     |
| [Duplicate response](invalid/duplicate-response.ndjson)           | Second response to the same write                  |
| [Invalid after commit](invalid/invalid-after-commit.ndjson)       | Committed write later reported invalid             |
| [Commit after invalid](invalid/commit-after-invalid.ndjson)       | Invalid write later reported committed             |
| [Rollback below commit](invalid/rollback-below-commit.ndjson)     | New view would roll back a committed write         |
| [Status without response](invalid/status-without-response.ndjson) | Status for a transaction ID never returned         |
| [Status mismatch](invalid/status-mismatch.ndjson)                 | Status field disagrees with the action             |
| [Consensus dropped commit](invalid/consensus-drops-commit.ndjson) | Consensus trace: election drops a committed entry  |
| [Consensus stale commit](invalid/consensus-stale-commit.ndjson)   | Consensus trace: old leader commits a lost write   |
| [Consensus invalid](invalid/consensus-invalid-committed.ndjson)   | Consensus trace: committed write reported invalid  |
| [Consensus two leaders](invalid/consensus-two-leaders.ndjson)     | Consensus trace: second leader in the same view    |
| [Consensus no election](invalid/consensus-no-election.ndjson)     | Consensus trace: entry in a view with no leader    |
| [Consensus missing entry](invalid/consensus-missing-entry.ndjson) | Consensus trace: gap in a view's ledger entries    |

From `lean/consistency`, inspect a failure directly (exit status 1 is expected):

```sh
lake exe consistency-replay replayer/fixtures/invalid/rollback-below-commit.ndjson
```
