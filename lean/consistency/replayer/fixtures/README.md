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

From `lean/consistency`, inspect a failure directly (exit status 1 is expected):

```sh
lake exe consistency-replay replayer/fixtures/invalid/rollback-below-commit.ndjson
```
