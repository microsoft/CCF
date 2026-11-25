# Replay fixtures

The [Lean package workflow](../../../../.github/workflows/lean-package.yml) runs these fixtures through the real replay executable.
Every [valid](valid) fixture must be accepted, and every [invalid](invalid) fixture must be rejected with exit status 1.

| Valid fixture                                                             | Behaviour                                                     |
| ------------------------------------------------------------------------- | ------------------------------------------------------------- |
| [Write and commit](valid/write-commit.ndjson)                             | Entries committed, and reported committed to a client         |
| [Rollback at the same sequence number](valid/rollback_same_seqno.ndjson)  | Election replaces a lost write, later reported invalid        |
| [Non-contiguous view election](valid/election_non_contiguous_view.ndjson) | Election skips intermediate views                             |
| [Election from an older view](valid/election-older-view.ndjson)           | New leader's ledger predates the latest view                  |
| [Late election](valid/late-election.ndjson)                               | View 3 wins after view 4 commits and its write is invalidated |

| Invalid fixture                                                         | Expected failure                                                 |
| ----------------------------------------------------------------------- | ---------------------------------------------------------------- |
| [Empty](invalid/empty.ndjson)                                           | Trace has no records                                             |
| [Malformed JSON](invalid/malformed-json.ndjson)                         | Record is not valid JSON                                         |
| [Missing field](invalid/missing-field.ndjson)                           | Entry has no `seqno`                                             |
| [Missing election](invalid/missing-election.ndjson)                     | Entry in a view with no leader                                   |
| [Write in a skipped view](invalid/write-in-skipped-view.ndjson)         | A later election does not open skipped views                     |
| [Missing entry](invalid/missing-entry.ndjson)                           | Gap in a view's ledger entries                                   |
| [Two leaders](invalid/two-leaders.ndjson)                               | Second leader in the same view                                   |
| [Rollback below commit](invalid/rollback-below-commit.ndjson)           | New view would roll back a committed entry                       |
| [Late election below commit](invalid/late-election-below-commit.ndjson) | Late leader drops a prefix committed before its view was skipped |
| [Stale commit](invalid/stale-commit.ndjson)                             | Replaced leader commits a lost write                             |
| [Commit of unknown entry](invalid/commit-unknown-entry.ndjson)          | Node commits an entry its view does not hold                     |
| [Invalid after commit](invalid/invalid-after-commit.ndjson)             | Committed write later reported invalid                           |
| [Commit after invalid](invalid/commit-after-invalid.ndjson)             | Invalid write later reported committed                           |
| [Status without response](invalid/status-without-response.ndjson)       | Status for a transaction ID no leader wrote                      |
| [Status not final](invalid/status-not-final.ndjson)                     | Status is neither committed nor invalid                          |

From `lean/consistency`, inspect a failure directly (exit status 1 is expected):

```sh
lake exe consistency-replay replayer/fixtures/invalid/rollback-below-commit.ndjson
```
