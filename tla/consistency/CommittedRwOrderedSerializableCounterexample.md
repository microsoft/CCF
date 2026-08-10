# Counterexample to the previous ordered serialisability equality

## Result

The previous definition of `CommittedRwOrderedSerializableInv` required
adjacent entries in `CommittedRwResponses` to differ by exactly the later
transaction's write. That equality was too strong because
`CommittedRwResponses` is filtered to responses whose clients explicitly
received committed status. A committed ledger write without a response or
status in `history` can therefore appear between two entries which are
adjacent only after filtering.

The invariant now requires the earlier observation to be a proper prefix of
the later observation and the later observation to end with its own write:

```tla
CommittedRwOrderedSerializableInv ==
    \A i \in 1..Len(CommittedRwResponses)-1:
        LET Earlier == CommittedRwResponses[i]
            Later == CommittedRwResponses[i+1]
        IN  /\ IsPrefix(Earlier.observed, Later.observed)
            /\ Len(Earlier.observed) < Len(Later.observed)
            /\ Last(Later.observed) = Later.tx
```

This retains the intended transaction-ID ordering guarantee while allowing
zero or more intervening ledger writes before the later transaction.
`CommittedRwOrderedSpecLinearizableInv` continues to include this invariant
and remains enabled in the normal multi-node configurations.

## Why this replacement is narrow

`CommittedRwSerializableInv` allows either observation to be a prefix of the
other. The repaired ordered invariant is deliberately stronger:

1. `IsPrefix(Earlier.observed, Later.observed)` fixes the prefix direction
   according to transaction-ID order.
2. `Len(Earlier.observed) < Len(Later.observed)` requires strict progress, so
   equal observations do not satisfy the property.
3. `Last(Later.observed) = Later.tx` preserves the requirement that the later
   transaction observes its own write last.

The replacement is not set inclusion or a subsequence check. Both would allow
observations to be reordered and would lose the ledger-prefix guarantee.

## The old equality

`CommittedRwResponses` contains read-write responses whose transaction IDs
have an explicit committed-status event in `history`, sorted by transaction
ID. The previous property required each adjacent pair in that filtered
sequence to differ by exactly the later transaction:

```tla
CommittedRwOrderedSerializableInv ==
    \A i \in 1..Len(CommittedRwResponses)-1:
        CommittedRwResponses[i+1].observed =
            Append(
                CommittedRwResponses[i].observed,
                CommittedRwResponses[i+1].tx)
```

That equality treated adjacency after response filtering as adjacency in the
ledger. The consistency transition system does not equate those notions.

## Counterexample to the old equality

With `HistoryLimit = 7`, both the single-node model and the multi-node model
with `ViewLimit = 3` reach the same shortest witness. It has seven external
history events, ten transitions, and eleven states including the initial
state. It requires no view change, read-only transaction, invalid status, or
non-client ledger entry.

| Transition | State reached | TLC action                        | Relevant result                       | History length |
| ---------: | ------------: | --------------------------------- | ------------------------------------- | -------------: |
|          1 |             2 | `MCRwTxRequestAction` for `0`     | Request `0` is visible                |              1 |
|          2 |             3 | `MCRwTxRequestAction` for `1`     | Request `1` is visible                |              2 |
|          3 |             4 | `MCRwTxRequestAction` for `2`     | Request `2` is visible                |              3 |
|          4 |             5 | `RwTxExecuteAction` for `0`       | Ledger slot 1 is `(view 1, tx 0)`     |              3 |
|          5 |             6 | `RwTxExecuteAction` for `1`       | Ledger slot 2 is `(view 1, tx 1)`     |              3 |
|          6 |             7 | `RwTxExecuteAction` for `2`       | Ledger slot 3 is `(view 1, tx 2)`     |              3 |
|          7 |             8 | `MCRwTxResponseAction` for `0`    | ID `<<1, 1>>`, observes `<<0>>`       |              4 |
|          8 |             9 | `MCRwTxResponseAction` for `2`    | ID `<<1, 3>>`, observes `<<0, 1, 2>>` |              5 |
|          9 |            10 | `MCStatusCommittedResponseAction` | `<<1, 1>>` enters `CommittedTxIDs`    |              6 |
|         10 |            11 | `MCStatusCommittedResponseAction` | `<<1, 3>>` enters `CommittedTxIDs`    |              7 |

There is deliberately no response or status event for transaction `1`. In the
final state:

```tla
CommittedTxIDs = {<<1, 1>>, <<1, 3>>}

CommittedRwResponses =
    <<
        [tx |-> 0, tx_id |-> <<1, 1>>, observed |-> <<0>>],
        [tx |-> 2, tx_id |-> <<1, 3>>, observed |-> <<0, 1, 2>>]
    >>
```

The old equality compared:

```text
actual   = <<0, 1, 2>>
expected = Append(<<0>>, 2) = <<0, 2>>
```

The intervening write `1` made that equality false. This is a
specification-property counterexample, not a CCF consistency counterexample.
In a real ledger, committing sequence number 3 commits the preceding ledger
prefix as well. The abstraction's `CommittedTxIDs` represents committed
statuses explicitly observed by clients, not every transaction covered by
the commit watermark.

## Why the witness satisfies the repaired invariant

For the same filtered pair, the repaired property evaluates as follows:

```tla
IsPrefix(<<0>>, <<0, 1, 2>>) = TRUE
Len(<<0>>) < Len(<<0, 1, 2>>) = TRUE
Last(<<0, 1, 2>>) = 2
```

The witness therefore passes for the intended reason: transaction `1` may
intervene, but the observation remains an ordered extension and transaction
`2` remains last.

## Model-checking bounds

The normal `MCMultiNode.cfg` and `MCMultiNodeReads.cfg` configurations use
`HistoryLimit = 6`. Seven external events are needed to expose the old
equality's mistake: three requests create the ledger entries, two responses
provide the compared pair, and two committed-status events retain that pair
in `CommittedRwResponses`.

The bound predates the ordered property. It was established with the original
consistency specification in commit
[`724c827247`](https://github.com/microsoft/CCF/commit/724c827247)
([PR #5699](https://github.com/microsoft/CCF/pull/5699)). Commit
[`bf4fcff670`](https://github.com/microsoft/CCF/commit/bf4fcff670)
([PR #6185](https://github.com/microsoft/CCF/pull/6185)) later introduced
`CommittedRwOrderedSpecLinearizableInv` without changing the bound.

The dedicated positive-check configurations raise `HistoryLimit` to 7:

```bash
cd tla
./tlc.py --workers 1 \
  --config consistency/MCSingleNodeOrderedSerializable.cfg \
  mc consistency/MCSingleNode.tla

./tlc.py --workers 1 \
  --config consistency/MCMultiNodeOrderedSerializable.cfg \
  mc consistency/MCMultiNode.tla
```

An exhaustive one-worker run checks 63,449 distinct single-node states and
21,586,197 distinct multi-node states without an invariant violation. The
multi-node check retains the normal `ViewLimit = 3`. It is intentionally not
added as a permanent CI job because this higher-bound exhaustive check is
substantially more expensive than the normal model-checking configurations.
