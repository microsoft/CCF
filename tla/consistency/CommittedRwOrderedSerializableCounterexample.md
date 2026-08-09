# `CommittedRwOrderedSerializableInv` counterexample

## Result

`CommittedRwOrderedSerializableInv` is not an invariant of the consistency
transition system. A minimal counterexample has ten actions and seven external
history events. It requires no view change, read-only transaction, invalid
status, or non-client ledger entry, so it occurs in the single-node subset of
the model.

This is a specification-property failure, not a CCF consistency failure. The
property assumes that responses which are adjacent after filtering for
explicitly reported committed transaction IDs are also adjacent ledger
entries. The transition system does not make that assumption, and CCF does not
require it for serialisability.

The property remains defined in `ExternalHistoryInvars.tla` as the target of
the dedicated expected-counterexample configuration. It is not checked by the
normal multi-node configurations.

## The property

`CommittedRwResponses` contains read-write responses whose transaction IDs
have an explicit committed-status event in `history`, sorted by transaction
ID. The property requires each adjacent pair in that filtered sequence to
differ by exactly the later transaction:

```tla
CommittedRwOrderedSerializableInv ==
    \A i \in 1..Len(CommittedRwResponses)-1:
        CommittedRwResponses[i+1].observed =
            Append(
                CommittedRwResponses[i].observed,
                CommittedRwResponses[i+1].tx)
```

The equality is too strong. An intervening client write can be present in the
ledger and in the later response's observations without having its own
response or committed-status event in the external history.

## Minimal counterexample

TLC finds the following breadth-first trace. Transaction IDs are
`<<view, sequence number>>`.

| Step | Action                           | Relevant result                       | History length |
| ---: | -------------------------------- | ------------------------------------- | -------------: |
|    1 | Request transaction `0`          | Request `0` is visible                |              1 |
|    2 | Request transaction `1`          | Request `1` is visible                |              2 |
|    3 | Request transaction `2`          | Request `2` is visible                |              3 |
|    4 | Execute transaction `0`          | Ledger slot 1 is `(view 1, tx 0)`     |              3 |
|    5 | Execute transaction `1`          | Ledger slot 2 is `(view 1, tx 1)`     |              3 |
|    6 | Execute transaction `2`          | Ledger slot 3 is `(view 1, tx 2)`     |              3 |
|    7 | Respond to transaction `0`       | ID `<<1, 1>>`, observes `<<0>>`       |              4 |
|    8 | Respond to transaction `2`       | ID `<<1, 3>>`, observes `<<0, 1, 2>>` |              5 |
|    9 | Report transaction `0` committed | `<<1, 1>>` enters `CommittedTxIDs`    |              6 |
|   10 | Report transaction `2` committed | `<<1, 3>>` enters `CommittedTxIDs`    |              7 |

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

The property checks the only adjacent pair and compares:

```text
actual   = <<0, 1, 2>>
expected = Append(<<0>>, 2) = <<0, 2>>
```

The intervening `1` makes the equality false. The weaker
`CommittedRwSerializableInv` still holds because `<<0>>` is a prefix of
`<<0, 1, 2>>`.

In a real ledger, committing sequence number 3 commits the preceding ledger
prefix as well. The abstraction's `CommittedTxIDs`, however, represents
committed statuses explicitly observed by clients, not every transaction
implicitly covered by the commit watermark. Filtering responses with that set
can therefore hide transaction `1` even though later execution observes it.

The trace is minimal for this construction:

1. Three requests and three executions place an intervening write between the
   two compared ledger entries.
2. Two responses expose the observations being compared.
3. Two committed-status events include both outer responses in
   `CommittedRwResponses`.

These are ten actions. The execution actions do not append to `history`, so
the three requests, two responses, and two statuses produce seven history
events.

## Reproduce with TLC

On Ubuntu, install Java, `wget`, and the repository's TLC dependencies:

```bash
sudo apt update
sudo apt install -y default-jre wget
cd tla
python3 install_deps.py
```

From the `tla` directory, run the expected-counterexample wrapper:

```bash
./tlc_debug.sh --workers 1 --difftrace \
  --config consistency/MCSingleNodeOrderedSerializableCounterexample.cfg \
  mc consistency/MCSingleNode.tla
```

The dedicated configuration checks only
`CommittedRwOrderedSerializableInv`, as required by `tlc_debug.sh`. TLC
reports:

```text
Error: Invariant CommittedRwOrderedSerializableInv is violated.
...
Counterexample found as expected.
```

`MCSingleNode.tla` provides the smallest state space containing the violating
execution. The same execution is valid in `MCMultiNode.tla` and
`MCMultiNodeReads.tla`.

## Why existing model checking missed it

The normal `MCMultiNode.cfg` and `MCMultiNodeReads.cfg` configurations both
set:

```tla
HistoryLimit = 6
```

Seven external events are necessary: three requests create the ledger entries,
two responses provide the pair to compare, and two committed-status events
include that pair in the filtered sequence. With `HistoryLimit = 6`, TLC
exhaustively checks the bounded state graph but cannot reach the violating
state. Raising only this bound to 7 exposes the counterexample.

The bound predates the property. It was established with the original
consistency specification in commit
[`724c827247`](https://github.com/microsoft/CCF/commit/724c827247)
([PR #5699](https://github.com/microsoft/CCF/pull/5699)). Commit
[`bf4fcff670`](https://github.com/microsoft/CCF/commit/bf4fcff670)
([PR #6185](https://github.com/microsoft/CCF/pull/6185)) later introduced
`CommittedRwOrderedSpecLinearizableInv` and added it to the two multi-node
model-checking configurations without changing `HistoryLimit`.

The other configurations did not close the gap:

- The single-node configurations used a history limit of 7 but did not check
  the new property.
- `MCMultiNodeReadsAlt.cfg` used a larger history limit but did not check the
  new property.
- The configurations which checked the property remained capped at 6.

This was a scope-boundary blind spot, not a TLC search failure.

## Why the property fails

PR #6185 intended to state that committed read-write transactions are
serialisable in transaction-ID order. Its formula selects only responses with
explicitly observed committed statuses, sorts that filtered set, and then
treats adjacent elements as adjacent ledger writes.

Those notions of adjacency differ:

- Adjacent in `CommittedRwResponses` means no other response with an explicit
  committed-status event is between the pair.
- Adjacent in the ledger means no client write is between their sequence
  numbers.

The transition system permits a write to execute without a response or status
event. Such a write is absent from `CommittedRwResponses` but remains present
in every later observation of that ledger prefix. The `Append` equality
therefore cannot hold in general.

A replacement property requires a separate design decision. For example, it
could allow an observed suffix between the compared writes, or the abstraction
could distinguish actual ledger commitment from client receipt of a committed
status. This counterexample does not assert a replacement guarantee.
