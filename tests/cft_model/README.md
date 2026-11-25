# Consensus model driver

`cft_model_driver` runs the [consensus scenarios](../cft_scenarios/README.md) on the [Lean model](../../lean/consensus/README.md) of the protocol, without the implementation.
A scenario is the same program for both: [`cft_driver`](../cft_scenarios/README.md#running-scenarios) binds its commands to [`cft.h`](../../src/consensus/aft/cft.h), and `cft_model_driver` binds them to the model.
Its assertions must then hold of the model, and it writes what the model did as the trace which the implementation would write, to compare the two.

## Runs

```sh
build/cft_model_driver <name> [<trace>]
build/cft_model_driver --all [<directory>]
```

- `<name>` runs the scenario of that name, and writes its trace to the file `<trace>`, if given.
- `--all` runs every scenario, and writes the trace of each to `<directory>/<name>.ndjson`, if given.

A run exits with status 1 if a command of a scenario fails, and 2 if its arguments are wrong.
As the scenario driver does, it asserts after each command which can alter state that the commit index of every node is safe, and confirms after the last that the network can still make progress.
A trace is written up to the command which fails.

## Trace

A trace has the records of a [trace of the implementation](../../lean/consensus/replay/README.md), as the scenario test writes them to `consensus/raw/<name>.ndjson`: one line of JSON for each, with the same fields in the same order.

- `pid` identifies the process, by its ID and the time at which it started, and `m_ts` numbers the records of a trace from 0.
- `msg` is the record: `{"cmd": ...}` for each command of the scenario, followed by the events which it caused.
  An event has the `function` of `cft.h` which traces it, such as `recv_append_entries`, and what that function traces: the `state` of the node, a `packet`, the `configurations` of the node.

A step of the model is one call of `cft.h`, which traces several events as it goes, some with the state of the node part of the way through.
[`ModelDriver.lean`](ModelDriver.lean) writes those events from the state of the node before the step, the messages which the model sent in it, and the definitions of the model.
It fails the command unless the events show each message which the step sent, and end in the state which the model gives the node.
A step which the model does not allow writes no event, as a call of `cft.h` which returns at once.

The trace of a scenario is then that of the implementation, byte for byte but for `pid`, unless the two differ in what they do.
The model driver itself [differs](#driving-the-model) from the scenario driver where an election timeout decides, because the implementation chooses it at random: such a trace of the implementation is not the same from one run to the next either.

To compare the two traces of a scenario, after `cft_scenario_test` and `cft_model_test`:

```sh
diff <(sed 's/"pid": "[^"]*"//' build/consensus/raw/<name>.ndjson) \
  <(sed 's/"pid": "[^"]*"//' build/consensus/model/<name>.ndjson)
```

## Driving the model

The model does not say when a timer fires, when a primary sends, or which message is delivered next: those are its inputs.
`ModelDriver.lean` decides them as [`driver.h`](../../src/consensus/aft/test/driver.h) and `cft.h` do:

- A node has a clock, which `periodicOne` and `periodicAll` advance.
  A primary sends to each peer when its clock reaches the request timeout of 10 ms, and steps down unless a majority of each configuration has acknowledged it within the election timeout of 100 ms.
  Another node starts an election when its clock reaches the election timeout.
  The clock restarts where `cft.h` restarts it: when the node changes role or term, accepts an AppendEntries, or grants a vote.
- A node has a queue of the messages which it has sent, which the `dispatch` commands deliver oldest first, the `drop` commands lose, and `pendingMessages` lists.
  A message is lost if its sender and target are not connected when it is delivered.
- A primary sends a peer the entries which it lacks in messages of one term each, and of as many entries as `cft.h` would send.
  That number follows the size of the entries which the node has replicated, so the model driver gives each entry the size which the scenario driver replicates for it.
  As `cft.h`, a primary also sends before the end of a batch, once it has replicated 20,000 bytes since it last did.

It differs from them in what follows:

- A restarted clock starts at 0, where `cft.h` starts it at random within half the election timeout.
  A node of the implementation may so start an election a few ticks before that of the model, as at the end of `nominate_successor`, when the driver confirms progress.
- An AppendEntries holds the entries which its sender had when it sent it, where the scenario driver reads them from the ledger of the sender when it delivers the message.
  Both lose the message if the sender no longer holds entries up to its last index.
- The name of a node has at most 16 bytes.
- `nodes`, which is deprecated, fails: the model has no network which starts without a primary.

## Building

The model driver needs Lean, as [`cft_driver`](../cft_scenarios/README.md#running-scenarios) does, and CMake builds it only on request:

```sh
cmake -S . -B build -GNinja -DCFT_MODEL_DRIVER=ON
cmake --build build --target cft_model_driver
ctest --test-dir build -VV -R '^cft_model_test$' --no-tests=error
```

`cft_model_test` runs `cft_model_driver --all consensus/model`, which writes the traces beside those of the scenario test, in `consensus/raw/`.
For the model driver, `lake` builds the consensus model, and fetches from GitHub the formatter which the package of the model requires.

## Bindings

[`CftDriver.lean`](../cft_scenarios/CftDriver.lean) declares each command as a C function, `cft_*`.
[`ModelDriver.lean`](ModelDriver.lean) implements each on the model as `model_cft_*`, and defines `main`.
[`shim.c`](shim.c) defines `cft_*` to call `model_cft_*`: a command borrows its arguments, and a function which Lean exports owns them.
`lake` compiles the model driver, the scenarios and the model to static libraries, which `cft_model_driver` links with `shim.c` and the Lean runtime.
It links neither [`driver.cpp`](../../src/consensus/aft/test/driver.cpp) nor any other part of CCF.
