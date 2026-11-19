# Consensus model driver

`cft_model_driver` runs the [consensus scenarios](../cft_scenarios/README.md) on the [Lean model](../../lean/consensus/README.md) of the protocol, without the implementation.
A scenario is the same program for both: [`cft_driver`](../cft_scenarios/README.md#running-scenarios) binds its commands to [`cft.h`](../../src/consensus/aft/cft.h), and `cft_model_driver` binds them to the model.
Its assertions must then hold of the model, and it writes what the model did as a trace, to compare with that of the implementation.

## Runs

```sh
build/cft_model_driver <name> [<trace>]
build/cft_model_driver --all [<directory>]
```

- `<name>` runs the scenario of that name, and writes its trace to the file `<trace>`, if given.
- `--all` runs every scenario, and writes the trace of each to `<directory>/<name>.ndjson`, if given.

A run exits with status 1 if a command of a scenario fails, and 2 if its arguments are wrong.
As the scenario driver does, it asserts after each command which can alter state that the commit index of every node is safe, and confirms after the last that the network can still make progress.

## Trace

A trace has one line of JSON for each command, in order, and a last one for `finish`, which confirms progress.

- `cmd` is the command and its arguments, separated by commas, as in the `cmd` record of a [trace of the implementation](../cft_scenarios/README.md#bindings).
- `actions` are the steps of the model which the command caused, in order.
  Each has the `node_id` which took it, and its `action`: `append`, `sendEntries`, `timeout`, `nominateSuccessor`, `initAsBackup`, or `receive` with the `packet` and the node which it is from.
  `sent` are the packets which the step sent, each with the node which it is to.
  A step which the model does not allow has `allowed` false, and changes nothing.
  `lose` is not a step of the model: the message is no longer undelivered, because it was dropped, or its sender and target are not connected.
- `nodes` is the state in which the command leaves each node.
- `error` is why the command failed, if it did.

The state of a node and a packet have the fields which a trace of the implementation gives them, such as `leadership_state`, `current_view`, `last_idx` and `commit_idx`.

## Driving the model

The model does not say when a timer fires, when a primary sends, or which message is delivered next: those are its inputs.
[`ModelDriver.lean`](ModelDriver.lean) decides them as [`driver.h`](../../src/consensus/aft/test/driver.h) and `cft.h` do:

- A node has a clock, which `periodicOne` and `periodicAll` advance.
  A primary sends to each peer when its clock reaches the request timeout of 10 ms, and steps down unless a majority of each configuration has acknowledged it within the election timeout of 100 ms.
  Another node starts an election when its clock reaches the election timeout.
  The clock restarts where `cft.h` restarts it: when the node changes role or term, accepts an AppendEntries, or grants a vote.
- A node has a queue of the messages which it has sent, which the `dispatch` commands deliver oldest first, and the `drop` commands lose.
  A message is lost if its sender and target are not connected when it is delivered.
- A primary sends to a peer all the entries which the peer lacks, in one message for each term.

It differs from them in what follows, which no scenario depends on:

- A restarted clock starts at 0, where `cft.h` starts it at random within half the election timeout.
- A primary does not limit the entries of a message by their size, and `replicate` does not send before the end of a batch which exceeds 20,000 bytes.
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
