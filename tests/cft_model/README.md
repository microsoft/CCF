# Consensus model driver

`cft_model_driver` runs the [consensus scenarios](../cft_scenarios/README.md) with the [Lean model](../../lean/consensus/README.md) of the protocol in the same process.
The driver keeps its trace in memory, and [replay](../../lean/consensus/replay/README.md) checks it against the model as the run goes, so a program can read the state of the model to choose its next command.

## Runs

```sh
build/cft_model_driver <name>
build/cft_model_driver --in-step
build/cft_model_driver --all
```

- `<name>` runs the scenario of that name, then replays its trace whole and [by command](../../lean/consensus/replay/README.md#replay-by-command), which must agree.
- `--in-step` runs commands chosen from the model.
  It replays each command as soon as the driver has run it, and requires each undelivered message of the driver to be a message which the model holds.
  It delivers the messages which the model holds, newest first, and asserts of the driver the commit indexes of the model.
- `--all` runs every scenario and the run in step, each in a process of its own, because a process can start the driver once.

A run prints its status as JSON.
It exits with status 1 if a command fails or the model rejects the trace, and 2 if its arguments are wrong.

## Building

The model driver needs the same prerequisites as [`cft_driver`](../cft_scenarios/README.md#running-scenarios), and CMake builds it only on request:

```sh
cmake -S . -B build -GNinja -DCFT_MODEL_DRIVER=ON
cmake --build build --target cft_model_driver
ctest --test-dir build -VV -R '^cft_model_test$' --no-tests=error
```

`cft_model_test` runs `cft_model_driver --all`.
For the model driver, `lake` builds the consensus model, and fetches from GitHub the formatter which the package of the model requires.

## Bindings

[`ModelDriver.lean`](ModelDriver.lean) imports the scenarios and [`Session.lean`](../../lean/consensus/Consensus/Replay/Session.lean), and defines `main`.
`lake` compiles it, the scenarios and the model to static libraries.
`cft_model_driver` links them with [`driver.cpp`](../../src/consensus/aft/test/driver.cpp) and the Lean runtime, as `cft_driver` does the scenarios.
