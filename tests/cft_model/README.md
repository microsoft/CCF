# Consensus model driver

`cft_model_driver` runs the [consensus scenarios](../cft_scenarios/README.md) with the [Lean model](../../lean/consensus/README.md) of the protocol in the same process.
The driver keeps its trace in memory, and [replay](../../lean/consensus/replay/README.md) checks it against the model once the scenario has run.

## Runs

```sh
build/cft_model_driver <name>
build/cft_model_driver --all
```

- `<name>` runs the scenario of that name, then replays its trace, as [`consensus-replay`](../../lean/consensus/replay/README.md) does a trace file.
- `--all` runs every scenario, each in a process of its own, because a process can start the driver once.
  A run fails if its process does not exit with status 0, whether or not it writes an error, and `--all` reports that status.

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

[`ModelDriver.lean`](ModelDriver.lean) imports the scenarios and [`Reduction.lean`](../../lean/consensus/Consensus/Replay/Reduction.lean), and defines `main`.
`lake` compiles it, the scenarios and the model to static libraries.
`cft_model_driver` links them with [`driver.cpp`](../../src/consensus/aft/test/driver.cpp) and the Lean runtime, as `cft_driver` does the scenarios.
