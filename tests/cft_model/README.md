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
  It also runs each scenario again from its [recorded commands](#programs), which must show the same outcomes, and [explores](#exploring) briefly.

A run prints its status as JSON.
It exits with status 1 if a command fails or the model rejects the trace, and 2 if its arguments are wrong.

## Programs

A trace records each command of a scenario as its name and arguments, separated by commas.
A program is a file of such commands, one on each line, which the model driver runs without compiling a scenario:

```sh
build/cft_model_driver --record <name> <name>.program
build/cft_model_driver --run <name>.program [<result>.json]
```

- `--record` runs a scenario and writes the commands which it issued as a program.
- `--run` runs a program, and checks its trace against the model: before the driver confirms that the network can make progress, and after.
  With a result file, it writes there the status of the run, the [outcomes](../../lean/consensus/replay/README.md#outcomes) which the model shows, and the commands which it issued.
  It writes beside it the edges of the consensus implementation which the run reached, and the trace if the run is a finding.

A line of a program which starts with `#` is a comment.
One which starts with `@` is a choice, which the driver makes when the run reaches it, among what its state then allows.
For example, `@hold 7` holds one of the undelivered messages, and `@release 7` delivers one of those held.
The number selects which, so a program always runs in the same way.
A step which the state does not allow is left out, such as a command for a node which does not exist.

## Exploring

```sh
build/cft_model_driver --explore <directory> [--seed N] [--runs N] [--jobs N]
```

The commands of each scenario, without its assertions, are a first program.
The model driver changes a program at random: it holds a message until later, loses or delivers one early, advances the clock of a node, disconnects a node for a while, nominates, replicates, or leaves out, repeats or swaps commands.
It runs each changed program in a process of its own.

- A run is kept, to be changed in turn, if the model shows an outcome, or the run reaches an edge of [`cft.h`](../../src/consensus/aft/cft.h), which no run before it has.
  It is run a second time first, and is only kept if it does so again.
- A run is a finding if the driver fails, for example because a commit is unsafe, or if the model rejects its trace.
  Findings with the same message, numbers aside, are counted together.
- A run is neither if the model does not cover it, for example because a primary is asked to remove a node which has not retired.

The directory receives the programs kept in `corpus/`, the first program and trace of each finding in `findings/`, the edges which the scenarios reach in `scenarios.edges`, and `report.md`.
The same seed gives the same changes.

```sh
build/cft_model_driver --shrink <program> <shorter program> [--outcome <outcome> | --edges <edges>]
build/cft_model_driver --scenario <program> <name> <name>.lean
```

- `--shrink` leaves out steps of a program for as long as its run is the same finding.
  With `--outcome`, it does so for as long as the model accepts the run and shows that outcome.
  With `--edges`, it does so for as long as the model accepts the run, and the run reaches every edge which it reached at first and the edges in that file lack, such as `scenarios.edges`.
- `--scenario` writes a program as a scenario in Lean, which ends by asserting the leadership and the commit index of each node.

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

- [`Command.lean`](ModelDriver/Command.lean): driver commands as data, programs, and scenarios written from them.
- [`Episode.lean`](ModelDriver/Episode.lean): one run of the driver in a process, checked against the model.
- [`Explore.lean`](ModelDriver/Explore.lean): the changes made to programs, the runs kept, and the findings.
- [`edges.allowlist`](edges.allowlist): the functions whose edges the driver counts, for which `driver.cpp` is compiled with `-fsanitize-coverage`, and without inlining, so that the edges are those of `cft.h` only.
