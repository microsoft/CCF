# Consensus scenarios

Each file in [`Scenarios/`](Scenarios) is a Lean program which drives a network of CCF consensus nodes ([`src/consensus/aft/cft.h`](../../src/consensus/aft/cft.h)) through one scenario, controlling time and message delivery.

```lean
import CftDriver

open CftDriver

-- A second node joins, and replicates the ledger
initialize scenario "example" do
  startNode 0
  replicate 2 [signature]
  assertCommitIdx 0 2

  trustNode 2 1
  replicate 2 ["hello", signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  assertCommitIdx 1 5
  assertDetail 1 "leadership_state" "Follower"
```

[`CftDriver.lean`](CftDriver.lean) documents every command.
Node identifiers and terms are written as numbers or strings, and `latest` is the primary in the highest term.
Each `replicate` appends one batch of entries, which are transaction data or `signature`.
A scenario delivers the messages of a node in the order in which they were sent, or picks one: `dispatchNth` delivers it, `dropNth` loses it, and `holdNth` sets it aside until `dispatchHeld` delivers it, however late.
Scenarios are ordinary Lean, so they can also use loops, conditions and definitions.

After each command which can alter state, the driver asserts that the commit index of every node is safe.
After the last command, it confirms that the network can still make progress.
A node starts its election timer as a real node does, when it first holds a signature while it is in its latest configuration.
Advancing its clock before that starts no election.

## Adding a scenario

1. Create `Scenarios/<name>.lean`, which registers the scenario `<name>` as above.
2. Import it in [`Scenarios.lean`](Scenarios.lean).

The scenario test fails for a file in `Scenarios/` which is not imported.

## Running scenarios

Building `cft_driver` needs [Lean](https://lean-lang.org/install/), in addition to the [CCF build prerequisites](../../doc/contribute/build_ccf.rst).
If CMake cannot find `lake` when configuring, it does not build `cft_driver` and disables `cft_scenario_test`.
From the repository root, run one scenario:

```sh
cmake --build build --target cft_driver
build/cft_driver <name>
```

To also write the trace of the scenario to a file, name the file:

```sh
build/cft_driver <name> <name>.ndjson
```

`cft_scenario_test` runs every scenario in `Scenarios/` with [`cft_scenarios_runner.py`](../cft_scenarios_runner.py), which needs Python `msgpack`:

```sh
ctest --test-dir build -VV -R '^cft_scenario_test$' --no-tests=error
```

The runner prints each scenario as a Mermaid sequence diagram, and writes its trace to `consensus/raw/<name>.ndjson` in the build directory.
[`consensus-replay`](../../lean/consensus/replay/README.md) validates these traces against the Lean model of the protocol.

## Bindings

`lake` compiles the scenarios to a static library, which defines `main` in [`Main.lean`](Main.lean).
`cft_driver` links it with [`driver.cpp`](../../src/consensus/aft/test/driver.cpp), which implements each command declared in `CftDriver.lean` by calling `CftDriver` in [`driver.h`](../../src/consensus/aft/test/driver.h), and with the Lean runtime.
A trace records each command as a `cmd` record, naming the command and its arguments.
The driver exports its trace over TCP, to a Fluentd collector such as the scenario test runs.
For a trace file, and for `takeTrace`, `driver.cpp` collects it from a local port in the same process.

Another program can import `Scenarios` and define its own `main`.
The [consensus model driver](../cft_model/README.md) does, to run the scenarios with the Lean model of the protocol in the same process.
