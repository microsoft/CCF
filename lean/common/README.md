# Common Lean transition infrastructure

The `ccf_common` Lake package exposes protocol-independent definitions in the `CCF` namespace.

| Module                          | Purpose                                                      |
| ------------------------------- | ------------------------------------------------------------ |
| `CCF.Capabilities`              | Envelopes, ordered outputs, effects, and recording callbacks |
| `CCF.TransitionSystem`          | Initial states, enabled transitions, and reachability        |
| `CCF.MultiNodeTransitionSystem` | Local protocols composed into a message-passing network      |
| `CCF.Execution`                 | Finite runs and finite or infinite recorded-step traces      |
| `CCF.Architecture`              | Checks of specification import layering                      |

`CCF.Execution` represents a trace as an initial state and a finite or infinite sequence of recorded steps, using Mathlib's `Stream'.Seq`.
Each step records its before-state, action, and after-state, and the steps form a linked path from the initial state.
`trace.stepAt i` reads a recorded step, while `trace.stateAt i` reads the state after `i` steps, including the initial state at zero.
Membership `state ∈ trace` means that `trace.stateAt i = some state` for some position.
`Trace.ofStream states actions` constructs an infinite trace, and `Trace.run system initial actions` executes a finite action list, stopping before the first disabled action.
`reachable_iff_trace` shows that valid traces contain exactly the reachable states, with every reachable state occurring in a valid finite trace.

## Transition systems

`CCF.TransitionSystem` bundles the `State` and `Action` types with the initial-state predicate `init` and the partial transition function `step`.
Define a model as `system : TransitionSystem`, setting `State` and `Action` in the structure rather than supplying type parameters.
Use `abbrev` for concrete systems so Lean can unfold their bundled types during typeclass inference.
Generic helpers use `system.State` and `system.Action`, while `system.Reachable state` and `Execution.Run system start actions final` describe executions.
Traces have type `Execution.Trace system.State system.Action`; `Execution.Trace.Valid system trace` (or `trace.Valid system`) requires an initial state and checks each recorded step against the bundled system.

## Import coverage

After `lake build`, run `lake exe check-imports` from any package using `ccf_common`.
The command reads that package's library roots from Lake, loads their compiled transitive imports (including private imports), and scans the corresponding source directories.
It fails if any source module is missing from the imported modules, without requiring every module to be listed directly in the library root.

## Architecture checks

After `lake build`, run the same `lake exe check-imports` command to check architecture as well as import coverage.
The shared command discovers the package's library roots from Lake and applies `CCF.Architecture` to each specification root.
The `CCF` root contains shared infrastructure and is not treated as a specification.
New specifications need no per-model architecture test, namespace configuration, or additional CI command.

The checker examines direct import edges throughout each library root's transitive import closure, including private imports.
Import coverage ensures that all source modules are included.
Architecture checks run in `lake exe check-imports`, not during `lake build`; CI already runs this command for every Lean package.

The same rules apply to every specification namespace, including multi-component names:

- `CCF` modules cannot import the specification.
- `Model` and its submodules can import only model modules within the specification.
  Model submodules cannot import the assembled `Model` entrypoint.
- The `Properties` entrypoint can import model modules, property helpers, and proofs.
- Property helpers can import model modules and other property helpers, but not proofs or the `Properties` entrypoint.
- Proofs can import model modules, property helpers, and other proofs, but not the `Properties` entrypoint.
- Other modules, such as tests and trace validation, are unrestricted.
  Imports outside the specification namespace are unrestricted except for the common-to-specification restriction above.
