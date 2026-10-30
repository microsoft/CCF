# Common Lean transition infrastructure

The `ccf_common` Lake package exposes protocol-independent definitions in the `CCF` namespace.

| Module                          | Purpose                                                      |
| ------------------------------- | ------------------------------------------------------------ |
| `CCF.Capabilities`              | Envelopes, ordered outputs, effects, and recording callbacks |
| `CCF.TransitionSystem`          | Initial states, enabled transitions, and reachability        |
| `CCF.MultiNodeTransitionSystem` | Local protocols composed into a message-passing network      |
| `CCF.Execution`                 | Finite runs and finite or infinite execution traces          |
| `CCF.Parsec`                    | Stateful Parsec combinators over arrays of arbitrary events  |
| `CCF.Architecture`              | Checks of specification import layering                      |

`CCF.Execution.Trace system` records state and action sequences using Mathlib's `Stream'.Seq`, so the package depends on Mathlib.
The trace bundles proofs of initialization, enabled transitions, and aligned domains: action `n` exists exactly when state `n + 1` exists.
Finite traces therefore contain one more state than action, including initial-only traces with no actions.
`reachable_iff_trace` shows that finite execution traces reach exactly the reachable states.

## Event parsing

`CCF.Parsec.ParserT Event State` parses an immutable `Array Event` while threading application-defined state.
The cursor uses natural-number positions, so events need no equality instance.
`peek`, `take`, and `satisfy` inspect or consume events; `many`, `many_`, `optionalRule`, and `optional_` preserve Parsec's committed-choice behavior while threading state.
A failed alternative discards its application-state changes, but failure after consuming input cannot select another alternative.
Wrap a speculative rule in `attempt` to restore both input and application state on failure, including failure after consumption.
Attempts retain the farthest consumed-pattern diagnostic separately from the cursor and application state.
If the parse ultimately fails before that position, `run` reports that diagnostic rather than a later generic mismatch; successful parses ignore discarded-branch diagnostics.
Every repeated rule must consume input when it succeeds.
`failure` and `validated` report parser or application-validation errors.
Run a parser with `CCF.Parsec.run events (parser.run initialState)`; include `CCF.Parsec.eof` when trailing events must be rejected.
Protocol-specific matching, diagnostics, and output emission belong in the consuming package.

## Transition systems

`CCF.TransitionSystem` bundles the `State` and `Action` types with the initial-state predicate `init` and the partial transition function `step`.
Define a model as `system : TransitionSystem`, setting `State` and `Action` in the structure rather than supplying type parameters.
Use `abbrev` for concrete systems so Lean can unfold their bundled types during typeclass inference.
Generic helpers use `system.State` and `system.Action`, while `system.Reachable state` and `Execution.Run system start actions final` describe executions.
Traces have type `Execution.Trace system`, with validity carried by the structure rather than a separate premise.
Use `trace.stateAt n` and `trace.actionAt n` for optional indexed access, `state ∈ trace` for state membership, and `trace.states` and `trace.actions` to access the sequences directly.
`trace.reachable` proves that every member state is reachable.

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
