# Common Lean transition infrastructure

The `ccf_common` Lake package exposes protocol-independent definitions in the `CCF` namespace.

| Module                          | Purpose                                                      |
| ------------------------------- | ------------------------------------------------------------ |
| `CCF.Capabilities`              | Envelopes, ordered outputs, effects, and recording callbacks |
| `CCF.TransitionSystem`          | Initial states, enabled transitions, and reachability        |
| `CCF.MultiNodeTransitionSystem` | Local protocols composed into a message-passing network      |
| `CCF.Execution`                 | Finite runs and finite or infinite state traces              |
| `CCF.Parsec`                    | Stateful Parsec combinators over arrays of arbitrary events  |

`CCF.Execution` represents traces as Mathlib's `Stream'.Seq`, so the package depends on Mathlib.
`reachable_iff_trace` shows that valid finite traces reach exactly the reachable states.

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
Traces remain state sequences of type `Execution.Trace system.State`; `Execution.Trace.Valid system trace` (or `trace.Valid system`) checks them against the bundled system.

## Import coverage

After `lake build`, run `lake exe check-imports` from any package using `ccf_common`.
The command reads that package's library roots from Lake, loads their compiled transitive imports (including private imports), and scans the corresponding source directories.
It fails if any source module is missing from the imported modules, without requiring every module to be listed directly in the library root.
