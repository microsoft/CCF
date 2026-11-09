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
| `CCF.Seq`                       | Possibly infinite sequences (replaces Mathlib `Stream'.Seq`) |
| `CCF.Finset`                    | Finite sets as strictly sorted lists (replaces `Finset`)     |
| `CCF.Function`                  | Point updates of functions (replaces `Function.update`)      |
| `CCF.Proofs.Execution`          | Theorems about runs, traces, and reachability                |
| `CCF.Proofs.Finset`             | Lemmas about the `CCF.Finset` operations                     |

`CCF.Execution.TraceImpl system` records an `init` state and a possibly infinite `steps` sequence pairing each action with its destination state.
`CCF.Execution.Trace system` is the subtype whose `TraceImpl.Valid` proof establishes initialization and every recorded transition.
`reachable_iff_trace`, in `CCF.Proofs.Execution`, shows that finite execution traces reach exactly the reachable states.

As in the specification packages, definitions and the theorems about them live in separate modules.
Theorems go under `CCF.Proofs`, keeping their original names, so `CCF.Execution.reachable_iff_trace` is declared in `CCF.Proofs.Execution`.
Definition modules keep only the proofs their definitions carry, such as the sortedness of `CCF.Finset` and the stability of `CCF.Seq`.
`CCF.Seq` and `CCF.Function` keep their few `rfl` and `simp` lemmas alongside their definitions.

## Dependency imports

The packages depend only on Lean core, leanfmt and (for the disaster-recovery and kv `lake lint` drivers) Batteries, not on Mathlib.
`CCF.Seq`, `CCF.Finset`, and `CCF.Function` are minimal replacements for the Mathlib facilities the specifications used that Lean core, Std and Batteries do not provide.
Specification proofs import only the modules they need.
Their CCF declarations, theorem statements, exposed definitions, and required tactic support remain available, but importing a proof module or an assembled specification root does not promise to reexport unrelated tactics or theory.
Consumers that need other facilities should import their defining modules explicitly.
The documented property entrypoints remain the public proof APIs; see the [CCF consensus protocol](../consensus/README.md#proofs), [consistency](../consistency/README.md#properties), and [disaster recovery](../disaster-recovery/README.md#properties) packages.

Selective imports do not reduce the checked CCF roots or omit tests.
`lake check` still exports the complete imported environment and checks its safe declarations and axiom dependencies, including declarations from dependencies.
Compilation caches do not avoid this independent kernel check.

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
The sequences are derived from `init` and `steps`, so finite traces always have one more state than action.
Use `action ∈ trace.actions` for action membership; `State` and `Action` can be the same type, so `action ∈ trace` cannot safely be overloaded.
`trace.reachable` proves that every member state is reachable.

## Import coverage

After `lake build`, run `lake exe check-imports` from any package using `ccf_common`.
The command reads that package's library roots from Lake, loads their compiled transitive imports (including private imports), and scans the corresponding source directories.
It fails if any source module is missing from the imported modules, without requiring every module to be listed directly in the library root.

## Architecture checks

After `lake build`, run the same `lake exe check-imports` command to check architecture as well as import coverage.
The shared command discovers the package's library roots from Lake and applies `CCF.Architecture` to each specification root.
The `CCF` root contains shared infrastructure; it is not treated as a specification and is checked only against the common rules below.
New specifications need no per-model architecture test, namespace configuration, or additional CI command.

The checker examines direct import edges throughout each library root's transitive import closure, including private imports.
Import coverage ensures that all source modules are included.
Architecture checks run in `lake exe check-imports`, not during `lake build`; CI already runs this command for every Lean package.

The same rules apply to every specification namespace, including multi-component names:

- `CCF` modules cannot import the specification.
- Within `CCF`, only the `CCF` entrypoint and `CCF.Proofs` modules can import `CCF.Proofs`.
- `Model` and its submodules cannot import `CCF.Proofs` or the `CCF` entrypoint that reexports it, so models depend only on shared definitions.
- `Model` and its submodules can import only model modules within the specification.
  Model submodules cannot import the assembled `Model` entrypoint.
- The `Properties` entrypoint can import model modules, property helpers, and proofs.
- Property helpers can import model modules and other property helpers, but not proofs or the `Properties` entrypoint.
- Proofs can import model modules, property helpers, and other proofs, but not the `Properties` entrypoint.
- Other modules, such as tests and trace validation, are unrestricted.
  Imports outside the specification namespace are unrestricted except for the `CCF` restrictions above.
