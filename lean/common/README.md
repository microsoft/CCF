# Common Lean transition infrastructure

The `ccf_common` Lake package exposes protocol-independent definitions in the `CCF` namespace.

| Module                          | Purpose                                                      |
| ------------------------------- | ------------------------------------------------------------ |
| `CCF.Capabilities`              | Envelopes, ordered outputs, effects, and recording callbacks |
| `CCF.TransitionSystem`          | Initial states, enabled transitions, and reachability        |
| `CCF.MultiNodeTransitionSystem` | Local protocols composed into a message-passing network      |
| `CCF.Execution`                 | Finite runs and finite or infinite state traces              |
| `CCF.WitnessedTheorem`          | Paired safety and existential witness declarations           |

`CCF.Execution` represents traces as Mathlib's `Stream'.Seq`, so the package depends on Mathlib.
`reachable_iff_trace` shows that valid finite traces reach exactly the reachable states.

## Witnessed theorems

Import `CCF.WitnessedTheorem` to state a safety theorem and an applicable case without repeating their parameters or assumptions:

```lean
witnessed_theorem zero_add
  for (n : Nat)
  requires n = 0
  ensures 0 + n = n
  witness_satisfies n < 1
  proof := by
    intro n _
    exact Nat.zero_add n
  witness_proof := by
    exact ⟨0, rfl, by decide⟩
```

This generates ordinary theorems `zero_add : ∀ (n : Nat), n = 0 → 0 + n = n` and `zero_add_witness : ∃ (n : Nat), n = 0 ∧ n < 1`.
Each proof covers its complete quantified statement; omitting `witness_satisfies` removes the extra witness predicate.
The witness is always named `<theorem_name>_witness`; both declarations navigate to the command's theorem name.
Use a simple theorem name in the current namespace and named, explicitly typed parameters without placeholders.
Shared regression tests run with `lake build CCF.Tests.WitnessedTheorem`.

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
