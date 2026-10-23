# Common Lean transition infrastructure

The `ccf_common` Lake package exposes protocol-independent definitions in the `CCF` namespace.

| Module                          | Purpose                                                      |
| ------------------------------- | ------------------------------------------------------------ |
| `CCF.Capabilities`              | Envelopes, ordered outputs, effects, and recording callbacks |
| `CCF.TransitionSystem`          | Initial states, enabled transitions, and reachability        |
| `CCF.MultiNodeTransitionSystem` | Local protocols composed into a message-passing network      |
| `CCF.Execution`                 | Finite runs and finite or infinite state traces              |
| `CCF.WitnessedTheorem`          | Safety and an applicable case in a `Prop`-valued structure   |

`CCF.Execution` represents traces as Mathlib's `Stream'.Seq`, so the package depends on Mathlib.
`reachable_iff_trace` shows that valid finite traces reach exactly the reachable states.

## Transition systems

`CCF.TransitionSystem` bundles the `State` and `Action` types with the initial-state predicate `init` and the partial transition function `step`.
Define a model as `system : TransitionSystem`, setting `State` and `Action` in the structure rather than supplying type parameters.
Use `abbrev` for concrete systems so Lean can unfold their bundled types during typeclass inference.
Generic helpers use `system.State` and `system.Action`, while `system.Reachable state` and `Execution.Run system start actions final` describe executions.
Traces remain state sequences of type `Execution.Trace system.State`; `Execution.Trace.Valid system trace` (or `trace.Valid system`) checks them against the bundled system.

## Witnessed theorems

Import `CCF.WitnessedTheorem` to bundle a universal implication and an applicable case in an ordinary theorem:

```lean
theorem zero_add :
    CCF.WitnessedTheorem
      (requires := fun n : Nat => n = 0)

      (ensures := fun n => 0 + n = n)

      (witness_satisfies := fun n => n < 1) where

  proof := by
    intro n _
    exact Nat.zero_add n

  witness_proof := by exact ⟨0, rfl, by decide⟩

example : forall n : Nat, n = 0 -> 0 + n = n := zero_add.proof
example : exists n : Nat, n = 0 /\ n < 1 := zero_add.witness_proof
```

`witness_satisfies` is optional and constrains only the existential witness.
Bundle multiple parameters with products or dependent parameters with sigma types.

## Import coverage

After `lake build`, run `lake exe check-imports` from any package using `ccf_common`.
The command reads that package's library roots from Lake, loads their compiled transitive imports (including private imports), and scans the corresponding source directories.
It fails if any source module is missing from the imported modules, without requiring every module to be listed directly in the library root.
