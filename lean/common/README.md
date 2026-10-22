# Common Lean transition infrastructure

The `ccf_common` Lake package exposes protocol-independent definitions in the `CCF` namespace.

| Module                          | Purpose                                                      |
| ------------------------------- | ------------------------------------------------------------ |
| `CCF.Capabilities`              | Envelopes, ordered outputs, effects, and recording callbacks |
| `CCF.TransitionSystem`          | Initial states, enabled transitions, and reachability        |
| `CCF.MultiNodeTransitionSystem` | Local protocols composed into a message-passing network      |
| `CCF.Execution`                 | Finite runs and finite or infinite state traces              |

`CCF.Execution` represents traces as Mathlib's `Stream'.Seq`, so the package depends on Mathlib.
`reachable_iff_trace` shows that valid finite traces reach exactly the reachable states.

## Import coverage

After `lake build`, run `lake exe check-imports` from any package using `ccf_common`.
The command reads that package's library roots from Lake, loads their compiled transitive imports (including private imports), and scans the corresponding source directories.
It fails if any source module is missing from the imported modules, without requiring every module to be listed directly in the library root.
