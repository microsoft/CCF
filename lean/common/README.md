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
