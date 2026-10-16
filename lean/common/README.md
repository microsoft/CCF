# Common Lean transition infrastructure

The `ccf_common` Lake package exposes protocol-independent definitions in the `CCF` namespace.

| Module                          | Purpose                                                          |
| ------------------------------- | ---------------------------------------------------------------- |
| `CCF.Capabilities`              | Envelopes, ordered outputs, effects, and recording callbacks     |
| `CCF.TransitionSystem`          | Initial states, enabled transitions, and reachability            |
| `CCF.MultiNodeTransitionSystem` | Local protocols composed into a message-passing network          |
| `CCF.Execution`                 | Finite runs and state traces                                     |
| `CCF.Architecture`              | Build-time layering and proof-coverage checks for model packages |
