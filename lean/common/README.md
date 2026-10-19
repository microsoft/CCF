# Common Lean transition infrastructure

The `ccf_common` Lake package exposes protocol-independent definitions in the `CCF` namespace.

| Module                          | Purpose                                                      |
| ------------------------------- | ------------------------------------------------------------ |
| `CCF.Capabilities`              | Envelopes, ordered outputs, effects, and recording callbacks |
| `CCF.TransitionSystem`          | Initial states, enabled transitions, and reachability        |
| `CCF.MultiNodeTransitionSystem` | Local protocols composed into a message-passing network      |
| `CCF.Execution`                 | Finite runs and state traces                                 |

The shared network stores node states and queued messages.
Each execution starts with distinct node identities and an empty queue; transitions do not create nodes.
Protocols specify any required nodes and impose their own participation or availability restrictions around the shared transition system.
