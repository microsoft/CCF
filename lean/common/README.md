# Common Lean transition infrastructure

The `ccf_common` Lake package exposes protocol-independent definitions in the `CCF` namespace.

| Module                          | Purpose                                                      |
| ------------------------------- | ------------------------------------------------------------ |
| `CCF.Capabilities`              | Envelopes, ordered outputs, effects, and recording callbacks |
| `CCF.TransitionSystem`          | Initial states, enabled transitions, and reachability        |
| `CCF.MultiNodeTransitionSystem` | Local protocols composed into a message-passing network      |
| `CCF.Execution`                 | Finite runs and countably infinite state traces              |

`Execution.Trace.states` is a function from `Nat` to states.
A valid trace starts in an initial state and has an enabled action between every adjacent pair; membership means that a state occurs at some natural-number index.
Validity adds neither implicit stuttering nor fairness, and a reachable state need not belong to an infinite valid trace if its execution cannot continue.
`Run` relates a start state and a finite action list to an end state.
