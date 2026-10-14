# Common Lean transition infrastructure

The `ccf_common` Lake package exposes protocol-independent definitions in the `CCF` namespace.
It depends only on Lean's standard library and imports neither disaster recovery nor Raft.

| Module                          | Purpose                                                      |
| ------------------------------- | ------------------------------------------------------------ |
| `CCF.Capabilities`              | Envelopes, ordered outputs, effects, and recording callbacks |
| `CCF.TransitionSystem`          | Initial states, enabled transitions, and reachability        |
| `CCF.MultiNodeTransitionSystem` | Local protocols composed into a message-passing network      |
| `CCF.Execution`                 | Finite runs and state traces                                 |

`Effect Node Message Notification` is `StateT (Outputs Node Message Notification) Option`.
Running a node step produces `Option (LocalState × Outputs Node Message Notification)`.
A failed guard disables the entire step and discards its state and outputs, including sends and notifications recorded before the guard.
This is deliberately not `OptionT (StateM Outputs)`, which would retain outputs on failure.
Successful delivery removes exactly one occurrence of its envelope and appends outgoing messages in order; disabled delivery produces no successor and leaves the envelope pending.

Consumers add a local Lake dependency:

```toml
[[require]]
name = "ccf_common"
path = "../common"
copy = true
```

Import the individual modules above or `CCF` for the complete library.
`copy = true` materializes the dependency inside the consumer's `.lake` directory, allowing `lake check` to build it within its sandbox.
Run `lake update --keep-toolchain ccf_common` in the consumer after editing the common sources to refresh that copy.
`Protocol.step` returns an effect directly.
`Protocol.ValidStep s` requires `(protocol.step (Capabilities.record s.node) s.node s.before s.action).run {} = some (s.after, s.effects)`.
Node handlers can use flat `do` blocks with `guard`, `host.send`, `host.notify`, and `return`.

Run `lake build --wfail --fail-fast`, `lake lint`, and `lake check` from this directory.
The disaster-recovery package also checks the common declarations through its full-library import graph and existing model, proof, and regression checks.
See its [validation instructions](../disaster-recovery/README.md#validation) for the full consumer checks and sandbox prerequisites.
