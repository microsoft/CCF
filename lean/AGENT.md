# CCF Lean objectives

We use agents to generate models and proofs that those models are correct.
We use trace validation to align the models with the implementation.
Formally, if B(X) is the set of behaviours permitted by X, then B(implementation) \subseteq B(Model) \subseteq B(Properties).

The aim of this spec is to standardise the models to make human review easier.
To be clear being able to save 1 line of human readable code at the cost of 1000 machine generated and verified lines is a win.

# CCF lean module specification

## Module ownership

Within a model's library directory, use this layout:

| Location               | Responsibility                                                                                                      |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `Model.lean`           | Assemble the executable model, including configuration and network composition.                                     |
| `Model/`               | Model-specific definitions and transitions. For disaster recovery, this includes `Model/Local.lean`.                |
| `../common/CCF/`       | Reusable transition systems, network composition, and execution definitions in the `CCF` namespace.                 |
| `Properties.lean`      | State safety theorems and witness lemmas directly for CCF-Raft; disaster recovery retains named `Prop` definitions. |
| `Properties/`          | Definitions needed to state and understand those claims, such as state and trace predicates.                        |
| `Proof.lean`           | For disaster recovery, establish the named property definitions using their checked implementations.                |
| `Proofs/`              | Supporting derivations, ghost state, strengthening invariants, and correspondence proofs.                           |
| `Tests/`               | Executable model checks and regression cases.                                                                       |
| `TraceValidation.lean` | Replay recorded implementation traces through the executable model.                                                 |
| `TraceValidation/`     | Parsing and ordering of those traces, for `TraceValidation.lean`.                                                   |

## Dependency direction

- Keep `common/CCF/`, `Model/`, and `Model.lean` independent of property and proof modules.
  Shared infrastructure must not depend on a particular protocol.
- CCF-Raft's `Properties.lean` imports the model and supporting proofs, and contains the full statements as theorems and witness lemmas.
  Keep each proof body to a one-line call into `Proofs/`, where the implementation belongs.
  Do not retain separate `Prop` definitions or a `Proof.lean` wrapper for those results.
  CCF-Raft's `Proofs/` must not import `Properties.lean`; this keeps the result entrypoint free of cycles.
- Disaster recovery's property definitions depend on the model, shared definitions, and other property helpers, but not `Proof.lean` or `Proofs/`.
  Its `Proofs/` may depend on property definitions, and its `Proof.lean` imports both statements and implementations.

For disaster recovery's split statement/proof layout, the proof entrypoint establishes the named property rather than repeating its statement.
For example:

```lean
theorem quorum_opener_unique : Properties.QuorumOpenerUnique :=
	Proofs.Model.quorum_opener_unique
```

Do not use axioms or unfinished theorems as placeholders for property statements.

## Statement definitions versus proof machinery

A definition belongs with properties when a reader needs it to understand the claim or its assumptions.
A definition used only to establish the claim belongs with proofs.

State historical properties over executions of the actual model.
Put reusable execution definitions in `common/CCF/` and protocol-specific trace predicates in `Properties/`.
Keep ghost histories, send-time snapshots, and proof-only invariants under `Proofs/`; do not expose their representation through public property helpers.

When using a ghost execution, prove that every relevant model execution admits the decoration.
Do not restrict the model to executions convenient for a proof.
Moving ghost definitions into `Properties/` merely to remove an import does not establish this separation.

## Review and validation

Review the model, property statements, their helpers, and the proof links in the result entrypoint (`Properties.lean` for CCF-Raft, `Proof.lean` for disaster recovery).
Keep the detailed proof implementations machine-checked and within the axiom allowlist.

Retain package-level import coverage and the whole-package kernel and axiom-dependency checks with `lake check`.
The proof entrypoint does not replace either check.
After moving modules, update the import root and run `lake exe check-imports` and the package's existing checks.
For disaster recovery, see the [validation commands](disaster-recovery/README.md#validation).

`DisasterRecovery/Tests/Architecture.lean` checks the property import graph during the build.
It rejects proof dependencies and imports that reverse the shared, model, and property layers.
