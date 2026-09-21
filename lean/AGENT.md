# Lean module boundaries

Separate what the model does, what its properties mean, and how those properties
are proved. Use the following module boundaries.

## Module ownership

Within a model's library directory, use this layout:

| Location          | Responsibility                                                                                       |
| ----------------- | ---------------------------------------------------------------------------------------------------- |
| `Model.lean`      | Assemble the executable model, including configuration and network composition.                      |
| `Model/`          | Model-specific definitions and transitions. For disaster recovery, this includes `Model/Local.lean`. |
| `Shared/`         | Reusable transition systems, network composition, and execution definitions.                         |
| `Properties.lean` | Define the named claims as `def ... : Prop`.                                                         |
| `Properties/`     | Definitions needed to state and understand those claims, such as state and trace predicates.         |
| `Proof.lean`      | Export theorems establishing the named properties, linked to their checked implementations.          |
| `Proofs/`         | Supporting derivations, ghost state, strengthening invariants, and correspondence proofs.            |
| `Tests/`          | Executable model checks and regression cases.                                                        |

Use PascalCase for Lean module directories and filenames. Match declaration
namespaces to module paths. For example, disaster recovery's local model is
`DisasterRecovery/Model/Local.lean`, in `DisasterRecovery.Model.Local`.

## Dependency direction

- Keep `Shared/`, `Model/`, and `Model.lean` independent of property and proof
  modules. Shared infrastructure must not depend on a particular protocol.
- Let property definitions depend on the model, shared definitions, and other
  property helpers. Neither `Properties.lean` nor `Properties/` may import
  `Proof.lean` or `Proofs/`.
- Let `Proofs/` depend on model and property definitions, plus other supporting
  proofs. `Proof.lean` imports the property statements and their implementations.

The proof entrypoint should establish the named property rather than repeat its
statement. For example:

```lean
theorem quorum_opener_unique : Properties.QuorumOpenerUnique :=
	Proofs.Model.quorum_opener_unique
```

Do not use axioms or unfinished theorems as placeholders for property statements.

## Statement definitions versus proof machinery

A definition belongs with properties when a reader needs it to understand the
claim or its assumptions. A definition used only to establish the claim belongs
with proofs.

State historical properties over executions of the actual model. Put reusable
execution definitions in `Shared/` and protocol-specific trace predicates in
`Properties/`. Keep ghost histories, send-time snapshots, and proof-only
invariants under `Proofs/`; do not expose their representation through public
property helpers.

When using a ghost execution, prove that every relevant model execution admits
the decoration. Do not restrict the model to executions convenient for a proof.
Moving ghost definitions into `Properties/` merely to remove an import does not
establish this separation.

## Review and validation

Review the model, property definitions, their helpers, and the theorem links in
`Proof.lean`. Keep the detailed proof implementations machine-checked and within
the axiom allowlist.

Retain the generated package-level import-all module and the whole-package axiom
audit. The proof entrypoint does not replace either check. After moving modules,
regenerate the import root and run the package's existing checks. For disaster
recovery, see the [validation commands](disaster-recovery/README.md#validation).

`DisasterRecovery/Tests/Architecture.lean` checks the property import graph during
the build. It rejects proof dependencies and imports that reverse the shared,
model, and property layers.
