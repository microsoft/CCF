# CCF Lean objectives

We use agents to generate models and proofs that those models are correct.
We use trace validation to align the models with the implementation.
Formally, if B(X) is the set of behaviours permitted by X, then B(implementation) \subseteq B(Model) \subseteq B(Properties).

The aim of this spec is to standardise the models to make human review easier.
To be clear being able to save 1 line of human readable code at the cost of 1000 machine generated and verified lines is a win.

# CCF lean module specification

## Module ownership

Within a model's library directory, use this layout:

| Location               | Responsibility                                                                                       |
| ---------------------- | ---------------------------------------------------------------------------------------------------- |
| `Model.lean`           | Assemble the executable model, including configuration and network composition.                      |
| `Model/`               | Model-specific definitions and transitions. For disaster recovery, this includes `Model/Local.lean`. |
| `../common/CCF/`       | Reusable transition systems, network composition, and execution definitions in the `CCF` namespace.  |
| `Theorems.lean`        | State proved claims and witnesses explicitly, linked to their checked implementations.               |
| `Conjectures.lean`     | State unproved claims and witnesses as `def ... : Prop`, without implying they are established.      |
| `Properties/`          | Definitions needed to state and understand those claims, such as state and trace predicates.         |
| `Proofs/`              | Supporting derivations, ghost state, strengthening invariants, and correspondence proofs.            |
| `Tests/`               | Executable model checks and regression cases.                                                        |
| `TraceValidation.lean` | Replay recorded implementation traces through the executable model.                                  |
| `TraceValidation/`     | Parsing and ordering of those traces, for `TraceValidation.lean`.                                    |

## Dependency direction

- Keep `common/CCF/`, `Model/`, and `Model.lean` independent of statement helpers, conjectures, theorems, and proof modules.
  Shared infrastructure must not depend on a particular protocol.
- Statement helpers in `Properties/` and unproved claims in `Conjectures.lean` should depend on the model, shared definitions, and other statement helpers.
  They may not import `Theorems.lean` or `Proofs/`.
- Let `Proofs/` depend on model definitions, statement helpers, and other supporting proofs, but not `Theorems.lean`.
  `Theorems.lean` imports statement helpers and proof implementations.

Write the full proposition in each theorem declaration rather than defining a separate named property.
Keep its proof a short reference to an implementation in `Proofs/`.
For example:

```lean
theorem rejected_gossip_stutters :
    forall (config : Model.Config) (localStep : Properties.LocalStep),
    forall (source : Model.Local.Location) (txid : Model.Local.TxID),
      ((Model.protocol config).ValidStep localStep
        /\ localStep.action = .receiveGossip source txid .rejected)
      -> localStep.after = localStep.before
          /\ List.Mem (.rejected "quote-or-certificate") localStep.effects.notifications :=
  Proofs.Local.rejected_gossip_stutters
```

Keep the supporting proof's statement explicit too, avoiding an import cycle through `Theorems.lean`.
Place each witness theorem next to the claim whose premises it exercises.
Every theorem declaration requires a proof, so a separate property-to-theorem coverage check is unnecessary.
Unproved claims and witness statements belong in `Conjectures.lean` until their proofs exist; do not use axioms or unfinished theorems as placeholders.

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

Review the model, theorem statements and proof links in `Theorems.lean`, their statement helpers, and any unproved claims in `Conjectures.lean`.
Keep the detailed proof implementations machine-checked and within the axiom allowlist.

Retain the generated package-level import-all module and the whole-package kernel and axiom-dependency checks with `lake check`.
The proof entrypoint does not replace either check.
After moving modules, regenerate the import root and run the package's existing checks.
For disaster recovery, see the [validation commands](disaster-recovery/README.md#validation).

The model packages' `Tests/Architecture.lean` modules check the import graph during the build.
They reject proof and theorem dependencies from statement helpers and conjectures, and imports that reverse the shared, model, and statement-helper layers.
