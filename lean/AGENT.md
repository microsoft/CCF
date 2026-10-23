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
| `Properties.lean`      | State safety theorems and witness lemmas explicitly, linked to checked implementations.              |
| `Properties/`          | Definitions needed to state and understand those claims, such as state and trace predicates.         |
| `Proofs/`              | Supporting derivations, ghost state, strengthening invariants, and correspondence proofs.            |
| `Tests/`               | Executable model checks and regression cases.                                                        |
| `TraceValidation.lean` | Replay recorded implementation traces through the executable model.                                  |
| `TraceValidation/`     | Parsing and ordering of those traces, for `TraceValidation.lean`.                                    |

## Dependency direction

- Keep `common/CCF/`, `Model/`, and `Model.lean` independent of property helpers, theorem entrypoints, and proof modules.
  Shared infrastructure must not depend on a particular protocol.
- Property helpers in `Properties/` should depend on the model, shared definitions, and other property helpers.
  They may not import `Properties.lean` or `Proofs/`.
- Let `Proofs/` depend on model definitions, property helpers, and other supporting proofs, but not `Properties.lean`.
  `Properties.lean` publicly imports the types and helpers needed to understand its statements and privately imports proof implementations.

Write the full logical statement in each public safety theorem and existential witness lemma, rather than defining a separate named proposition.
Keep each proof body a one-line `by exact Proofs.<implementation>` reference, and place each witness lemma next to its corresponding safety theorem.
For example:

```lean
namespace DisasterRecovery.Properties

theorem rejected_gossip_stutters
    : forall (config : Model.Config) (localStep : Properties.LocalStep),
      forall (source : Model.Local.Location) (txid : Model.Local.TxID),
        ((Model.protocol config).ValidStep localStep
          /\ localStep.action = .receiveGossip source txid .rejected)
        -> localStep.after = localStep.before
            /\ List.Mem (.rejected "quote-or-certificate") localStep.effects.notifications := by
  exact Proofs.Local.rejected_gossip_stutters

end DisasterRecovery.Properties
```

Keep supporting proof statements explicit too, or use existing lower-level facts, so they do not depend on the final theorem entrypoint.
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

Review the model, full statements and proof links in `Properties.lean`, and the property helpers used by those statements.
Keep the detailed proof implementations machine-checked and within the axiom allowlist.

Retain the package-level import root, whole-package import coverage with `lake exe check-imports`, and kernel and axiom-dependency checks with `lake check`.
The proof entrypoint does not replace either check.
After moving modules, update the import root and run the package's existing checks.
For disaster recovery, see the [validation commands](disaster-recovery/README.md#validation).

Each model package's `Tests/Architecture.lean` checks dependency direction during the build.
It keeps common and model modules independent of properties and proofs, property helpers independent of proofs and theorem entrypoints, and proof implementations independent of the final theorem entrypoint.
