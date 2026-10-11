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
| `Shared/`              | Reusable transition systems, network composition, and execution definitions.                         |
| `Properties.lean`      | Define the named claims as `def ... : Prop`.                                                         |
| `Properties/`          | Definitions needed to state and understand those claims, such as state and trace predicates.         |
| `Proof.lean`           | Export theorems establishing the named properties, linked to their checked implementations.          |
| `Proofs/`              | Supporting derivations, ghost state, strengthening invariants, and correspondence proofs.            |
| `Tests/`               | Executable model checks and regression cases.                                                        |
| `TraceValidation.lean` | Replay recorded implementation traces through the executable model.                                  |
| `TraceValidation/`     | Parsing and ordering of those traces, for `TraceValidation.lean`.                                    |

## Dependency direction

- Keep `Shared/`, `Model/`, and `Model.lean` independent of property and proof
  modules. Shared infrastructure must not depend on a particular protocol.
- Property definitions should depend on the model, shared definitions, and other
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

## Source and style checks

From the repository root, run `scripts/lean-lint-checks.sh`. This checks every
tracked or untracked, non-ignored `.lean` file under `lean/`, including nested
packages, files outside default build targets, and the lint tooling itself.
Dependencies and build outputs under `.lake/` are excluded by Git's ignore rules.
New packages do not need to be added to a directory allowlist.

The shared tooling package at `lean/` pins Mathlib and the Lean toolchain.
Keep package toolchains aligned with `lean/lean-toolchain`; a mismatch fails
the check rather than silently leaving a package unchecked.
Each source is checked with its nearest Lake package's module setup, after the
package's default targets are built, if it has any. Packages containing only
standalone scripts are checked too. Mathlib's linters are imported only for the
additional source-checking pass, which writes no compiled artifacts. In particular, the
standalone recovery replayer retains its dependency-free build.

The check enables Mathlib's complete `linter.mathlibStandardSet`, the upstream
1500-line file limit, all its current Lean text-based linters, and its module-name
checks. The header linter uses CCF's existing Apache license notice.
`lakefile.lean` is exempt only from the module-name checks because Lake fixes
that filename. Formatting remains a separate check.

The following upstream checks are intentionally not enabled:

- Mathlib-only checks for imports of `Mathlib.Init` and documentation of Mathlib's
  own `scripts/` directory. They assume Mathlib's repository layout and are
  explicitly excluded from its downstream standard set.
- Checks Mathlib itself leaves disabled as experimental, unstable, or advisory:
  for example, `haveLet`, `ppRoundTrip`, `minImports`, and `upstreamableDecls`.
  See the explanation in
  [the pinned Mathlib.Init](https://github.com/leanprover-community/mathlib4/blob/5ed2965256430c3649e86755f9576b54eca72435/Mathlib/Init.lean).
- The remaining legacy Python style checks: the pinned upstream
  `scripts/lint-style.py` fails with `NameError: nonterminal_simp_check is not defined`.
  This is an upstream implementation failure, not an exception for CCF source
  violations. Reconsider it when updating Mathlib.

Do not disable a standard check simply to accept existing source. Any necessary
exception must identify a concrete incompatibility and be documented here.
