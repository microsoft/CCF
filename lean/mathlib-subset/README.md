# Mathlib subset

The `mathlib_subset` Lake package vendors the few [Mathlib](https://github.com/leanprover-community/mathlib4) and [Batteries](https://github.com/leanprover-community/batteries) declarations that the CCF Lean packages use, so that they do not depend on Mathlib itself.
Each file has the same path and module name as the upstream module it is taken from, but keeps only the definitions, instances, notation and theorems that CCF needs.
Theorems keep their upstream statements, but the subset may prove them differently, for example where an upstream proof needs modules that are not vendored or uses deprecated lemmas.
Lemmas that CCF needs but that are not upstream belong in the CCF packages, not here.

## Upstream version

The subset is taken from Mathlib `v4.35.0` and the Batteries revision that Mathlib pins.
The checker's [`lakefile.toml`](../mathlib-subset-check/lakefile.toml) and [`lake-manifest.json`](../mathlib-subset-check/lake-manifest.json) record these revisions.
The subset and the checker link their `lean-toolchain` files to the [Lean toolchain](../lean-toolchain) of the other packages.
Mathlib and Batteries are released under the Apache 2.0 license, a copy of which is in [`LICENSE`](LICENSE), and each file keeps its upstream copyright header.
The files also keep upstream formatting, so `scripts/lean-format-checks.sh` skips them.

## Checking against upstream

The [`mathlib-subset-check`](../mathlib-subset-check/Main.lean) package imports the subset and upstream Mathlib under the same module names, and requires the subset's declarations to match their upstream counterparts: the same module, kind and universe parameters, the same type, the same value for definitions after erasing proofs, and the same reducibility, instance priority and structure shape.
It also rejects axioms other than `propext`, `Classical.choice` and `Quot.sound`.
`Main.lean` documents the exact rules, including the internal declarations and metaprogram values that it does not compare.

Run the check from the repository root:

```sh
(cd lean/mathlib-subset && lake build --wfail)
cd lean/mathlib-subset-check
lake exe cache get
lake exe mathlib-subset-check ../mathlib-subset
```

`lake exe cache get` downloads upstream Mathlib and its prebuilt cache, about 7 GB on disk.
The CCF packages build the subset themselves, so this is only needed when changing the subset, the checker or the Lean toolchain.
The [Lean Mathlib Subset workflow](../../.github/workflows/lean-mathlib-subset.yml) runs the same commands on pull requests that change the subset, the checker, the Lean toolchain or the workflow.

## Adding a declaration

1. Find the module that declares it upstream, at the pinned version.
   After `lake exe cache get`, the pinned sources are in `lean/mathlib-subset-check/.lake/packages/`.
2. Copy the declaration into the file with the same path here, creating the file with the upstream copyright header if needed.
3. Copy any declarations it uses that are not yet vendored, in the same way.
4. Give each file the upstream imports that are vendored.
   Instances found during elaboration depend on what is imported, so other imports can produce a different term that the checker rejects.
5. Build the subset and run the checker.

Mathlib releases target a single Lean release, so `lean/lean-toolchain` and the checker's Mathlib version change together.
To move to a new version, update `lean/lean-toolchain`, the `rev` in the checker's `lakefile.toml` and the version stated above, run `lake update` in `lean/mathlib-subset-check`, and copy the new upstream version of each declaration that the checker reports.
