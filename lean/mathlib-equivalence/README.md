# Mathlib equivalence

This package proves that the local replacements for Mathlib definitions are equivalent to the Mathlib definitions they replaced.
It is the only Lean package that depends on Mathlib, so the common and specification packages, and their CI jobs, do not need it.
The [Lean Mathlib equivalence workflow](../../.github/workflows/lean-mathlib-equivalence.yml) checks it only when the replacement definitions or this package change.

| Module                        | CCF definition                  | Mathlib definition            | Results                                                                                                                                                                                                                                                   |
| ----------------------------- | ------------------------------- | ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MathlibEquivalence.Seq`      | `CCF.Seq`                       | `Stream'.Seq`                 | `equiv`, an equivalence of types that preserves `get?`, `nil`, `cons`, `map`, `ofList`, `ofStream` and membership                                                                                                                                         |
| `MathlibEquivalence.Finset`   | `CCF.Finset`                    | `Finset`, for a `LinearOrder` | `equiv`, an equivalence of types that preserves membership, the empty set, singletons, `insert`, `filter`, `erase`, union, intersection, difference, `ofList` (`List.toFinset`), subset, `Nonempty`, `Disjoint`, `card`, `sort` and `min?` (`Finset.min`) |
| `MathlibEquivalence.Function` | `CCF.Function.update`           | `Function.update`             | The two are equal                                                                                                                                                                                                                                         |
| `MathlibEquivalence.Rank`     | `rankBelow` and `findSuccessor` | `toLex`                       | `rankBelow` is `toLex` comparison, and `findSuccessor` equals its previous `toLex` definition                                                                                                                                                             |

The equivalences map each CCF operation to the corresponding Mathlib operation, so properties proved about the Mathlib definitions hold for the CCF ones.
The lemmas about the replacements in `CCF.Proofs.Finset` are proved independently, with the same names as their Mathlib counterparts.

## Checking

Fetch Mathlib's build cache (about 5 GB) and run the kernel and axiom check:

```bash
cd lean/mathlib-equivalence
lake exe cache get
lake check --inadvisably-no-sandbox
```

Check formatting from the repository root with `./scripts/lean-format-checks.sh mathlib-equivalence`.
