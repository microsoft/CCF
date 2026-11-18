# Vendored EverParse CBOR

Rust sources of the `cborrs` (deterministic) and `cborrs-nondet`
(non-deterministic) crates from
[project-everest/everparse](https://github.com/project-everest/everparse),
extracted from the formally verified EverCBOR implementation.

They are vendored because upstream does not publish these crates to crates.io,
and a crate with git dependencies cannot be published there.

- `REVISION` records the upstream commit.
- Everything under `src/` and `LICENSE` is a byte-for-byte copy at its upstream
  path. Do not edit these files; they are licensed under Apache-2.0.
- `../../src/lib.rs` mounts the sources as private modules at the crate root
  and supplies the three-line `lowstar` shim from the upstream `lib.rs` files.

To update, or to check that the copy still matches upstream:

```sh
scripts/vendor-everparse.sh [rev]   # rev defaults to REVISION
git status --short cbor/vendor      # empty when unchanged
```
