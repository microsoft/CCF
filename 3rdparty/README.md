3rdparty dependencies included here are divided into 3 categories.

#### Test
These dependencies are only used for building unit tests or sample apps for CCF, and are not distributed.

#### Internal
These may be built into the distributed artifacts, but are not distributed in source form.

#### Exported
These are used by the distributed artifacts and their source is exported so they can be re-used by applications consuming those artifacts.

#### Glaze

`exported/glaze/` contains a JSON-only subset of [Glaze v9.0.0](https://github.com/stephenberry/glaze/tree/d78832c82289c61a9315bfbc35332cec9f4e93ca), commit `d78832c82289c61a9315bfbc35332cec9f4e93ca`.
Retained headers preserve their upstream paths and contents.
The MIT license, optional embedding exception, and embedded components' copyright notices are retained in `THIRD_PARTY_NOTICES.txt`.
The development package installs those notices in its documentation directory alongside the exported source headers.
The existing exported include and installation rules expose these headers without downloading dependencies during configuration.
Only the JSON read/write/schema entry points and their dependencies are supplied, not the general `<glaze/glaze.hpp>` umbrella or unrelated formats.

To regenerate from an upstream checkout at the manifest's pinned revision:

```sh
python3 scripts/vendor-glaze.py --source /path/to/glaze/include --output 3rdparty/exported/glaze
python3 scripts/vendor-glaze.py --source /path/to/glaze/include --output 3rdparty/exported/glaze --check
```

The script follows internal includes across all conditional branches, including relative includes, and fails on unsupported computed include directives.
Check mode does not write files and reports missing, changed, or surplus headers.
The `ENTRY_POINTS` list in the script records the headers actually used by CCF; update that list when adding format support or changing entry points.
After changing the upstream revision or entry points, regenerate the subset, verify provenance, and build/test CCF and an installed SDK consumer using only the trimmed tree.
Run the script's regression tests with `python3 -m unittest discover -s scripts/tests -p vendor_glaze_test.py`.

Glaze requires C++23 and an available `std::expected` implementation.
Clang 18 with libstdc++ 13 needs a compatibility workaround because the standard library gates its existing `<expected>` declarations on a newer concepts feature macro.
This dependency addition does not change CCF's compiler selection or patch the upstream headers.

Verify the vendored tree with `scripts/verify-vendored-dependency.py cgmanifest.json glaze`.

### Verification

Git dependencies are recorded in `cgmanifest.json`.
After changing a vendored dependency or its manifest entry, verify all dependencies with:

```sh
scripts/verify-vendored-dependency.py cgmanifest.json
```

Pass a repository name as a second argument to check only that dependency.
The Vendored Dependency Verification workflow runs automatically when vendored sources, the manifest, or the verifier change.
