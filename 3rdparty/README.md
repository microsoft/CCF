3rdparty dependencies included here are divided into 3 categories.

#### Test
These dependencies are only used for building unit tests or sample apps for CCF, and are not distributed.

#### Internal
These may be built into the distributed artifacts, but are not distributed in source form.

#### Exported
These are used by the distributed artifacts and their source is exported so they can be re-used by applications consuming those artifacts.

### Verification

Git dependencies are recorded in `cgmanifest.json`. After changing a vendored
dependency or its manifest entry, verify all dependencies with:

```sh
scripts/verify-vendored-dependency.py cgmanifest.json
```

Pass a repository name as a second argument to check only that dependency. The
Vendored Dependency Verification workflow runs automatically when vendored
sources, the manifest, or the verifier change.
