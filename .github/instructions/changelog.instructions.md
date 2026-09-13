---
applyTo: "CHANGELOG.md,python/pyproject.toml"
---

# CHANGELOG entries

Use [Keep a Changelog 1.0.0](https://keepachangelog.com/en/1.0.0/) format, with the CCF-specific rules below.

These instructions apply when writing or reviewing changelog entries and SDK release-version changes. Unrelated changes to `python/pyproject.toml` do not require a release bump.

## Selecting the release section

Before adding an entry, identify the target branch's release line and whether it is a stable maintenance line or a prerelease/development line. Use the branch context and published `ccf-<version>` releases/tags; do not select the repository-wide newest release across unrelated release lines, infer publication from `CHANGELOG.md` alone, or rely on an incomplete local tag list. Confirm ambiguous publication status against GitHub releases.

- Use concrete Semantic Versioning release sections, not `Unreleased`.
- If the first section is an unpublished next release for the target line, use it.
- On a stable maintenance line, if the first section is already published, create the next patch section above it using the latest published stable release on that line. Add the matching `https://github.com/microsoft/CCF/releases/tag/ccf-<version>` link definition.
- For prerelease/development lines, follow an explicit release target rather than inventing a patch, minor, major, or prerelease increment. If the target line, next version, or publication status cannot be established, ask for clarification before editing release metadata.
- Whenever a new release section is created, update `project.version` in `python/pyproject.toml` to the same version. The first version in `CHANGELOG.md` and `project.version` must always match.
- When reviewing release metadata, verify section selection and version synchronisation. Report unavailable publication evidence as a validation limitation, not a guessed release status.

## Pull request references

Each new or modified entry must reference the introducing PR using `(#1234)`. Preserve original PR references when correcting an existing entry; include the current PR when it introduces an additional change. Issue references are optional in changelog entries; closing references belong in the PR description.

- Before a PR number exists, omit the reference temporarily and report that it must be added once the PR exists, before merge. Never invent a number or add a fake numeric placeholder.
- When reviewing a PR, flag touched entries missing the relevant PR reference, including nested entries. Directly propose the correct PR number with a GitHub suggested change rather than asking the author to add it. A reference to an issue alone does not satisfy the PR-reference requirement.

Do not flag:

- Section headings, version headings, or release-highlights blockquotes.
- Pre-existing entries that the diff does not touch.
- Entries that already cite the relevant introducing PR, whether or not they also reference issues or commits.
