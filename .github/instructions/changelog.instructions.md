---
applyTo:
  - "CHANGELOG.md"
---

# CHANGELOG entries

These instructions apply both when writing and when reviewing changes to `CHANGELOG.md`.

## Selecting the release section

Before adding an entry, determine the latest published CCF release from the git `ccf-<version>` tags or github.com/microsoft/CCF releases. Do not infer release status from the contents of `CHANGELOG.md` alone.

- Every entry must be placed under a concrete Semantic Versioning release section.
- If the first release section in `CHANGELOG.md` is newer than the latest published release, treat it as the next release and add the entry to the appropriate existing subsection.
- If the first release section has already been published, create a new section above it by incrementing the patch component of the latest published release. Add the matching link definition using the existing `https://github.com/microsoft/CCF/releases/tag/ccf-<version>` convention.
- Whenever a new release section is created, update `project.version` in `python/pyproject.toml` to the same version. The first version in `CHANGELOG.md` and `project.version` must always match.
- When reviewing a changelog addition, verify the release status, section selection, and version synchronisation above.

## Pull request references

Every new or modified entry must include a reference to the pull request that introduced the change and to the relevant issues(s) that the PR closes, in the form `(#1234)` at the end of the entry, matching the existing convention.

When reviewing, flag any added or modified bullet under an `Added`, `Changed`, `Fixed`, `Removed`, or similarly named section that does not include such a `(#<number>)` reference, and ask the author to add the corresponding PR number. This applies to entries directly under top-level version sections and in nested subsections such as `Developer API` / `C++` / `Added`.

Do not flag:

- Section headings, version headings, or release-highlights blockquotes.
- Pre-existing entries that the diff does not touch.
- Entries that already cite at least one PR number, even if they reference additional issues or commits as well.
