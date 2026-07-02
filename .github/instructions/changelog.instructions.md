---
applyTo:
  - "CHANGELOG.md"
---

# Code review – CHANGELOG entries

When reviewing changes to `CHANGELOG.md`, always verify that every new or modified entry includes a reference to the pull request that introduced the change, in the form `(#1234)` at the end of the entry (matching the existing convention).

Flag any added or modified bullet under an `Added`, `Changed`, `Fixed`, `Removed`, or similarly-named section that does not include such a `(#<number>)` reference, and ask the author to add the corresponding PR number. This applies to entries under both top-level version sections (e.g. `[Unreleased]`) and nested subsections (e.g. `### Developer API` → `#### C++` → `##### Added`).

Do not flag:

- Section headings, version headings, or release-highlights blockquotes.
- Pre-existing entries that the diff does not touch.
- Entries that already cite at least one PR number, even if they reference additional issues or commits as well.
