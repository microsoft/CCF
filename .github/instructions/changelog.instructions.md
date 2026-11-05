---
description: "Use when writing change descriptions, dependency updates, or preparing changelog/SDK releases."
applyTo: ".changes/*.md,CHANGELOG.md,python/pyproject.toml"
---

# Change descriptions

- Add one `.changes/<unique-name>.<category>.md` change description per PR with notable user-facing impact; internal-only changes need none.
- Categories are `added`, `changed`, `deprecated`, `removed`, `fixed`, `security`, and `dependencies`.
- Use one or two concise sentences of plain Markdown, naming affected APIs or dependency versions and linking to documentation relative to the repository root, without a leading bullet, heading, release version, or PR number.
- Leave `CHANGELOG.md` and the SDK version unchanged outside release preparation; follow the [release procedure](../../doc/contribute/release_ccf.rst) for releases.
