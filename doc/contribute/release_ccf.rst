Release or patch a CCF release
==============================

Prepare release notes
---------------------

Normal PRs add change descriptions in ``.changes/`` instead of editing the changelog.
The release workflow collects these descriptions directly into the GitHub release notes, without a release-notes PR or an intermediary changelog update.
To preview the notes locally, fetch the release tags and run the following command for a tagged release commit:

.. code-block:: bash

    python3 scripts/extract-release-notes.py --from-changes --target-version 7.0.25

The collector reads the files from the target tag, not from the working tree.
It selects descriptions whose adding commits belong to ``previous_tag..release_tag``, in category and filename order.
By default, the predecessor is the nearest ancestor ``ccf-*`` tag found by ``git describe`` starting at the release commit's parent.
Dev, RC, and stable tags all count: successive dev and RC releases are incremental, and the first stable release normally includes only changes since the last RC.
Use ``--previous-tag ccf-7.0.23`` to choose a different ancestor explicitly, for example to include the full RC cycle in stable notes.
The same range is used for ``--describe-path-changes``.
Fetch complete local history and release tags before collecting; the first release without an ancestor tag requires an explicit starting commit via ``--previous-tag``.
Range boundaries follow the current local tags, so moving a tag can change selection.
Edits to an existing description are included as they appear in the release commit.
Retained published descriptions are not repeated, and edits after release do not assign an old description to a new release.
Write a new, uniquely named fragment for a subsequent change; do not rename or reuse a published fragment's filename.
The collector reads each description's adding commit from local Git history and uses the trailing ``(#1234)`` reference from its squash-merge subject.
Missing references stop collection; use ``--pr receipt-validation.fixed.md=1234`` to override that description's PR lookup when previewing locally.
No GitHub API access or credentials are required to generate the notes.
Relative inline Markdown links are expanded to the corresponding files at the release tag.
During the transition, the changelog section matching the target release version is included alongside fragments, preserving its existing PR references.
For example, ``7.0.24`` combines its changelog section with descriptions added in ``ccf-7.0.23..ccf-7.0.24``.

Generation does not modify ``CHANGELOG.md``, SDK metadata, or change descriptions.
Cleanup is optional and is not required between releases.
GitHub Releases are authoritative; ``CHANGELOG.md`` is a searchable archive which may lag multiple releases.
The archive can still be validated or extracted with the script's existing changelog mode:

.. code-block:: bash

    scripts/release-notes-checks.sh

Historical changelog validation does not require its first version to match the current SDK version.

Before tagging any release, manually update ``project.version`` in ``python/pyproject.toml`` to match the intended release version and commit the bump.
This is the only release-version field in source that requires a manual bump; native and npm package versions are derived from the release tag.
Use Python version spelling for prereleases, for example ``8.0.0.dev10`` for ``ccf-8.0.0-dev10`` and ``8.0.0rc0`` for ``ccf-8.0.0-rc0``.
Tag the reviewed commit containing the version bump using the existing release process.
The OneBranch PyPI publisher checks the tag against SDK metadata before building the wheel, including prerelease normalization.
GitHub release-note generation does not perform this check, so a forgotten bump can fail the later PyPI build after the GitHub release has already been published.

The workflow generates a release-notes artifact, including on dry runs for a tagged commit, and uses it when creating the draft GitHub release.
The collector does not assign versions, commit, tag, or publish.

Consolidate released descriptions (optional)
--------------------------------------------

On the branch containing the releases, with clean consolidation inputs, supply explicit ranges oldest first:

.. code-block:: bash

    python3 scripts/consolidate-release-notes.py ccf-7.0.23..ccf-7.0.24 ccf-7.0.24..ccf-7.0.25

Use the same boundaries and any PR overrides used when generating the release notes.
``--pr FILENAME=NUMBER`` is supported for a single range.
The script uses the collector's selection and formatting, reading historical descriptions and any matching changelog section at each release tag, without fetching GitHub release bodies.
Unlike GitHub release notes, the archive retains relative Markdown links to match the existing changelog style.
It creates or replaces one archive section per version, preserving mixed-source transition notes without duplicating sections.
Rerunning committed consolidation with the same ranges is safe.
It then deletes only selected fragments whose working-tree contents still exactly match their released contents; unreleased fragments remain untouched.
All ranges and cleanup candidates are checked before writing.
If a selected fragment has post-release edits, consolidation stops without modifying files.
Preserve those edits in a new fragment and restore the old fragment's released contents before retrying.
Review and commit the archive update and deletions together.
No consolidation PR is required between releases.

Patch an LTS release
--------------------

CCF releases are cut from branches named ``release/N.x`` where ``N`` is the major release number.
Patching a release, ie. issuing a ``N.0.x+1`` version when the current version is ``N.0.x`` involves the following steps:

#. Apply commits to ``release/N.x``, and/or cherry-pick them from ``main``
#. Tag the reviewed release commit as ``ccf-N.0.x+1``.

Create an LTS release
---------------------

#. Create a ``release/N.x`` branch from the head of ``main``
#. Tag the reviewed release commit as ``ccf-N.0.0-rc0``.
#. If necessary, apply patch process outline above with ``ccf-N.0.0-rc1`` etc
#. When ready, tag the reviewed release commit as ``ccf-N.0.0``.

Create a dev release
---------------------

#. Review the changes on ``main`` for ``N+1.0.0-devX+1``, where ``N`` is the latest LTS, and ``X`` the latest dev release.
#. Tag the reviewed release commit as ``ccf-N+1.0.0-devX+1``.

Labelling LTS PRs
-----------------

To keep track of which changes should be merged to LTS branches and then confirm them before cutting LTS releases, the following policy should be used:

#. A PR targeting ``main`` which contains changes that should also reach the N.x LTS should be labelled in GitHub with ``N.x-todo``
#. Where possible ``N.x-todo`` PRs should contain the minimal set of changes with no dependencies on earlier PRs, so they can be more easily cherry-picked
#. A PR targeting an LTS branch (``release/N.x``) should be labelled in GitHub with ``N.x-backport``, so it can be easily found with a filter
#. A PR targeting an LTS branch which is constructed primarily of a cherry-pick from ``main`` should be named consistently as ``Cherry-pick #<PR_ID> to N.x LTS``, so it can be easily correlated with the corresponding ``N.x-todo`` PR. If an LTS PR contains commits from multiple PRs to ``main``, each should be mentioned in the PR title, eg ``Port <foo> to N.x LTS (#PR1_ID, #PR2_ID, ...)```

Before creating an LTS release, the releaser should do a scan of PRs and ensure that there are none with ``N.x-todo`` label. If any exist, they should be merged to the LTS branch before releasing, and those candidate labels removed.
