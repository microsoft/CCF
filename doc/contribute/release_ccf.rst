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
It includes all descriptions present at that tag, in category and filename order, without comparing previous tags or trying to infer which descriptions have already been published.
Edits to an existing description are included as they appear in the release commit.
The collector reads each description's adding commit from local Git history and uses the trailing ``(#1234)`` reference from its squash-merge subject.
Missing references stop collection; use ``--pr receipt-validation.fixed.md=1234`` to override that description's PR lookup when previewing locally.
No GitHub API access or credentials are required to generate the notes.
Relative inline Markdown links are expanded to the corresponding files at the release tag.
During the transition, the changelog section matching the target release version is included alongside fragments, preserving its existing PR references.
For example, ``7.0.24`` combines its changelog section with all change descriptions present at ``ccf-7.0.24``.

Generation does not modify ``CHANGELOG.md``, SDK metadata, or change descriptions.
Published descriptions must be removed manually before a subsequent release to avoid repeating their notes; automated cleanup is not yet implemented.
The historical changelog remains available and can still be validated or extracted with the script's existing changelog mode:

.. code-block:: bash

    scripts/release-notes-checks.sh

Historical changelog validation does not require its first version to match the current SDK version.
Tag the reviewed release commit using the existing release process.
The workflow generates a release-notes artifact, including on dry runs for a tagged commit, and uses it when creating the draft GitHub release.
The collector does not assign versions, commit, tag, or publish.

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
