Release or patch a CCF release
==============================

Prepare release notes
---------------------

Normal PRs add change descriptions in ``.changes/`` instead of editing the changelog.
In a release-preparation PR, install ``scripts/requirements.txt``, choose the version, and preview the collected notes:

.. code-block:: bash

    python3 scripts/gather_changelog.py --version 7.0.25 --base-branch main
    python3 scripts/gather_changelog.py --version 7.0.25 --base-branch main --write

The default is to collect all change descriptions; pass explicit ``.changes/*.md`` paths to select a subset.
Preview does not change files; ``--write`` prepends the release section and deletes only the selected change descriptions.
Other change descriptions may remain for future releases.
The collector uses PyGithub to find each change description's introducing commit and associated merged PR on ``--base-branch``.
Missing or ambiguous references stop collection before files are changed; use ``--pr receipt-validation.fixed.md=1234`` to override that change description's PR lookup at release time.

Manually update ``project.version`` in ``python/pyproject.toml`` to match the first changelog version, converting prereleases such as ``8.0.0-dev10`` to ``8.0.0.dev10``.
Review and commit the changelog, SDK version change, and selected change-description deletions together, then validate:

.. code-block:: bash

    scripts/release-notes-checks.sh

After merging the release PR, tag the reviewed release commit using the existing release process.
The collector does not assign versions, edit SDK metadata, commit, tag, or publish.

Patch an LTS release
--------------------

CCF releases are cut from branches named ``release/N.x`` where ``N`` is the major release number.
Patching a release, ie. issuing a ``N.0.x+1`` version when the current version is ``N.0.x`` involves the following steps:

#. Apply commits to ``release/N.x``, and/or cherry-pick them from ``main``
#. Prepare and merge a release-notes PR as described above.
#. Tag the reviewed release commit as ``ccf-N.0.x+1``.

Create an LTS release
---------------------

#. Create a ``release/N.x`` branch from the head of ``main``
#. Prepare and merge a release-notes PR for ``N.0.0-rc0``.
#. Tag the reviewed release commit as ``ccf-N.0.0-rc0``.
#. If necessary, apply patch process outline above with ``ccf-N.0.0-rc1`` etc
#. When ready, prepare the release-notes PR for ``N.0.0`` and tag its reviewed commit as ``ccf-N.0.0``.

Create a dev release
---------------------

#. Prepare and merge a release-notes PR on ``main`` for ``N+1.0.0-devX+1``, where ``N`` is the latest LTS, and ``X`` the latest dev release.
#. Tag the reviewed release commit as ``ccf-N+1.0.0-devX+1``.

Labelling LTS PRs
-----------------

To keep track of which changes should be merged to LTS branches and then confirm them before cutting LTS releases, the following policy should be used:

#. A PR targeting ``main`` which contains changes that should also reach the N.x LTS should be labelled in GitHub with ``N.x-todo``
#. Where possible ``N.x-todo`` PRs should contain the minimal set of changes with no dependencies on earlier PRs, so they can be more easily cherry-picked
#. A PR targeting an LTS branch (``release/N.x``) should be labelled in GitHub with ``N.x-backport``, so it can be easily found with a filter
#. A PR targeting an LTS branch which is constructed primarily of a cherry-pick from ``main`` should be named consistently as ``Cherry-pick #<PR_ID> to N.x LTS``, so it can be easily correlated with the corresponding ``N.x-todo`` PR. If an LTS PR contains commits from multiple PRs to ``main``, each should be mentioned in the PR title, eg ``Port <foo> to N.x LTS (#PR1_ID, #PR2_ID, ...)```

Before creating an LTS release, the releaser should do a scan of PRs and ensure that there are none with ``N.x-todo`` label. If any exist, they should be merged to the LTS branch before releasing, and those candidate labels removed.
