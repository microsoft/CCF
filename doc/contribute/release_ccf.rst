Release or patch a CCF release
==============================

Patch an LTS release
--------------------

CCF releases are cut from branches named ``release/N.x`` where ``N`` is the major release number.
Patching a release, ie. issuing a ``N.0.x+1`` version when the current version is ``N.0.x`` involves the following steps:

    1. Create a ``release/N.0.x+1`` branch from the head of ``release/N.x``
    2. Apply commits to ``release/N.0.x+1``, and/or cherry-pick them from ``main``
    3. Open a PR from ``release/N.0.x+1`` to ``release/N.x``
    4. Merge PR, subject to approval and automated checks
    5. Tag head of ``release/N.x`` as ``ccf-N.0.x+1``

Create an LTS release
---------------------

    1. Create a ``release/N.x`` branch from the head of ``main``
    2. Tag head of ``release/N.x`` as ``ccf-N.0.0-rc1``
    3. If necessary, apply patch process outline above with ``ccf-N.0.0-rc2`` etc
    4. When ready, tag the head of ``release/N.x`` as ``ccf-N.0.0`` 

Create a dev release
---------------------

    1. Tag the head of ``main`` as ``ccf-N+1.0.0-devX+1``, where ``N`` is the latest LTS, and ``X`` the latest dev release.

Labelling LTS PRs
-----------------

To keep track of which changes should be merged to LTS branches and then confirm them before cutting LTS releases, the following policy should be used:

    1. PRs targetting ``main`` which contain changes that should also reach the LTS should be labelled in Github with ``lts-candidate``
    2. Where possible ``lts-candidate`` PRs should contain the minimal set of changes with no dependencies on earlier PRs, so they can be more easily cherry-picked
    3. PRs targetting an LTS branch (``release/N.x``) should be given labelled in Github with ``lts``, so they can be easily found
    4. PRs targetting an LTS branch which are constructed primarily of a cherry-pick from ``main`` should be named consistently as ``Cherry-pick #<PR_ID> to N.x LTS``, so they can be easily correlated with the corresponding ``lts-candidate`` PRs
    5. Once a corresponding cherry-pick has been merged to the LTS branch, the ``lts-candidate`` can be removed from the original PR

Before creating an LTS release, the releaser should do a scan of PRs and ensure that there are none with ``lts-candidate`` label. If any exist, they should be merged to the LTS branch before releasing, and those candidate labels removed.
