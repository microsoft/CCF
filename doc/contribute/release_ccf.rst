Release or patch a CCF release
==============================

Patch an LTS release
--------------------

CCF releases are cut from branches named ``release/N.x`` where ``N`` is the major release number.
Patching a release, ie. issuing a ``N.0.x+1`` version when the current version is ``N.0.x`` involves the following steps:

#. Apply commits to ``release/N.0.x``, and/or cherry-pick them from ``main``
#. Tag head of ``release/N.x`` as ``ccf-N.0.x+1``

Create an LTS release
---------------------

#. Create a ``release/N.x`` branch from the head of ``main``
#. Tag head of ``release/N.x`` as ``ccf-N.0.0-rc0``
#. If necessary, apply patch process outline above with ``ccf-N.0.0-rc1`` etc
#. When ready, tag the head of ``release/N.x`` as ``ccf-N.0.0`` 

Create a dev release
---------------------

#. Tag the head of ``main`` as ``ccf-N+1.0.0-devX+1``, where ``N`` is the latest LTS, and ``X`` the latest dev release.

Labelling LTS PRs
-----------------

To keep track of which changes should be merged to LTS branches and then confirm them before cutting LTS releases, the following policy should be used:

#. A PR targetting ``main`` which contains changes that should also reach the N.x LTS should be labelled in GitHub with ``N.x-todo`` 
#. Where possible ``N.x-todo`` PRs should contain the minimal set of changes with no dependencies on earlier PRs, so they can be more easily cherry-picked
#. A PR targetting an LTS branch (``release/N.x``) should be labelled in Github with ``N.x-backport``, so it can be easily found with a filter
#. A PR targetting an LTS branch which is constructed primarily of a cherry-pick from ``main`` should be named consistently as ``Cherry-pick #<PR_ID> to N.x LTS``, so it can be easily correlated with the corresponding ``N.x-todo`` PR. If an LTS PR contains commits from multiple PRs to ``main``, each should be mentioned in the PR title, eg ``Port <foo> to N.x LTS (#PR1_ID, #PR2_ID, ...)```

Before creating an LTS release, the releaser should do a scan of PRs and ensure that there are none with ``N.x-todo`` label. If any exist, they should be merged to the LTS branch before releasing, and those candidate labels removed.
