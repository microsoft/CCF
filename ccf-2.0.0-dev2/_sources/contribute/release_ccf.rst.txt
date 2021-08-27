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