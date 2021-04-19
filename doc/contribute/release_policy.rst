CCF release and support policy
==============================

API stability and versioning
-----------------------------

REST endpoints exposed by CCF itself fall into three categories:

User-facing API
~~~~~~~~~~~~~~~

As defined under :ref:`use_apps/rpc_api:Built-ins`.

We expect these endpoints to be quite stable, but it is difficult for CCF itself to version them because its own versioning scheme may not be in-sync with a given application: release dates and numbers will differ.
We recommend instead that applications programmatically disables these endpoints as exposed by CCF now, and replace them with their own.
CCF exposes its implementation of the endpoints as a public, versioned C++ API and application code can dispatch to the chosen implementation for each of its own versions.  

For example:

- Application version 1.2 -> CCF::commit_v1
- Application version 1.3 -> CCF::commit_v1
- Application version 1.4 -> CCF::commit_v1

New CCF release adds CCF::commit_v2

- Application version 1.2 -> CCF::commit_v1
- Application version 1.3 -> CCF::commit_v1
- Application version 1.4 -> CCF::commit_v1
- **Application version 1.5 -> CCF::commit_v2**

We intend to use ``_v${INCREMENTING_INTEGER}`` as a symbol suffix, starting at 1. It’s simple, short and unambiguous. Symbol versions are connected with CCF releases by release notes “eg. CCF release X.Y.Z introduces call_v2”.

Operator-facing API
~~~~~~~~~~~~~~~~~~~

As defined under :ref:`opeartions/operator_rpc_api`.

This is the API used to monitor the network topology, memory usage, endpoint metrics etc. We intend to keep this API compatible without explicit versioning, by making sure that all changes are strict additions (ie. new fields, new arguments with default values that behave identically to the old call).
Fields/input arguments are never be modified/deleted unless exceptionally and explicitly notified in advance to users.

Member-facing API
~~~~~~~~~~~~~~~~~

As defined under :ref:`governance/member_rpc_api`.

Same as operator-facing API.

Support policy
--------------

In addition to the latest release, CCF will provide security patches and bugfixes on two long term support releases at any given time. These releases are guaranteed to be API-stable, but not ABI-stable.
Applications will need to rebuild to pick up updates, but will not need to make a code change.

A long term support release (LTS) will be supported for 1 year starting from its release date. That means that when a new LTS comes out, users effectively have a 6 months window to upgrade to the latest LTS.

REST API guarantees spelled out in the first section apply across releases, but new features, for example revisions of the User-facing C++ API or additions to the node API can only be introduced in a new release, never back-ported to an existing LTS.

.. image:: /img/ccf_release.png
    :alt: Release