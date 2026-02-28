Code Upgrade
============

This page describes how operators/members can upgrade a live CCF service to a new version with minimal downtime.

Reasons for running the code upgrade procedure include:

- Upgrading nodes to a new version of a C++ application or JavaScript runtime (i.e. ``libjs_generic.enclave.so.signed``).
- Upgrading nodes to a new version of CCF.

.. tip::

    - Note that there is no need to run the code upgrade procedure detailed on this page if `only` the JavaScript/TypeScript application needs updating (see :ref:`JavaScript/TypeScript bundle deployment procedure <build_apps/js_app_bundle:Deployment>`).
    - If more than a majority of nodes have failed, the disaster recovery procedure should be run by operators instead (see :doc:`/operations/recovery`).

.. note:: CCF guarantees specific live compatibility across different LTS versions. See :ref:`build_apps/release_policy:Operations compatibility` for more details.

Procedure
---------

0. Let's assume that the to-be-upgraded service is made of 3 nodes (tolerates up to one fault, i.e. ``f = 1``), with ``Node 1`` as the primary node (the code upgrade procedure can be run from any number of nodes):

.. mermaid::

    graph LR;
        classDef Primary stroke-width:4px

        subgraph Service
            Node0((Node 0))
            Node1((Node 1))
            class Node1 Primary
            Node2((Node 2))
        end

1. First, operators/members should register the new code version corresponding to the new enclave measurement using platform specific proposal actions (see :ref:`governance/common_member_operations:Updating Code Version`).


2. The set of new nodes running the enclave registered in the previous step should be added to the service (see :ref:`operations/start_network:Adding a New Node to the Network`) and trusted by members (see :ref:`governance/common_member_operations:Trusting a New Node`). Typically, the same number of nodes than were originally present should be added to the service. In this example, the service is now made of 6 nodes (``f = 2``).

.. mermaid::

    graph TB;
        classDef NewNode fill:turquoise
        classDef Primary stroke-width:4px

        subgraph Service
            subgraph Old Nodes
                Node0((Node 0))
                Node1((Node 1))
                class Node1 Primary
                Node2((Node 2))
            end

            subgraph New Nodes
                Node3((Node 3))
                Node4((Node 4))
                Node5((Node 5))
                class Node3 NewNode
                class Node4 NewNode
                class Node5 NewNode
            end
        end


3. The original nodes (``Node 0``, ``Node 1`` and ``Node 2``) can then safely be retired.

- ``Node 0`` is retired, 5 nodes remaining, ``f = 2``:

.. mermaid::

    graph TB;
        classDef NewNode fill:Turquoise
        classDef RetiredNode fill:LightGray
        classDef Primary stroke-width:4px

        Node0((Node 0))
        class Node0 RetiredNode

        subgraph Service
            subgraph Old Nodes
                Node1((Node 1))
                class Node1 Primary
                Node2((Node 2))
            end

            subgraph New Nodes
                Node3((Node 3))
                Node4((Node 4))
                Node5((Node 5))
                class Node3 NewNode
                class Node4 NewNode
                class Node5 NewNode
            end
        end

- ``Node 1`` (primary) is retired, 4 nodes remaining, ``f = 1``. ``Node 4`` becomes primary after election phase (during which service cannot temporarily process requests that mutate the state of the key-value store):

.. mermaid::

    graph TB;
        classDef NewNode fill:Turquoise
        classDef RetiredNode fill:LightGray
        classDef Primary stroke-width:4px

        Node0((Node 0))
        Node1((Node 1))
        class Node0 RetiredNode
        class Node1 RetiredNode

        subgraph Service
            subgraph Old Nodes
                Node2((Node 2))
            end

            subgraph New Nodes
                Node3((Node 3))
                Node4((Node 4))
                class Node4 Primary
                Node5((Node 5))
                class Node3 NewNode
                class Node4 NewNode
                class Node5 NewNode
            end
        end

.. note:: It is possible for another old node (e.g. ``Node 2``) to become primary when the old primary node is retired. However, eventually, the primary-ship of the service will be transferred to one of the new nodes (e.g. ``Node 4``):

- ``Node 2`` is retired, 3 nodes remaining, ``f = 1``:

.. mermaid::

    graph TB;
        classDef NewNode fill:Turquoise
        classDef RetiredNode fill:LightGray
        classDef Primary stroke-width:4px

        Node0((Node 0))
        Node1((Node 1))
        Node2((Node 2))
        class Node0 RetiredNode
        class Node1 RetiredNode
        class Node2 RetiredNode


        subgraph Service
            subgraph New Nodes
                Node3((Node 3))
                Node4((Node 4))
                class Node4 Primary
                Node5((Node 5))
                class Node3 NewNode
                class Node4 NewNode
                class Node5 NewNode
            end
        end

4. Once all old nodes ``0``, ``1`` and ``2`` have been retired, and they are listed under :http:GET:`/node/network/removable_nodes`, operators can safely stop them and delete them from the state (:http:DELETE:`/node/network/nodes/{node_id}`):

.. mermaid::

    graph LR;
        classDef NewNode fill:Turquoise
        classDef Primary stroke-width:4px

        subgraph Service
            Node3((Node 3))
            Node4((Node 4))
            class Node4 Primary
            Node5((Node 5))
            class Node3 NewNode
            class Node4 NewNode
            class Node5 NewNode
        end

5. If necessary, the constitution scripts and JavaScript/TypeScript application bundles should be updated via governance:

- Members should use the ``set_constitution`` proposal action to update the constitution scripts.
- See :ref:`bundle deployment procedure <build_apps/js_app_bundle:Deployment>` to update the JavaScript/TypeScript application.

6. Finally, once the code upgrade process has been successful, the old code version (i.e. the code version run by nodes 0, 1 and 2) can be removed using the ``remove_snp_host_data`` proposal action.

Notes
-----

- The :http:GET:`/node/version` endpoint can be used by operators to check which version of CCF a specific node is running.
- A code upgrade procedure provides very little service downtime compared to a disaster recovery. The service is only unavailable to process write transactions while the primary-ship changes (typically a few seconds) but can still process read-only transactions throughout the whole procedure. Note that this is true during any primary-ship change, and not just during the code upgrade procedure.

Code Update Policy
------------------

Instead of explicitly trusting host data values, members can set a **code update policy** — a JavaScript function that evaluates transparent statements presented by joining nodes. A transparent statement is a COSE_Sign1 envelope carrying a signed statement about the node's code, countersigned with a CCF receipt that proves the statement was registered on the ledger.

.. note::

    CCF currently only supports **self-issued** transparent statements: the service itself acts as the transparency service, issuing receipts over signed statements registered on its own ledger.

The policy receives an array of transparent statements and must return ``true`` to accept or a string describing the rejection reason. Any other return value is treated as an error. Structural validation (non-empty fields, receipt signature verification, claims digest binding) is performed by CCF before the policy runs; the policy only needs to compare values.

Policy Input Schema
~~~~~~~~~~~~~~~~~~~

The ``apply(transparent_statements)`` function receives an array of transparent statement objects. Each element has the following shape:

.. code-block:: javascript

    [
      {
        phdr: {                           // COSE_Sign1 protected header
          alg: <int>,                     // REQUIRED - COSE algorithm (e.g. -7 for ES256)
          cty: <int|string|undefined>,    // OPTIONAL - content type
          x5chain: [<string>, ...],       // REQUIRED - certificate chain (PEM)
          cwt: {                          // CWT claims
            iss: <string>,                // REQUIRED - issuer DID (did:x509:...)
            sub: <string>,                // REQUIRED - subject / feed
            iat: <int|undefined>,         // OPTIONAL - issued-at (Unix timestamp)
            svn: <int|undefined>,         // OPTIONAL - security version number
          },
        },
        receipts: [                       // at least one CCF receipt
          {
            alg: <int>,                   // REQUIRED - signature algorithm
            vds: <int>,                   // REQUIRED - verifiable data structure (1 = CCF_LEDGER_SHA256)
            kid: <string|undefined>,      // OPTIONAL - key identifier
            cwt: {                        // receipt CWT claims
              iss: <string>,              // REQUIRED - receipt issuer (e.g. "service.example.com")
              sub: <string>,              // REQUIRED - receipt subject
              iat: <int|undefined>,       // OPTIONAL - receipt issued-at
            },
            ccf: {                        // CCF-specific claims
              txid: <string|undefined>,   // OPTIONAL - transaction ID (e.g. "2.42")
            },
            leaves: [                     // at least one Merkle tree leaf
              {
                claims_digest: <string>,      // hex-encoded SHA-256
                commit_evidence: <string>,    // commit evidence string
                write_set_digest: <string>,   // hex-encoded SHA-256
              },
              ...
            ],
          },
          ...
        ],
      },
      ...
    ]

Example Policy
~~~~~~~~~~~~~~

The following policy demonstrates checking every available field:

.. code-block:: javascript

    export function apply(transparent_statements) {
      for (const ts of transparent_statements) {
        if (ts.phdr.alg !== -7) {
          return "Unexpected algorithm: " + ts.phdr.alg;
        }
        if (ts.phdr.cwt.iss !== "did:x509:abc::eku:1.2.3") {
          return "Invalid issuer: " + ts.phdr.cwt.iss;
        }
        if (ts.phdr.cwt.sub !== "my-application") {
          return "Invalid subject: " + ts.phdr.cwt.sub;
        }
        if (ts.phdr.cwt.svn < 100) {
          return "SVN too low: " + ts.phdr.cwt.svn;
        }

        for (const r of ts.receipts) {
          if (r.alg !== -7) {
            return "Unexpected receipt algorithm: " + r.alg;
          }
          if (r.vds !== 1) {
            return "Unexpected VDS: " + r.vds;
          }
          if (r.cwt.iss !== "service.example.com") {
            return "Invalid receipt issuer: " + r.cwt.iss;
          }
          if (r.cwt.sub !== "ledger.signature") {
            return "Invalid receipt subject: " + r.cwt.sub;
          }

          for (const leaf of r.leaves) {
            if (leaf.claims_digest !== "abcdef...") {
              return "Unexpected claims_digest: " + leaf.claims_digest;
            }
            if (leaf.commit_evidence !== "ce:2.42:deadbeef") {
              return "Unexpected commit_evidence: " + leaf.commit_evidence;
            }
            if (leaf.write_set_digest !== "012345...") {
              return "Unexpected write_set_digest: " + leaf.write_set_digest;
            }
          }
        }
      }
      return true;
    }

Setting the Policy
~~~~~~~~~~~~~~~~~~

Use the ``set_node_join_policy`` governance action to register the policy and ``remove_node_join_policy`` to remove it. A node presenting a transparent statement can only join if a code update policy is set and returns ``true``.

Joining with a Transparent Statement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a node joins the network, it can present a transparent statement by setting the ``code_transparent_statement_path`` field in the ``join`` section of its configuration file. This must point to a COSE Sign1 file (the transparent statement) that attests to the node's host data:

.. code-block:: json

    {
      "command": {
        "join": {
          "target_rpc_address": "primary.example.com:8080",
          "code_transparent_statement_path": "/path/to/transparent_statement.cose"
        }
      }
    }

If the joining node's host data is not in the trusted list (i.e. not registered via ``add_snp_host_data``), CCF falls back to evaluating the transparent statement against the code update policy. If no transparent statement is provided, or the policy rejects it, the node will not be allowed to join. If the host data is already explicitly trusted, the node joins without evaluating the policy, regardless of whether a transparent statement is provided.
