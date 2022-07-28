Code Upgrade
============

.. note:: Refer to :doc:`/operations/code_upgrade_1x` for specific guidelines on how to upgrade a 1.x CCF service to 2.0.

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

    graph TB;
        classDef Primary stroke-width:4px

        subgraph Service
            Node0((Node 0))
            Node1((Node 1))
            class Node1 Primary
            Node2((Node 2))
        end

1. First, operators/members should register the new code version corresponding to the new enclave measurement using the ``add_node_code`` proposal action (see :ref:`governance/common_member_operations:Updating Code Version`).


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

    graph TB;
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

- Members should be use the ``set_constitution`` proposal action to update the constitution scripts.
- See :ref:`bundle deployment procedure <build_apps/js_app_bundle:Deployment>` to update the JavaScript/TypeScript application.

6. Finally, once the code upgrade process has been successful, the old code version (i.e. the code version run by nodes 0, 1 and 2) can be removed using the ``remove_node_code`` proposal action.

Notes
-----

- The :http:GET:`/node/version` endpoint can be used by operators to check which version of CCF a specific node is running.
- A code upgrade procedure provides very little service downtime compared to a disaster recovery. The service is only unavailable to process write transactions while the primary-ship changes (typically a few seconds) but can still process read-only transactions throughout the whole procedure. Note that this is true during any primary-ship change, and not just during the code upgrade procedure.
