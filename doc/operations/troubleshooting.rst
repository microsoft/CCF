Troubleshooting CCF
===================

This page contains troubleshooting tips for CCF.

Tips for interacting with CCF to diagnose issues
------------------------------------------------
.. note:: In the examples below this documentation uses ``example-ccf-domain.com`` as an example CCF domain, you will need to replace that with your own CCF domain when using these commands. 

.. note:: CCF may be deployed with a loadbalancer which may cache the node which last responded to a query from an IP address. Until the cache clears, any subsequent queries from that IP address will be handled by the same node. As an example, if the cache clears after one minute, then in order to get a response from a different node, an operator must wait one minute between queries.  

Below are descriptions of CLI commands and how they are useful for diagnosing CCF issues:

**“What node is handling my requests?”**

.. code-block:: bash 

    curl -k https://example-ccf-domain.com/node/network/nodes/self -i

This is useful to identify which node is handling queries. The node ID can be found in the Location header. Please read the note above about loadbalancers.

**“What CCF version is running?”**

.. code-block:: bash

    curl -k https://example-ccf-domain.com/node/version

This is useful to confirm the version that is running.

**“What nodes are part of the current network?”**

.. code-block:: bash

    curl -k https://example-ccf-domain.com/node/network/nodes

This will show information for all nodes in the network. In a healthy network all nodes will show ``“status” = “Trusted”``, and one node only will show ``“primary” = true``. This is the healthy state of the network. 
Around upgrades/restarts/migrations nodes will transition through unhealthy states temporarily. If the network remains in an unhealthly state for a long time, this indicates there is an issue. 

You can obtain this information for a single node by appending its ID to this endpoint. E.g. ``https://<your-domain>/node/network/nodes/<ID>``, where ``<ID>`` can be obtained from the ``/node/network/nodes/self`` endpoint described above. Take note of the ``node_data`` field which contains useful correlation IDs. E.g. ``node 0``, ``pod name``.

**“Is the network in the middle of a reconfiguration?”**

.. code-block:: bash

    curl -k https://example-ccf-domain.com/node/consensus

This has a few bits of data that might help us diagnose a partitioned/faulty network. In particular, most of the time there should be a single entry in the ``configs`` list. During an upgrade/restart/migration, there may be multiple values. If multiple values persist for a long time, it suggests something went wrong during the reconfiguration.

**“Is the CCF network stable?”**

.. code-block:: bash

    curl -k https://example-ccf-domain.com/node/commit

This is a good endpoint to query to check if the CCF service is reachable. Additionally, comparing the view in this response with the “current view” from /node/consensus endpoint, explained above, can highlight a partitioned node. So for example, if the response from ``/node/commit`` states the ``view`` is ``15``, and the response from ``/node/concensus`` states the node's ``current view`` is ``78967`` and that number is constantly increasing, then this indicates the node is unable to make consensus progress, which likely indicates it is unable to contact other nodes. 


Node Output
===========

By default node output is written to ``stdout`` and to ``stderr`` and can be handled accordingly.

There is an option to generate machine-readable logs for monitoring. To enable this pass ``--json-format-json`` when creating a node (in either ``start`` or ``join`` mode). The generated logs will be in JSON format as displayed below:

.. code-block:: json

    {
        "e_ts": "2019-09-02T14:47:24.589386Z",
        "file": "../src/consensus/raft/raft.h",
        "h_ts": "2019-09-02T14:47:24.589384Z",
        "level": "info",
        "msg": "Deserialising signature at 24\n",
        "number": 651
    }

- ``e_ts`` is the ISO 8601 UTC timestamp of the log if logged inside the enclave (field will be missing if line was logged on the host side)
- ``h_ts`` is the ISO 8601 UTC timestamp of the log when logged on the host side
- ``file`` is the file the log originated from
- ``number`` is the line number in the file the log originated from
- ``level`` is the level of the log message [info, debug, trace, fail, fatal]
- ``msg`` is the log message