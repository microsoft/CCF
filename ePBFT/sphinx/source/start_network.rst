Starting up a network
=====================

Proposed diagram for creating a new network when running with CCF
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. mermaid::

    sequenceDiagram
        participant Member Consortium
        participant Node 0 
        participant Node 1 

        Node 0 ->>Node 0 : node start - signed by Node 0
        Note over Node 0 : node start txs [add members, add nodes (0), governance, ...]

        Node 1 ->>Node 0 : JoinRPC - signed by Node 1
        Node 0 ->>Node 0 : add Node 1 to nodes table
        Node 0 ->>Node 1 : OK [respond with node 1 id and node 0 id]
        Node 1 ->> Node 1 : setup PBFT for Node 1
        Node 1 ->> Node 1 : add Node 0 to PBFT configuration

        Note over Node 0 : ... more nodes can join in the mean time ...

        Member Consortium->>Node 0 : OPEN network - signed by member(s)
        Node 0 ->>Node 0 : Set f > 0
        loop Node Catchup
            Node 0 ->>Node 1 : replay ledger to Node 1
            Node 1 ->> Node 0 : ask for previous state
            Node 0 ->> Node 1: replay ledger to Node 1
            Node 1 ->>Node 1 : replay ledger transactions - hooks triggered that set up the rest of the PBFT replicas
        end