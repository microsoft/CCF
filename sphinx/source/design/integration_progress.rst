PBFT integration
================

Starting up a network
---------------------

Proposed diagram for creating a new network when running with CCF

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

`Primary`

.. mermaid::

    sequenceDiagram
        participant Client
        participant LedgerEnclave(RB)
        participant Frontend
        participant KV
        participant History
        participant Client Proxy
        participant Replica
        participant Backup Replica

        Client->>Frontend: JSON-RPC Request
        Frontend->>History: add_request(RequestID, actor, caller_id, JSON-RPC Request)


        History->>Client Proxy: ON_REQUEST callback(RequestID, actor, caller_id, JSON-RPC Request)

        Client Proxy->>Client Proxy: Wrap JSON-RPC Request in PBFT command

        Client Proxy->>Replica: send(PBFT command, All_replicas)
        Replica->>Backup Replica: send(PBFT command)
        Replica-->>Client Proxy:_


        Client Proxy->>Replica: handle(Request [PBFT command])
        Replica->>Replica: execute_tentative: starts
        Replica->>Replica: exec_command: starts

        Replica->>Frontend: process_pbft(PBFT command [Wrapped JSON-RPC Request])

        Frontend->>History: register ON_RESULT callback

        Frontend->>Frontend: process_json()

        Frontend->>KV: COMMIT TX
        KV->>History: add_result(RequestID, version, merkle_root)

        History->>History: ON_RESULT callback: populated merkle_root reference that was passed by process_pbft when callback was registered

        History-->>KV:_
        KV-->>Frontend:_

        Frontend->>Replica: return from process_pbft(): ProcessPbftResult{result, merkle_root}
        Replica->>Replica: cp merkle_root into exec_command's Byz_info
        Replica->>Replica: exec_command: returns
        Replica->>Replica: execute_tentative: returns

        Replica->>Replica: put merkle_root in pre prepare msg
        Replica->>Replica: write pre prepare and requests to ledger
        Replica->>LedgerEnclave(RB): ON_APPEND_LEDGER_ENTRY Callback: put_entry()
        LedgerEnclave(RB)-->>Replica:_

        Replica->>Replica Backup: send(pre prepare, All_replicas)

        Replica-->>Client Proxy: return from handle()
        Client Proxy-->>History: return from ON_REQUEST callback()
        History-->>Frontend: return from add_request()
        Frontend-->>Client: return from process()


`Backup/Replica`


[handling a prepare is the same if the Replica is Primary]

.. mermaid::

    sequenceDiagram
        participant Nodestate
        participant LedgerEnclave(RB)
        participant Frontend
        participant Client Proxy
        participant Replica
        participant All Other Replicas

        Nodestate->>Replica: receive_message()

        Replica-->>Replica: receive_process_one_msg()
        Replica->>Replica: handle(Request)
        Replica->>Replica: store request
        Replica->>Replica: forward request to primary

        Nodestate->>Replica: receive_message()
        Replica-->>Replica: receive_process_one_msg()
        Replica->>Replica: handle(Pre_prepare)
        Replica->>Replica: write pre prepare to ledger [as shown for primary]
        Replica-->>LedgerEnclave(RB): [as shown above]

        Replica->>Replica: execute_tentative [as shown for primary]
        Replica->>Replica: exec_command [as shown for primary]

        Replica->>Replica: check that merkle_root matches
        Note over Replica: check that merkle_root returned from exec_command (populated by history after exec_command calls out to frontend) matches the one from the pre_prepare msg
        Replica->>All Other Replicas: [if not ok just return] if ok send(Prepare with pp's digest, All_replicas)

        Nodestate->>Replica: receive_message()
        Replica-->>Replica: receive_process_one_msg()

        Replica->>Replica: handle(Prepare)
        Replica->>Replica: [if prepare cert is complete] write prepare cert info to ledger
        Note over Replica: writing prepare includes writing a header [seqno, num of pp proofs] and writing the proofs [all pp proofs for each prepare that I have in this certifcate]
        Replica-->>LedgerEnclave(RB): write header
        Replica-->>LedgerEnclave(RB): write proofs

        Replica->> All Other Replicas: [if prepare cert complete] send(commit, All_replicas)

Proposed integration layout
---------------------------

`Primary`

.. mermaid::

    graph TD
        Client-- Command -->Consensus
        Consensus-- Batch of Commands -->Dispatcher
        Dispatcher-- SubBatch of Commands -->FrontEnd1
        Dispatcher-- SubBatch of Commands -->FrontEnd2
        FrontEnd1-- Tx -->KV
        FrontEnd2-- Tx -->KV
        KV-- Tx Digest -->History
        History-- Merkle Tree Root -->KV
        KV-- Ordered Batch of Commands, Responses with Tree Root-->Consensus


.. mermaid::

    sequenceDiagram
        participant Client
        participant Consensus
        participant Dispatcher
        participant FrontEnd1
        participant FrontEnd2
        participant KV
        participant History
        Client->>Consensus: Command1
        Client->>Consensus: Command2
        Client->>Consensus: Command2
        Consensus->>Dispatcher: Batch of Command1,2,3
        Dispatcher->>FrontEnd1: Batch of Command1,2
        Dispatcher->>FrontEnd2: Batch of Command3
        FrontEnd1->>KV: Tx1, Tx2
        KV->>History: Digest1
        KV->>History: Digest2
        FrontEnd2->>KV: Tx3
        KV->>History: Digest3
        History->>KV: Root of Tree
        KV->>Consensus: Ordered Batch of Command 1,2 and Command3 with Root of Tree and Responses


`Replica`

.. mermaid::

    graph TD
        Primary-- Ordered Batch of Commands with Tree Root -->Consensus
        Consensus-- SubBatch of Commands -->FrontEnd1
        Consensus-- SubBatch of Commands -->FrontEnd2
        FrontEnd1-- Tx -->KV
        FrontEnd2-- Tx -->KV
        KV-- Tx Digest -->History
        History-- Merkle Tree Root -->KV
        KV-- Tree Root -->Consensus
        Consensus-- Confirm or Rollback --> KV

.. mermaid::

    sequenceDiagram
        participant Primary
        participant Consensus
        participant Dispatcher
        participant FrontEnd1
        participant FrontEnd2
        participant KV
        participant History
        Primary->>Consensus: Ordered Batch of Command 1,2 and Command3 with Root of Tree
        Consensus->>Dispatcher: Ordered Batch of Command 1,2 and Command3
        Dispatcher->>FrontEnd1: Batch of Command1,2
        Dispatcher->>FrontEnd2: Batch of Command3
        FrontEnd1->>KV: Tx1, Tx2
        KV->>History: Digest1
        KV->>History: Digest2
        FrontEnd2->>KV: Tx3
        KV->>History: Digest3
        History->>KV: Root of Tree
        KV->>Consensus: Root of Tree
        Consensus->>KV: Confirm or Rollback