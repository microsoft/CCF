Work In progress
================

note "28/06"
~~~~~~~~~~~~

Basic integration design

.. mermaid::

    sequenceDiagram
        participant Client
        participant Primary Frontend
        participant Primary KV
        participant Primary History
        participant Primary PBFT
        participant Backup PBFT
        participant Backup Frontend
        participant Backup KV
        participant Backup History

        Note over Primary PBFT: + PBFT Client Proxy
        Client->>Primary Frontend: JSON-RPC Request
        Primary Frontend->>Primary History: add_request(RequestID, JSON-RPC Request)
        Primary History->>Primary PBFT: PBFT ON_REQUEST callback
        Primary PBFT->>Backup PBFT: Send JSON-RPC Request
        Backup PBFT->>Backup PBFT: Record JSON-RPC Request
        Primary PBFT->>Primary PBFT: execute tentative: Noop
        Primary PBFT->>Backup PBFT: Send Pre-prepare
        Primary PBFT-->>Primary History: _
        Primary History-->>Primary Frontend: _
        Primary Frontend->>Primary KV: execution
        Primary KV->>Primary History: add_result(RequestID, version, tree root)
        Primary History->>Primary History: add hash of write set to tree
        Note right of Primary History: TODO: Pass version and tree root to PBFT
        Primary History-->>Primary KV: _
        Primary KV-->>Primary Frontend: _
        Primary Frontend->>Primary History: add_response(Request ID, JSON-RPC Response)
        Note right of Primary History: TODO: ?
        Primary History-->>Primary Frontend: _
        Primary Frontend-->>Client: JSON-RPC Response


        Backup PBFT->>Backup PBFT: execute tentative
        Note right of Backup PBFT: TODO: Dispatch to correct frontend
        Backup PBFT->>Backup Frontend: JSON-RPC Request execution
        Note right of Backup KV: TODO: Create new KV for PBFT?
        Backup Frontend->>Backup KV: execution
        Backup KV->>Backup History: add hash of write set to tree
        Backup KV-->>Backup Frontend: _
        Backup Frontend-->>Backup PBFT: _
        Note over Backup PBFT, Backup History: TODO: Verify Merkle root


note "05/07"
~~~~~~~~~~~~

.. mermaid::

    sequenceDiagram
        participant Client
        participant Primary Frontend
        participant Primary KV
        participant Primary History
        participant Primary Client Proxy
        participant Primary PBFT
        participant Backup PBFT
        participant Backup Frontend
        participant Backup KV
        participant Backup History

        Note over Client: TODO: Handle first request
        Client->>Primary Frontend: JSON-RPC Request
        Primary Frontend->>Primary History: add_request(RequestID, JSON-RPC Request)


        Primary History->>Primary Client Proxy: ON_REQUEST callback

        Primary Client Proxy->>Primary PBFT: Handle request


        Primary PBFT->>Backup PBFT: send JSON-RPC Request
        Backup PBFT->>Backup PBFT: record JSON-RPC Request
        Primary PBFT->>Primary PBFT: execute tentative

        Primary PBFT->>Primary Frontend: process(JSON-RPC Request)

        Note over Primary Frontend: Business Logic
        Primary Frontend->>Primary KV: Commit TX
        Primary KV->>Primary History: add_result(RequestID, version, tree root)
        Primary History->>Primary History: add hash of write set to tree

        Note over Primary History: TODO: Record Merkle root and version
        Primary History-->>Primary KV: _
        Primary KV-->>Primary Frontend: _
        Note over Primary Frontend: JSON-RPC Response generated
        Primary Frontend->>Primary History: add_response(Request ID, JSON-RPC Response)
        Note right of Primary History: TODO: ?
        Primary History-->>Primary Frontend: _
        Primary Frontend-->>Primary PBFT: _

        Note over Client, Primary PBFT: TODO: Only send the request once a round of PBFT has completed, hack for now
        Primary PBFT->>Primary Client Proxy: Send JSON-RPC Response
        Primary Client Proxy->>Client: JSON-RPC Response (via rpc_sessions)

        Note over Primary PBFT: Collect a batch of requests
        Primary PBFT->>Backup PBFT: send Pre-prepare (Merkle root + version)

        loop Ordered requests
            Backup PBFT->>Backup PBFT: execute tentative

            Backup PBFT->>Backup Frontend: process(JSON-RPC Request)
            Backup Frontend->>Backup KV: Commit TX
            Backup KV->>Backup History: add hash of write set to tree
            Backup KV-->>Backup Frontend: _
            Backup Frontend-->>Backup PBFT: _
        end

        Backup PBFT->>Backup PBFT: Verify Merkle root
        Note over Backup PBFT, Backup History: TODO: How do we signal to PBFT that the Merkle roots don't match up?


Done (some on master, some on the `pbft_integration` branch):

* Dispatching message to appropriate frontend
* CCF frontend + KV execution via PBFT's exec_command
* Integrate Client Proxy

To Do next:

* Make first transaction (genesis) work with PBFT
* Fix Client Proxy reply to client
* Pass Request ID from CCF to PBFT
* Support full round of PBFT before replying to client
* Pass the Merkle root and version in Pre-prepare message

note "19/07"
~~~~~~~~~~~~

.. mermaid::

    sequenceDiagram
        participant Client
        participant Primary Frontend
        participant Primary KV
        participant Primary History
        participant Primary Client Proxy
        participant Primary PBFT

        Client->>Primary Frontend: JSON-RPC Request
        Primary Frontend->>Primary History: add_request(RequestID, JSON-RPC Request)


        Primary History->>Primary Client Proxy: ON_REQUEST callback

        Primary Client Proxy->>Primary PBFT: Handle request


        Primary PBFT->>Backup PBFT: send JSON-RPC Request
        Backup PBFT->>Backup PBFT: record JSON-RPC Request
        Primary PBFT->>Primary PBFT: execute tentative

        Primary PBFT->>Primary Frontend: process(JSON-RPC Request)

        Note over Primary Frontend: Business Logic
        Primary Frontend->>Primary KV: Commit TX
        Primary KV->>Primary History: add_result(RequestID, version, tree root)
        Primary History->>Primary History: add hash of write set to tree

        Note over Primary History: TODO: Record Merkle root and version
        Primary History-->>Primary KV: _
        Primary KV-->>Primary Frontend: _
        Note over Primary Frontend: JSON-RPC Response generated
        Primary Frontend->>Primary History: add_response(Request ID, JSON-RPC Response)
        Note right of Primary History: TODO: ?
        Primary History-->>Primary Frontend: _
        Primary Frontend-->>Primary PBFT: _

        Primary PBFT->>Primary Client Proxy: Send JSON-RPC Response
        Primary Client Proxy->>Client: JSON-RPC Response (via rpc_sessions)

        Note over Primary PBFT: Collect a batch of requests


Done (all on `master`):

* Integration for f = 0:
    * Dispatching message to appropriate frontend
    * CCF frontend + KV execution via PBFT's exec_command
    * Integrate Client Proxy
    * Pass Request ID from CCF to PBFT
    * Support full round of PBFT before replying to client

To Do next:

* Unify consensus interface
* Pass the Merkle root and version in Pre-prepare message
* Support for f = 1:
    * Startup on all nodes
    * Dynamic node configuration


09/08
~~~~~

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


Done (all on `master`):

* Integration for f = 0:
    * Dispatching message to appropriate frontend
    * CCF frontend + KV execution via PBFT's exec_command
    * Integrate Client Proxy
    * Pass Request ID from CCF to PBFT
    * Support full round of PBFT before replying to client
* Pass the Merkle root and version in Pre-prepare message

To Do next:

* Unify consensus interface
* Support for f = 1:
    * Startup on all nodes
    * Dynamic node configuration