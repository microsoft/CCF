Integration progress diagram
============================

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