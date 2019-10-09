Proposed integration layout
===========================


Primary
~~~~~~~

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



Replica
~~~~~~~

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