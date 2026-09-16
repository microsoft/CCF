CCF threat model review
=======================

What is CCF?
------------

CCF is an application framework. Other teams deploy applications built on it. A CCF service runs an identical application on several nodes. Users reach it over HTTPS, application endpoints read and write a key-value store, and every state change is recorded in an integrity-protected replicated ledger. Users can obtain cryptographic receipts for committed transactions. A consortium of members governs the service through a JavaScript constitution. See the :doc:`public documentation </overview/what_is_ccf>` for the full description.

Threat modelling
----------------

Trust assumptions
~~~~~~~~~~~~~~~~~

Two terms carry a fixed meaning in this report. **Untrusted** means the party may behave maliciously and that behavior is in scope for the threat model. **Trusted** means the review assumes the party behaves correctly, so malicious behavior by that party is out of scope.

.. list-table::
   :header-rows: 1

   * - Party
     - Trust and what follows
   * - Approved application, CCF framework, and confidential-computing platform
     - **Trusted.** Assumed sound. Code running inside the enclave can read private state, so flaws there are not prevented.
   * - Governing consortium members
     - **Trusted collectively, not individually.** Members govern through signed proposals and the approval rules in the constitution. The constitution is application-specific and therefore outside the scope of CCF's threat model. Individual members may act maliciously; the consortium is trusted as a whole to govern correctly.
   * - Service operator
     - **Trusted** to operate the service correctly.
   * - Host infrastructure, including hosts and the people who run them
     - **Untrusted.** Assumed to see and modify anything outside the enclave, including ledger files, snapshots, node configuration, and network traffic. Malicious host behavior is in scope.

User interactions with the application are untrusted. Users can verify the service identity to check that they are communicating with the intended service. They can also obtain and verify :doc:`cryptographic receipts </audit/receipts>` for committed transactions, providing evidence with which to hold the service accountable.

Typical CCF deployment
~~~~~~~~~~~~~~~~~~~~~~

A CCF service runs the same application on several nodes. Typical deployments have three nodes. One of them holds the primary role at any moment; the other two are backups. Transactions are replicated across the nodes by the primary. Each node has its own local disk holding its copy of the ledger and its snapshots. The load balancer routes client requests to whichever node is the primary.

.. mermaid::

    flowchart TB
        client["Client"]
        lb["Load balancer"]
        subgraph s1["C-ACI node 1"]
            n1("CCF node<br/>current primary")
            d1[("Local disk")]
            n1 --- d1
        end
        subgraph s2["C-ACI node 2"]
            n2("CCF node<br/>backup")
            d2[("Local disk")]
            n2 --- d2
        end
        subgraph s3["C-ACI node 3"]
            n3("CCF node<br/>backup")
            d3[("Local disk")]
            n3 --- d3
        end
        client <--> lb
        lb <--> n1
        n1 <--> n2 & n3

Protection scope
~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1

   * - Surface
     - Protection
   * - Joining nodes
     - Attestation and consortium admission.
   * - Node-to-node channels
     - Authenticated, cryptographically protected channels.
   * - Client connections
     - HTTPS with application-defined caller authentication.
   * - Operator endpoints
     - Interface and VNet access restrictions.
   * - Stored state
     - Transaction integrity, private-data encryption, and rollback/fork detection.

Governance rules are application-specific and out of scope for this review. The report describes CCF's protection mechanisms, not the service's constitution or its choice of member approval rules.

Detailed analysis
-----------------

The sections below explain how CCF protects a node, its stored state, and its communication with clients and other nodes.

How a single node is protected
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A CCF node on Azure Confidential ACI runs inside an :doc:`AMD SEV-SNP </operations/platforms/snp>` protected utility VM (UVM). SEV-SNP encrypts the UVM's memory with a processor-managed, VM-specific key and protects its memory and guest execution state from the host and hypervisor. The application, CCF framework, private state, and ledger secrets run inside this boundary. Storage and network traffic remain outside it and use separate protections.

.. mermaid::

    classDiagram
        direction TB
        class Host["Host and hypervisor: untrusted"]
        class Network
        namespace Untrusted_inputs_and_storage {
            class Config["Node config JSON"]
            class Ledger["Ledger files"]
            class Snapshots
        }
        namespace SEV_SNP_protected_UVM {
            class App["Service application"]
            class Framework["CCF framework"]
            class Memory["Private state and ledger secrets"]
        }
        Host --> Config : Supplies inputs and storage
        Host --> App : Hosts the protected UVM
        App <--> Framework : Key-value reads and writes
        Framework <--> Memory : Private state and ledger secrets
        Config --> Framework : Read at startup
        Ledger <--> Framework : Transactions / AES-256-GCM authentication
        Snapshots <--> Framework : Encrypted private state / committed snapshot evidence
        Framework <--> Network

Protected execution
^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - Component
     - Protection
   * - UVM memory and guest execution state
     - SEV-SNP provides memory confidentiality and integrity against the host and hypervisor, including protection against replay, corruption, remapping, and aliasing attacks.
   * - Application and CCF framework
     - Both execute inside the protected UVM and can access private state. They are trusted code, not isolated from each other by SEV-SNP.
   * - Container images and launch commands
     - The UVM enforces the execution policy, which constrains permitted containers, commands, and runtime actions. Attestation binds the enforced policy to the node.

Attestation and trusted dependencies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Attestation lets peers check which environment a node runs in before trusting it. It identifies the protected environment; SEV-SNP provides the isolation.

.. list-table::
   :header-rows: 1

   * - Evidence
     - What it identifies
   * - UVM launch measurement and Microsoft-issued endorsements
     - The UVM image and its endorsement issuer.
   * - ``host_data``
     - The SHA-256 digest of the enforced execution policy.
   * - ``report_data``
     - A digest of the node public key, binding the evidence to the node's identity.
   * - Platform and trusted computing base (TCB) state
     - Hardware and firmware security versions, plus policy fields such as debug and migration permissions.

The node relies on AMD's processor, Platform Secure Processor (PSP) firmware, and endorsement chain, and on Microsoft's UVM and its policy enforcement. The consortium selects the accepted measurements, policy digests, and minimum TCB versions. The application and CCF framework remain trusted to handle private state correctly.

Configuration
^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - Input
     - Configuration options
     - Protection
   * - :doc:`config.json </operations/configuration>`
     - Contains options intended to be safe for the host to control, rather than security-sensitive launch options.
     - Unprotected, host-controlled input. Schema validation checks its format.
   * - :doc:`CLI arguments </operations/cli>`
     - Capture security-sensitive options, such as ``--log-level``, that must not be freely controlled by the host.
     - Constrained by the execution policy and bound through attestation where that policy fixes their values.

Stored state
^^^^^^^^^^^^

.. list-table::
   :header-rows: 1

   * - Component
     - Protection
   * - :doc:`Ledger transaction integrity </architecture/ledger>`
     - Each ledger transaction carries an AES-256-GCM header holding the IV and authentication tag. Public transaction data stays plaintext but is authenticated as associated data; private transaction data is encrypted and authenticated. Sequence numbers and some metadata remain visible.
   * - Private data on disk
     - Private map contents are encrypted with :doc:`AES-256-GCM </architecture/cryptography>` under ledger secrets held in plaintext only in memory by trusted nodes. The trusted application and framework can access private state.
   * - Rollback and fork detection
     - Transactions feed a :doc:`Merkle tree </architecture/merkle_tree>` whose root the primary signs at regular intervals. While the service is running with a healthy quorum, an outdated copy of the ledger cannot roll back committed transactions. Auditors can reconstruct the tree and verify signatures; retained signed receipts provide evidence of truncation or a fork after recovery. This is detection rather than unconditional prevention: consortium-approved :doc:`catastrophic recovery </operations/recovery>` can intentionally truncate history.
   * - :doc:`Snapshots </operations/ledger_snapshot>`
     - Private state is encrypted; public state remains visible. Snapshot evidence records a SHA-256 digest, and a later signature transaction commits it. Only committed snapshots are accepted for join and recovery.

Single-node communication
~~~~~~~~~~~~~~~~~~~~~~~~~

This diagram examines the traffic that crosses into and out of one node: user sessions, a join request from a prospective node, and the channels to already admitted peers.

.. mermaid::

    flowchart LR
        joiner("Joining node")
        peers("Admitted CCF nodes")
        node("CCF node")
        user["User"]:::external
        operator["Operator"]:::external
        joiner <-->|"HTTPS"| node
        peers <-->|"AES-256-GCM"| node
        node <-->|"HTTP over TLS"| user
        node <-->|"HTTP over TLS"| operator

.. list-table::
   :header-rows: 1

   * - Connection
     - Protection
   * - :doc:`Joining nodes </operations/start_network>`
     - The HTTPS join request carries SNP attestation bound to the joining node's public key. CCF validates the evidence; attestation validation and consortium admission are separate steps.
   * - :doc:`Node-to-node channels </architecture/node_to_node>`
     - Admitted nodes mutually authenticate service-endorsed identities. Authenticated Diffie-Hellman establishes per-direction AES-256-GCM keys for the custom TCP channel, and monotonic counters reject replayed messages. The Microsoft Cryptography Board approved this protocol.
   * - Client sessions
     - HTTPS terminates inside the CCF node. Clients verify the TLS certificate against the expected service identity. CCF 7.0.14 offers hybrid ML-KEM key exchange, with classical key exchange available as a fallback.
   * - :doc:`Caller authentication </build_apps/auth/index>`
     - The application sets authentication requirements per endpoint, including whether a TLS client certificate is required. mTLS is not a CCF-wide requirement.
