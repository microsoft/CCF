Cryptography
============

Keys
----

Service
~~~~~~~

A CCF service/network has:

- A service/network identity public-key certificate, used for :term:`TLS` server authentication.
- Symmetric data-encryption keys, used to encrypt entries in the ledger.

Node
~~~~

Each CCF node is identified by a fresh public-key certificate endorsed by a quote.
This certificate is used to authenticate the node when it joins the
network, and to sign entries committed by the node to the ledger during its time as primary.

Node keys are also used during recovery, to share recovered ledger secrets between nodes.

User
~~~~

Each CCF user is identified by a public-key certificate, used for :term:`TLS` client authentication when they connect to the service.
These keys are also used to sign user commands.

Member
~~~~~~

Each CCF consortium member is similarly identified by a public-key certificate used for client authentication and command signing.

Ephemeral Network Keys
~~~~~~~~~~~~~~~~~~~~~~

Each node to node pair establishes a symmetric traffic key, using an authenticated Diffie Hellman key exchange.
This key authenticates ledger replication headers exchanged between  nodes. It is also use to encrypt forwarded
write transactions from the backups to the primary.

Legend:

.. mermaid::

    flowchart TB
        A[Never leaves enclave]
        L[("Ledger (on disk)")]
        C{{Multiple}}
        B[Key] --> E[/encrypt/]
        P[Plaintext] --> E[/encrypt/] --> C[Cipher]

Identity keys diagram:

.. mermaid::

    flowchart TB
        ServiceCert[fa:fa-scroll Service Identity Certificate] -.- ServicePrivk[fa:fa-key Service Identity Private Key]
        NodeCert[fa:fa-scroll Node Identity Certificate] -.- NodePrivk[fa:fa-key Node Identity Private Key]
        ServiceCert -- recorded in <br> ccf.gov.service.info --> Ledger[(fa:fa-book Ledger)]
        NodeCert -- recorded in <br> ccf.gov.nodes.endorsed_certificates --> Ledger
        ServicePrivk -- signs --> NodeCert
        NodeCert -- contains --> NodePubk[Node Identity Public Key]
        NodePrivk -- signs --> Signature[fa:fa-file-signature Ledger Signatures]
        Signature -- recorded in <br> ccf.internal.signatures --> Ledger
        Attestation[fa:fa-microchip Node Enclave Attestation <br> + Collaterals] -- contains hash of --> NodePubk
        Attestation -- recorded in <br> ccf.gov.nodes.info --> Ledger


Ledger Secret diagram:

.. mermaid::

    flowchart TB
        WrappingKey -- split into --> RecoveryShares{{fa:fa-helicopter k-of-n <br> Recovery Shares}}
        MemberPublicKeys{{fa:fa-users Members Encryption <br> Public Keys}} --key--> F[/encrypts/]
        RecoveryShares --in--> F[/encrypts/] --> EncryptedRecoveryShares{{fa:fa-lock Encrypted k-of-n <br> Recovery Shares}}
        EncryptedRecoveryShares -- recorded in <br> ccf.internal.recovery_shares --> Ledger

        PreviousLedgerSecret[fa:fa-key Previous <br> Ledger Secret] --in--> H[/encrypts/] --> EncryptedPreviousLedgerSecret[fa:fa-lock Encrypted Previous <br> Ledger Secret]
        LedgerSecret --key--> H[/encrypts/]
        EncryptedPreviousLedgerSecret -- recorded in <br> ccf.internal.historical_encrypted_ledger_secret --> Ledger

        WrappingKey[fa:fa-key Ledger Secret <br> Wrapping Key] --key--> N[/encrypts/]
        LedgerSecret --in--> N[/encrypts/] --> EncryptedLedgerSecret[fa:fa-lock Encrypted <br> Ledger Secret]
        EncryptedLedgerSecret -- recorded in ccf.internal --> Ledger[(fa:fa-book Ledger)]

        LedgerSecret[fa:fa-key Ledger <br> Secret] -- "encrypts <br> (AES-GCM)" --> Transactions[fa:fa-lock All CCF Transactions]
        style LedgerSecret fill:#7EBB42,stroke:black,stroke-width:3px
        Transactions -- recorded in --> Ledger

        LedgerSecret --in--> K[/encrypts/] --> NodeEncryptedLedgerSecrets{{fa:fa-lock Node Encrypted Ledger Secrets}}
        NodeEncryptionPublicKeys{{Node Encryption <br> Public Keys}} --key--> K[/encrypt/]
        NodeEncryptedLedgerSecrets{{fa:fa-lock Node Encrypted <br> Ledger Secrets}}
        NodeEncryptedLedgerSecrets -- recorded in <br> ccf.internal.encrypted_ledger_secrets --> Ledger


Algorithms and Curves
---------------------

Authenticated encryption in CCF relies on AES256-GCM. Ledger authentication relies on Merkle trees using SHA2-256.

Public-key certificates, signatures, and ephemeral Diffie-Hellman key exchanges all rely on elliptic curves (except for the encryption of ledger secrets shared between nodes and member recovery shares, which uses `RSA OAEP <https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding>`_). The supported curves are listed in `crypto/curve.h`:

    .. literalinclude:: ../../src/crypto/curve.h
        :language: cpp
        :start-after: SNIPPET_START: supported_curves
        :end-before: SNIPPET_END: supported_curves

The ``service_identity_curve_choice`` determines the curve used by CCF for the service and node identities. User and member certificates do not need to match this, and can be created on any supported curve.