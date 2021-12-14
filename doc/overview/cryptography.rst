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
        A[[Never leaves enclave]]
        L[("Ledger (on disk)")]

Identity keys diagram:

.. mermaid::

    flowchart TB
        A[Service Identity Certificate] -.- B[[Service Identity Private Key]]
        C[Node Identity Certificate] -.- D[[Node Identity Private Key]]
        A[Service Identity Certificate] -- recorded in ccf.gov.service.info --> L[(Ledger)]
        C[Node Identity Certificate] -- recorded in <br> ccf.gov.nodes.endorsed_certificates --> L[(Ledger)]
        A[Service Identity Certificate] -- endorses --> C[Node Identity Certificate]
        C[Node Identity Certificate] -- contains --> P[Node Identity Public Key]
        Q[Node Enclave Quote] -- contains hash of --> P[Node Identity Public Key]
        D[[Node Identity Private Key]] -- signs --> S[Ledger Signatures]
        S[Ledger Signatures] -- recorded in <br> ccf.internal.signatures --> L[(Ledger)]


Ledger Secret diagram:

.. mermaid::

    flowchart TB
        B[[Current Ledger Secret]] -- encrypted by --> A[[Ledger Secret Wrapping Key]]
        B[[Current Ledger Secret]] -- "encrypts (AES-GCM)" --> W[All Transactions]
        W[All Transactions] -- recorded in --> L[(Ledger)]
        B[[Current Ledger Secret]] --> H[/encrypts/]
        E[[Previous Ledger Secret]] --> H[/encrypts/] --> I[Encrypted Previous Ledger Secret]
        I[Encrypted Previous Ledger Secret] -- recorded in <br> ccf.internal.historical_encrypted_ledger_secret --> L[(Ledger)]
        A[[Ledger Secret Wrapping Key]] -- split into --> C{{k-of-n recovery shares}}
        D[Members encryption public keys] --> F[/encrypts/]
        C{{k-of-n recovery shares}} --> F[/encrypts/] --> G[Encrypted k-of-n recovery shares]
        G[Encrypted k-of-n recovery shares] -- recorded in <br> ccf.internal.recovery_shares --> L[(Ledger)]


Algorithms and Curves
---------------------

Authenticated encryption in CCF relies on AES256-GCM. Ledger authentication relies on Merkle trees using SHA2-256.

Public-key certificates, signatures, and ephemeral Diffie-Hellman key exchanges all rely on elliptic curves (except for the encryption of ledger secrets shared between nodes and member recovery shares, which uses `RSA OAEP <https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding>`_). The supported curves are listed in `crypto/curve.h`:

    .. literalinclude:: ../../src/crypto/curve.h
        :language: cpp
        :start-after: SNIPPET_START: supported_curves
        :end-before: SNIPPET_END: supported_curves

The ``service_identity_curve_choice`` determines the curve used by CCF for the service and node identities. User and member certificates do not need to match this, and can be created on any supported curve.