Cryptography
============

Keys
----

Network
~~~~~~~

A CCF network has a master secret, which is used to derive keys for multiple purposes:

 * A network identity public-key certificate, used for :term:`TLS` server authentication.
 * Symmetric data-encryption keys, used to encrypt entries in the ledger.

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

Identity keys diagram:

.. mermaid::

    flowchart TB
        A[Service Identity Certificate] -.- B[[Service Identity Private Key]]
        C[Node Identity Certificate] -.- D[[Node Identity Private Key]]
        A[Service Identity Certificate] -- recorded in --> L[(Ledger)]
        C[Node Identity Certificate] -- recorded in --> L[(Ledger)]
        A[Service Identity Certificate] -- endorses --> C[Node Identity Certificate]


Ledger Secret diagram:

.. mermaid::

    flowchart TB
        A[Ledger Secret Wrapping Key] -- encrypts --> B[[Current Ledger Secret]]
        A[Ledger Secret Wrapping Key] -- split into --> C{{k-of-n recovery shares}}
        D[Members encryption public keys] -- encrypt --> C{{k-of-n recovery shares}}
        C{{k-of-n recovery shares}} -- recorded in --> L[(Ledger)]
        B[[Current Ledger Secret]] -- encrypts --> E[[Previous Ledger Secret]]

Algorithms and Curves
---------------------

Authenticated encryption in CCF relies on AES256-GCM. Ledger authentication relies on Merkle trees using SHA2-256.

Public-key certificates, signatures, and ephemeral Diffie-Hellman key exchanges all rely on elliptic curves (except for the encryption of ledger secrets shared between nodes and member recovery shares, which uses `RSA OAEP <https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding>`_). The supported curves are listed in `crypto/curve.h`:

    .. literalinclude:: ../../src/crypto/curve.h
        :language: cpp
        :start-after: SNIPPET_START: supported_curves
        :end-before: SNIPPET_END: supported_curves

The ``service_identity_curve_choice`` determines the curve used by CCF for the service and node identities. User and member certificates do not need to match this, and can be created on any supported curve.