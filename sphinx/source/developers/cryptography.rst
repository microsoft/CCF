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

Node keys are also used during recovery, to share recovered network secrets between nodes.

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

Algorithms and Curves
---------------------

Authenticated encryption in CCF relies on AES256-GCM. Ledger authentication relies on Merkle trees using SHA2-256. These algorithms are provided by `project Everest <https://project-everest.github.io/>`_.

Public-key certificates, signatures, and ephemeral Diffie-Hellman key exchanges all rely on
elliptic curves. They can be configured to use one of the following implementations:

 * ed25519 from `project Everest <https://project-everest.github.io/>`_.
 * secp384r1 from `mbedTLS <https://tls.mbed.org/>`_.
 * secp256k1 from `bitcoin core <https://github.com/bitcoin-core/secp256k1>`_.
