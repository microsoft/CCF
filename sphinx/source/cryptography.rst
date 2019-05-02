Cryptography
============

Keys
----

Network
```````

A CCF network has a master secret, which is used to derive keys for multiple purposes:

 * A network identity, used in :term:`TLS`
 * A symmetric data key, used to encrypt entries in the ledgers

Node
````

Each CCF node has a key pair. It is used to authenticate the node when it joins the
network, as well as to sign entries committed by a node to the ledger during its
time as leader.

Node keys are also used during recovery, to share recovered network secrets with nodes.

User
````

CCF users have key pairs, used to authenticate their :term:`TLS` connections to the service.
These keys can also be used to sign user commands.

Member
``````

CCF consortium members are identified by key pairs, which are used for authentication when
connecting to the member frontend.

Ephemeral Network Keys
``````````````````````

Each node to node pair establishes a unique symmetric key, using authenticated Diffie Hellman key exchange,
to authenticate ledger replication headers between the nodes. It is also use to encrypt forwarded
write transactions from the followers to the leader.

Algorithms and Curves
---------------------

All symmetric encryption in CCF is done with AES-GCM-256 from `Project Everest <https://project-everest.github.io/>`_.

Asymmetric crypto can be configured to use one of the following implementations:

 * curve25519/ed25519 from `Project Everest <https://project-everest.github.io/>`_.
 * secp384r1 from `mbedTLS <https://tls.mbed.org/>`_.
 * secp256k1 from `mbedTLS <https://tls.mbed.org/>`_.
 * secp256k1 from `bitcoin core <https://github.com/bitcoin-core/secp256k1>`_.
