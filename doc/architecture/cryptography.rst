Cryptography
============

Keys
----

.. tip:: See the :ref:`architecture/cryptography:Summary Diagrams` for a detailed overview of the relationships between cryptographic keys in CCF.

Service
~~~~~~~

A CCF service/network has:

- A service/network identity public-key certificate (``Service Identity Certificate``), used as root of trust for :term:`TLS` server authentication and receipt verification.
- A symmetric data-encryption key (``Ledger Secret``), used to encrypt and integrity protect all transactions/entries in the ledger.

.. note:: The service certificate, associated private key and data-encryption keys are shared by all nodes trusted to join the network.

Node
~~~~

Each CCF node is identified by a public-key certificate (``Node Identity Certificate``) endorsed by an attestation report (``Node Enclave Attestation + Collaterals``). This certificate is used to authenticate the node when it joins the network, and to periodically sign entries (``Ledger Signatures``) committed by the node to the ledger during its time as primary.

Each node also has an encryption public-key (``Node Encryption
Public Key``) used to share ledger secrets between the primary and backups nodes during a :ref:`live ledger rekey <governance/common_member_operations:Updating Recovery Threshold>`.

Member
~~~~~~

Each CCF consortium member is similarly identified by a public-key certificate used for client authentication and command signing. Recovery members also have an encryption public-key (``Member Encryption Public Key``) used to encrypt recovery shares in the ledger.

User
~~~~

Each CCF user is identified by a public-key certificate, used for :term:`TLS` client authentication when they connect to the service. These keys are also used to sign user commands.

Ephemeral Network Keys
~~~~~~~~~~~~~~~~~~~~~~

Each node-to-node pair establishes a symmetric key using an authenticated Diffie Hellman key exchange protocol. This key protects the integrity of consensus message headers exchanged between nodes. It is also use to encrypt forwarded write transactions from the backups to the primary node.

Summary Diagrams
----------------

.. note:: The ":fa:`key`" symbol indicates that the key never leaves the enclave memory, or in the case of the ``Service Identity Private Key`` and ``Ledger Secret`` is only shared between nodes over authenticated TLS.

Identity Keys and Certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following diagram describes the relationships between identity keys of the service/network and nodes. The shared service identity (``Service Identity Certificate``) is the root of trust for the service and is assumed to be trusted by users who can connect to the service over TLS as well as verify the integrity of :ref:`transaction receipts <audit/receipts:Receipts>`.

The primary node periodically signs the root of the Merkle Tree of all transactions (``Ledger Signature``) using its ``Node Identity Private Key`` and records it in the ledger. All public certificates and attestation reports (``Node Enclave Attestation + Collaterals``) are also recorded in the ledger for audit.

.. mermaid::

    flowchart TB
        ServiceCert[fa:fa-scroll Service Identity Certificate] --contains--> ServicePubk[Service Identity Public Key]
        ServicePubk -.- ServicePrivk[fa:fa-key Service Identity Private Key]
        NodePubk[Node Identity Public Key] -.- NodePrivk[fa:fa-key Node Identity Private Key]
        ServiceCert -- recorded in <br> ccf.gov.service.info --> Ledger[(fa:fa-book Ledger)]
        NodeCert[fa:fa-scroll Node Identity Certificate] -- recorded in <br> ccf.gov.nodes.endorsed_certificates --> Ledger
        ServicePrivk -- signs --> NodeCert
        NodePrivk -- signs --> Signature[fa:fa-file-signature Ledger Signatures <br> over Merkle Tree root]
        Signature -- recorded in <br> ccf.internal.signatures --> Ledger
        Attestation[fa:fa-microchip Node Enclave Attestation <br> + Collaterals] -- contains hash of --> NodePubk
        NodeCert -- contains --> NodePubk
        Attestation -- recorded in <br> ccf.gov.nodes.info --> Ledger


Ledger Secrets
~~~~~~~~~~~~~~

The ``Ledger Secret`` symmetric key is used to encrypt and protect the integrity (using AES-GCM) of all write transactions executed by the service and recorded in the ledger.

To be able to recover the ledger (see :doc:`/operations/recovery`), the ledger secret is also encrypted using an ephemeral ``Ledger Secret Wrapping Key`` and the resulting ``Encrypted Ledger Secret`` is recorded in the ledger. The ``Ledger Secret Wrapping Key`` is split into ``k-of-n Recovery Shares`` (with ``k`` the :ref:`service recovery threshold <governance/common_member_operations:Updating Recovery Threshold>` and ``n`` the number of recovery members) and each recovery share is encrypted with the recovery member's encryption public key. The resulting ``Encrypted k-of-n Recovery Shares`` are recorded in the ledger and can then be served to each recovery member by the recovered `public` service, who can then decrypt it (for example, :doc:`by using their encryption private key stored in a HSM</governance/hsm_keys>`) and then submit the decrypted share to the new service.

Since the ``Ledger Secret`` can also be rotated by members (see :ref:`governance/common_member_operations:Rekeying Ledger`), the old ledger secret (``Previous Ledger Secret``) is also encrypted with the new ledger secret and the resulting ``Encrypted Previous Ledger Secret`` is also recorded in the ledger. This allows recovery members to recover the entirety of the historical ledger by simply having access to their `most-recent` recovery shares.

Each node also has an encryption public-key (``Node Encryption
Public Key``) used to share ledger secrets between the primary and backups nodes during a :ref:`live ledger rekey <governance/common_member_operations:Updating Recovery Threshold>`.

.. mermaid::

    flowchart TB
        WrappingKey -- split into --> RecoveryShares{{fa:fa-helicopter k-of-n <br> Recovery Shares}}
        MemberPublicKeys{{fa:fa-users Members Encryption <br> Public Keys}} --key--> F[/encrypts/]
        RecoveryShares --in--> F[/encrypts/] --> EncryptedRecoveryShares{{fa:fa-lock Encrypted k-of-n <br> Recovery Shares}}
        EncryptedRecoveryShares -- recorded in <br> ccf.internal.recovery_shares --> Ledger

        WrappingKey[fa:fa-key Ledger Secret <br> Wrapping Key] --key--> N[/encrypts/]
        LedgerSecret --in--> N[/encrypts/] --> EncryptedLedgerSecret[fa:fa-lock Encrypted <br> Ledger Secret]
        EncryptedLedgerSecret -- recorded in ccf.internal --> Ledger[(fa:fa-book Ledger)]

        PreviousLedgerSecret[fa:fa-key Previous <br> Ledger Secret] --in--> H[/encrypts/] --> EncryptedPreviousLedgerSecret[fa:fa-lock Encrypted Previous <br> Ledger Secret]
        LedgerSecret --key--> H[/encrypts/]
        EncryptedPreviousLedgerSecret -- recorded in <br> ccf.internal.<br>historical_encrypted_ledger_secret --> Ledger

        LedgerSecret[fa:fa-key Ledger <br> Secret] -- "encrypts <br> (AES-GCM)" --> Transactions[fa:fa-lock All CCF Transactions]
        style LedgerSecret stroke:black,stroke-width:3px
        Transactions -- recorded in --> Ledger

        LedgerSecret --in--> K[/encrypts/] --> NodeEncryptedLedgerSecrets{{fa:fa-lock Node Encrypted Ledger Secrets}}
        NodeEncryptionPublicKeys{{Node Encryption <br> Public Keys}} --key--> K[/encrypt/]
        NodeEncryptedLedgerSecrets{{fa:fa-lock Node Encrypted <br> Ledger Secrets}}
        NodeEncryptedLedgerSecrets -- recorded in <br> ccf.internal.<br>encrypted_ledger_secrets --> Ledger


Algorithms and Curves
---------------------

Authenticated encryption in CCF relies on AES256-GCM. Ledger authentication relies on Merkle trees using SHA2-256.

Public-key certificates, signatures, and ephemeral Diffie-Hellman key exchanges all rely on elliptic curves (except for the encryption of ledger secrets shared between nodes and member recovery shares, which uses `RSA OAEP <https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding>`_). The supported curves are listed in `curve.h`:

    .. literalinclude:: ../../include/ccf/crypto/curve.h
        :language: cpp
        :start-after: SNIPPET_START: supported_curves
        :end-before: SNIPPET_END: supported_curves

The ``service_identity_curve_choice`` determines the curve used by CCF for the service and node identities. User and member certificates do not need to match this, and can be created on any supported curve.