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

Each CCF node is identified by a public-key certificate (``Node Identity Certificate``) endorsed by an attestation report (``Node Attestation + Endorsements``). This certificate is used to authenticate the node when it joins the network, and to periodically sign entries (``Ledger Signatures``) committed by the node to the ledger during its time as primary.

Each node also has an encryption public-key (``Node Encryption Public Key``) used to share ledger secrets between the primary and backups nodes during a :ref:`live ledger rekey <governance/common_member_operations:Updating Recovery Threshold>`.

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

.. note:: A thick border indicates that the key never leaves the TEE-protected memory of the node, or in the case of the ``Service Identity Private Key`` and ``Ledger Secret`` is only shared between nodes over authenticated TLS.

Identity Keys and Certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following diagram describes the relationships between identity keys of the service/network and nodes. The shared :term:`Service Identity` (``Service Identity Certificate``) is the root of trust for the service and is assumed to be trusted by users who can connect to the service over TLS as well as verify the integrity of :ref:`transaction receipts <audit/receipts:Receipts>`.

The primary node periodically signs the root of the Merkle Tree of all transactions (``Ledger Signature``) using its ``Node Identity Private Key`` and records it in the ledger. All public certificates and attestation reports (``Node Attestation + Endorsements``) are also recorded in the ledger for audit.

.. mermaid::

    flowchart TB
        classDef ProtectedKey stroke-width:3px
        ServiceCert[Service Identity Certificate] --contains--> ServicePubk[Service Identity Public Key]
        ServicePubk -.- ServicePrivk[Service Identity Private Key]
        NodePubk[Node Identity Public Key] -.- NodePrivk[Node Identity Private Key]
        class ServicePrivk,NodePrivk ProtectedKey
        ServiceCert -- recorded in ccf.gov.service.info --> Ledger[(Ledger)]
        NodeCert[Node Identity Certificate] -- recorded in ccf.gov.nodes.endorsed_certificates --> Ledger
        ServicePrivk -- signs --> NodeCert
        NodePrivk -- signs --> Signature[Ledger Signatures over Merkle Tree root]
        Signature -- recorded in ccf.internal.signatures --> Ledger
        Attestation[Node Attestation + Endorsements] -- contains hash of --> NodePubk
        NodeCert -- contains --> NodePubk
        Attestation -- recorded in ccf.gov.nodes.info --> Ledger


Ledger Secrets
~~~~~~~~~~~~~~

The ``Ledger Secret`` symmetric key is used to encrypt and protect the integrity (using AES-GCM) of all write transactions executed by the service and recorded in the ledger.

To be able to recover the ledger (see :doc:`/operations/recovery`), the ledger secret is also encrypted using an ephemeral ``Ledger Secret Wrapping Key`` and the resulting ``Encrypted Ledger Secret`` is recorded in the ledger. The ``Ledger Secret Wrapping Key`` is split into ``k-of-n Recovery Shares`` (with ``k`` the :ref:`service recovery threshold <governance/common_member_operations:Updating Recovery Threshold>` and ``n`` the number of recovery members) and each recovery share is encrypted with the recovery member's encryption public key. The resulting ``Encrypted k-of-n Recovery Shares`` are recorded in the ledger and can then be served to each recovery member by the recovered `public` service, who can then decrypt it (for example, :doc:`by using their encryption private key stored in a HSM</governance/hsm_keys>`) and then submit the decrypted share to the new service.

Since the ``Ledger Secret`` can also be rotated by members (see :ref:`governance/common_member_operations:Rekeying Ledger`), the old ledger secret (``Previous Ledger Secret``) is also encrypted with the new ledger secret and the resulting ``Encrypted Previous Ledger Secret`` is also recorded in the ledger. This allows recovery members to recover the entirety of the historical ledger by simply having access to their `most-recent` recovery shares.

Each node also has an encryption public-key (``Node Encryption Public Key``) used to share ledger secrets between the primary and backups nodes during a :ref:`live ledger rekey <governance/common_member_operations:Updating Recovery Threshold>`.

.. mermaid::

    flowchart TB
        classDef ProtectedKey stroke-width:3px
        WrappingKey -- split into --> RecoveryShares{{k-of-n Recovery Shares}}
        MemberPublicKeys{{Members Encryption Public Keys}} --key--> F[/encrypts/]
        RecoveryShares --in--> F[/encrypts/] --> EncryptedRecoveryShares{{Encrypted k-of-n Recovery Shares}}
        EncryptedRecoveryShares -- recorded in ccf.internal.recovery_shares --> Ledger

        WrappingKey[Ledger Secret Wrapping Key] --key--> N[/encrypts/]
        LedgerSecret --in--> N[/encrypts/] --> EncryptedLedgerSecret[Encrypted Ledger Secret]
        EncryptedLedgerSecret -- recorded in ccf.internal --> Ledger[(Ledger)]

        PreviousLedgerSecret[Previous Ledger Secret] --in--> H[/encrypts/] --> EncryptedPreviousLedgerSecret[Encrypted Previous Ledger Secret]
        LedgerSecret --key--> H[/encrypts/]
        EncryptedPreviousLedgerSecret -- recorded in ccf.internal.historical_encrypted_ledger_secret --> Ledger

        LedgerSecret[Ledger Secret] -- "encrypts (AES-GCM)" --> Transactions[All CCF Transactions]
        class WrappingKey,LedgerSecret,PreviousLedgerSecret ProtectedKey
        Transactions -- recorded in --> Ledger

        LedgerSecret --in--> K[/encrypts/] --> NodeEncryptedLedgerSecrets{{Node Encrypted Ledger Secrets}}
        NodeEncryptionPublicKeys{{Node Encryption Public Keys}} --key--> K[/encrypt/]
        NodeEncryptedLedgerSecrets{{Node Encrypted Ledger Secrets}}
        NodeEncryptedLedgerSecrets -- recorded in ccf.internal.encrypted_ledger_secrets --> Ledger


Identity IDs
------------

Node, member, and user IDs default to the existing ``sha256`` format.
Member and user IDs are the hexadecimal SHA-256 fingerprint of the DER certificate.
Node IDs are the hexadecimal SHA-256 fingerprint of the DER SubjectPublicKeyInfo public key.

New identities can instead use a `did:key <https://w3c-ccg.github.io/did-key-spec/>`_ ID, which embeds the multicodec-tagged public key rather than hashing it.
CCF supports compressed P-256, P-384, and P-521 keys and PKCS#1 RSA public keys between 2048 and 16384 bits.
The ``did:key`` specification lists the P-256 and P-384 key types; P-521 and RSA keys use the ``p521-pub`` and ``rsa-pub`` codes from the `multicodec table <https://github.com/multiformats/multicodec/blob/master/table.csv>`_, so other ``did:key`` implementations may not accept them.
Existing authentication and signing algorithm restrictions still apply.

The `did:key identifier syntax <https://w3c-ccg.github.io/did-key-spec/#did-key-identifier-syntax>`_ allows either a base58-btc (``z``) or a base64url (``u``) multibase value.
CCF only accepts and produces the base58-btc (``z``) form, which is the form used by every example in the specification, and rejects the base64url form.
As the specification describes, a ``did:key`` is a deterministic encoding of its public key, and CCF only accepts the ``did:key`` that it would produce from the decoded key.
For example, an EC key must use the compressed point encoding.
Only bare IDs are accepted; DID URLs with fragments, queries, or paths are not identity IDs.

A ``did:key`` is used as it is in an HTTP path, including before an action suffix, as in ``/gov/members/state-digests/did:key:z...:ack``.

Members and users enroll a ``did:key`` by passing it as ``did_key`` to ``set_member`` or ``set_user``; no certificate is stored or required.
The embedded public key is validated when it is enrolled; an ID that is only used to look up an identity is checked for syntax alone.
COSE Sign1 requests use the ``did:key`` as their ``kid`` and are verified with the embedded public key.
Endpoints using TLS client certificate authentication (such as ``user_cert`` or ``member_cert``) also accept any client certificate carrying the enrolled public key, and identify the caller by the enrolled ``did:key``.
The validity period of such a certificate is not checked: governance explicitly grants access by enrolling the identity, and revokes it by removing the identity.

Certificate-based and ``did:key`` enrollments are independent identities, even when they contain the same public key.
CCF does not detect or prevent enrolling the same public key under both ID formats; operators are responsible for deciding whether to do so, and for removing the identity they no longer want.
Each enrollment has its own ID, data, status, and recovery role, and removing one does not affect the other.
If both are enrolled in the same role, TLS client certificate authentication with the enrolled certificate identifies the caller by its certificate fingerprint ID; other certificates carrying the same key identify the caller by its ``did:key``.

See :doc:`/governance/migrating_identity_ids` for the user and member migration procedure.

Upgrade every node before opting in to DID identities.
Upgraded services can mix legacy and DID IDs, but older binaries are not supported in a DID-enabled service.
This option does not change SHA-256 ledger hashes, proposal IDs, receipt formats, attestation bindings, or cryptographic signature algorithms.

See :doc:`/operations/configuration` for node and genesis member configuration, :doc:`/governance/adding_member` and :doc:`/governance/open_network` for enrollment, and :doc:`/use_apps/issue_commands` for COSE signing.

Algorithms and Curves
---------------------

Authenticated encryption in CCF relies on AES256-GCM. Ledger authentication relies on Merkle trees using SHA2-256.

Public-key certificates, signatures, and ephemeral Diffie-Hellman key exchanges all rely on elliptic curves (except for the encryption of ledger secrets shared between nodes and member recovery shares, which uses `RSA OAEP <https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding>`_). The supported curves are listed in `curve.h`:

    .. literalinclude:: ../../include/ccf/crypto/curve.h
        :language: cpp
        :start-after: SNIPPET_START: supported_curves
        :end-before: SNIPPET_END: supported_curves

The ``service_identity_curve_choice`` determines the curve used by CCF for the service and node identities. User and member certificates do not need to match this, and can be created on any supported curve.