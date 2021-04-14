Built-in Maps
=============

`public:ccf.gov.`
-----------------

`certs`
~~~~~~~

X509 certificates of all members in the consortium.

``Key`` Member ID: SHA-256 digest of the member certificate, represented as a hex-encoded string.

``Value`` Member certificate, represented as a PEM-encoded string.

`encryption_public_keys`
~~~~~~~~~~~~~~~~~~~~~~~~

Public encryption keys submitted by members to the network. The recovery share for each member is encrypted by the key they have submitted.

``Key`` Member ID: SHA-256 digest of the member certificate, represented as a hex-encoded string.

``Value`` Member public encryption key, represented as a PEM-encoded string.

`members.info`
~~~~~~~~~~~~~~

Participation status and auxiliary information attached to a member.

``Key`` Member ID: SHA-256 digest of the member's X509 certificate, represented as a hex-encoded string.

``Value`` Represented as JSON.

.. doxygenstruct:: ccf::MemberDetails
   :project: CCF
   :members:

.. doxygenenum:: ccf::MemberStatus
   :project: CCF

`members.acks`
~~~~~~~~~~~~~~

Member acknowledgements of the ledger state, each containing a signature over the Merkle root at a particular sequence number.

``Key`` Member ID: SHA-256 digest of the member certificate, represented as a hex-encoded string.

``Value`` Represented as JSON.

.. doxygenstruct:: ccf::MemberAck
   :project: CCF
   :members:

.. doxygenstruct:: ccf::StateDigest
   :project: CCF
   :members:

.. doxygenstruct:: ccf::SignedReq
   :project: CCF
   :members:

`users.certs`
~~~~~~~~~~~~~

X509 certificates of all network users.

``Key`` User ID: SHA-256 digest of the user certificate, represented as a hex-encoded string.

``Value`` User certificate, represented as a PEM-encoded string.

`users.info`
~~~~~~~~~~~~

Auxiliary information attached to a user.

``Key`` User ID: SHA-256 digest of the user certificate, represented as a hex-encoded string.

``Value`` Represented as JSON.

.. doxygenstruct:: ccf::UserDetails
   :project: CCF
   :members:

`nodes.info`
~~~~~~~~~~~~

Identity, status and attestations (endorsed quotes) of the nodes hosting the network.

``Key`` Node ID: SHA-256 digest of the node public key, represented as a hex-encoded string.

``Value`` Represented as JSON.

.. doxygenstruct:: ccf::NodeInfo
   :project: CCF
   :members:

.. doxygenenum:: ccf::NodeStatus
   :project: CCF

.. doxygenstruct:: ccf::NodeInfoNetwork
   :project: CCF
   :members:

.. doxygenstruct:: ccf::QuoteInfo
   :project: CCF
   :members:

.. doxygenenum:: ccf::QuoteFormat
   :project: CCF

`nodes.code_ids`
~~~~~~~~~~~~~~~~

Versions of the code allowed to join the current network.

``Key`` MRENCLAVE, represented as a base64 string.

``Value`` Represented as JSON.

.. doxygenenum:: ccf::CodeStatus
   :project: CCF

``Example``

.. list-table::
   :header-rows: 1

   * - Code ID
     - Status
   * - `cae46d1...bb908b64e`
     - `ALLOWED_TO_JOIN`

`service.info`
~~~~~~~~~~~~~~

Service identity and status.

``Key`` Sentinel value 0, represented as a little-endian 64-bit unsigned integer.

``Value`` Represented as JSON.

.. doxygenstruct:: ccf::ServiceInfo
   :project: CCF
   :members:

`service.config`
~~~~~~~~~~~~~~~~

Service configuration.

``Key`` Sentinel value 0, represented as a little-endian 64-bit unsigned integer.

``Value`` Represented as JSON.

.. doxygenstruct:: ccf::ServiceConfiguration
   :project: CCF
   :members:

`proposals`
~~~~~~~~~~~

Governance proposals.

``Key`` Proposal ID: SHA-256 digest of the proposal and store state observed during its creation, represented as a hex-encoded string.

``Value`` Proposal as submitted (body of proposal request), as a raw buffer.

`proposals_info`
~~~~~~~~~~~~~~~~

Status, proposer ID and ballots attached to a proposal.

``Key`` Proposal ID: SHA-256 digest of the proposal and store state observed during its creation, represented as a hex-encoded string.

``Value`` Represented as JSON.

.. doxygenstruct:: ccf::jsgov::ProposalInfoDetails
   :project: CCF
   :members:

.. doxygenenum:: ccf::ProposalState
   :project: CCF

`modules`
~~~~~~~~~

JavaScript modules, accessible by JavaScript endpoint functions.

``Key`` Module name as a string.

``Value`` Contents of the module as a string.

`endpoints`
~~~~~~~~~~~

JavaScript endpoint definitions.

``Key`` Represented as JSON.

.. doxygenstruct:: ccf::endpoints::EndpointKey
   :project: CCF
   :members:

``Value`` Represented as JSON.

.. doxygenstruct:: ccf::endpoints::EndpointProperties
   :project: CCF
   :members:

.. doxygenenum:: ccf::endpoints::Mode
   :project: CCF

.. doxygenenum:: ccf::endpoints::ForwardingRequired
   :project: CCF

.. doxygenenum:: ccf::endpoints::ExecuteOutsideConsensus
   :project: CCF

`tls.ca_cert_bundles`
~~~~~~~~~~~~~~~~~~~~~

CA cert bundle storage table, these bundles are used to authenticate connections to JWT issuers.

``Key`` Bundle name, represented as a string.

``Value`` Cert bundle, represented as a PEM-encoded string.

`jwt.issuers`
~~~~~~~~~~~~~

JWT issuers.

``Key`` JWT issuer URL, represented as a string.

``Value`` Represented as JSON.

.. doxygenstruct:: ccf::JwtIssuerMetadata
   :project: CCF
   :members:

.. doxygenenum:: ccf::JwtIssuerKeyFilter
   :project: CCF

.. doxygenstruct:: ccf::JwtIssuerKeyPolicy
   :project: CCF
   :members:

`jwt.public_signing_keys`
~~~~~~~~~~~~~~~~~~~~~~~~~

JWT signing keys.

``Key`` JWT Key ID, represented as a string.

``Value`` JWT public key or certificate, represented as a PEM-encoded string.

`jwt.public_signing_key_issuer`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

JWT signing key to Issuer mapping.

``Key`` JWT Key ID, represented as a string.

``Value`` JWT issuer URL, represented as a string.