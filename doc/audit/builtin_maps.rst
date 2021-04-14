Built-in Maps
=============

`public:ccf.gov.members.certs`
------------------------------

This table contains the certificates of all members in the consortium.

Key
~~~

Member ID: SHA-256 digest of the member certificate, represented as a hex-encoded string.

Value
~~~~~

Member certificate, represented as a PEM-encoded string.

`public:ccf.gov.members.encryption_public_keys`
-----------------------------------------------

This table contains the public keys submitted by members for CCF to encrypt their recovery share with.

Key
~~~

Member ID: SHA-256 digest of the member certificate, represented as a hex-encoded string.

Value
~~~~~

Member public encryption key, represented as a PEM-encoded string.

`public:ccf.gov.members.info`
-----------------------------

Member status and auxiliary information.

Key
~~~

Member ID: SHA-256 digest of the member certificate, represented as a hex-encoded string.

Value
~~~~~

.. doxygenstruct:: ccf::MemberDetails
   :project: CCF
   :members:

.. doxygenenum:: ccf::MemberStatus
   :project: CCF

Represented as JSON.

`public:ccf.gov.members.acks`
-----------------------------

Member acknowledgements of the ledger state: signatures over the Merkle root at a particular sequence number.

Key
~~~

Member ID: SHA-256 digest of the member certificate, represented as a hex-encoded string.

Value
~~~~~

.. doxygenstruct:: ccf::MemberAck
   :project: CCF
   :members:

.. doxygenstruct:: ccf::StateDigest
   :project: CCF
   :members:

.. doxygenstruct:: ccf::SignedReq
   :project: CCF
   :members:

Represented as JSON.

`public:ccf.gov.users.certs`
----------------------------

This table contains the certificates of all users.

Key
~~~

User ID: SHA-256 digest of the user certificate, represented as a hex-encoded string.

Value
~~~~~

User certificate, represented as a PEM-encoded string.

`public:ccf.gov.users.info`
---------------------------

User auxiliary information.

Key
~~~

User ID: SHA-256 digest of the user certificate, represented as a hex-encoded string.

Value
~~~~~

.. doxygenstruct:: ccf::UserDetails
   :project: CCF
   :members:

Represented as JSON.

`public:ccf.gov.nodes.info`
---------------------------

Identity and status of participant nodes.

Key
~~~

Node ID: SHA-256 digest of the node public key, represented as a hex-encoded string.

Value
~~~~~

.. doxygenstruct:: ccf::NodeInfo
   :project: CCF
   :members:

.. doxygenenum:: ccf::NodeStatus
   :project: CCF
   :members:

.. doxygenstruct:: ccf::NodeInfoNetwork
   :project: CCF
   :members:

.. doxygenstruct:: ccf::QuoteInfo
   :project: CCF
   :members:

.. doxygenenum:: ccf::QuoteFormat
   :project: CCF
   :members:

Represented as JSON.

`public:ccf.gov.nodes.code_ids`
-------------------------------

This table contains all the versions of the code allowed to join the current network.

Key
~~~

base64 string representation of MRENCLAVE

Value
~~~~~

.. doxygenenum:: ccf::CodeStatus
   :project: CCF

Example
~~~~~~~

.. list-table::
   :header-rows: 1

   * - Code ID
     - Status
   * - `cae46d1...bb908b64e`
     - `ALLOWED_TO_JOIN`

`public:ccf.gov.service.info`
-----------------------------

Service identity and status.

Key
~~~

Sentinel value 0, represented as a little-endian 64-bit unsigned integer.

Value
~~~~~

.. doxygenstruct:: ccf::ServiceInfo
   :project: CCF
   :members:

Represented as JSON.

`public:ccf.gov.service.config`
-------------------------------

Service configuration.

Key
~~~

Sentinel value 0, represented as a little-endian 64-bit unsigned integer.

Value
~~~~~

.. doxygenstruct:: ccf::ServiceConfiguration
   :project: CCF
   :members:

Represented as JSON.

`public:ccf.gov.proposals`
--------------------------

Governance proposals.

Key
~~~

Proposal ID: SHA-256 digest of the proposal and store state observed during its creation, represented as a hex-encoded string.

Value
~~~~~

Proposal as submitted (body of proposal request), as a raw buffer.

`public:ccf.gov.proposals_info`
-------------------------------

Status, proposer ID and ballots attached to a proposal.

Key
~~~

Proposal ID: SHA-256 digest of the proposal and store state observed during its creation, represented as a hex-encoded string.

Value
~~~~~

.. doxygenstruct:: ccf::jsgov::ProposalInfoDetails
   :project: CCF
   :members:

.. doxygenenum:: ccf::ProposalState
   :project: CCF
   :members:

Represented as JSON.

`public:ccf.gov.modules`
------------------------

JavaScript modules, accessible by JavaScript endpoint functions.

Key
~~~

Module name as a string.

Value
~~~~~~

Contents of the module as a string.

`public:ccf.gov.endpoints`
--------------------------

JavaScript endpoint definitions.

Key
~~~

.. doxygenstruct:: ccf::endpoints::EndpointKey
   :project: CCF
   :members:

Represented as JSON.

Value
~~~~~~

.. doxygenstruct:: ccf::endpoints::EndpointProperties
   :project: CCF
   :members:

.. doxygenenum:: ccf::endpoints::Mode
   :project: CCF

.. doxygenenum:: ccf::endpoints::ForwardingRequired
   :project: CCF

.. doxygenenum:: ccf::endpoints::ExecuteOutsideConsensus
   :project: CCF

Represented as JSON.

`public:ccf.gov.tls.ca_cert_bundles`
------------------------------------

`public:ccf.gov.jwt.issuers`
----------------------------

`public:ccf.gov.jwt.public_signing_keys`
----------------------------------------

`public:ccf.gov.jwt.public_signing_key_issuer`
----------------------------------------------