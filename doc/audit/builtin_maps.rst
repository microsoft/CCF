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

Represented as a JSON string.

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

Represented as a JSON string.

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

User status and auxiliary information.

Key
~~~

User ID: SHA-256 digest of the user certificate, represented as a hex-encoded string.

Value
~~~~~

.. doxygenstruct:: ccf::UserDetails
   :project: CCF
   :members:

Represented as a JSON string.

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

Represented as a JSON string.

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

Sentinel value 0.

Value
~~~~~

.. doxygenstruct:: ccf::ServiceInfo
   :project: CCF
   :members:

Represented as a JSON string.

`public:ccf.gov.service.config`
-------------------------------

Service configuration.

Key
~~~

Sentinel value 0.

Value
~~~~~

.. doxygenstruct:: ccf::ServiceConfiguration
   :project: CCF
   :members:

Represented as a JSON string.

`public:ccf.gov.proposals`
--------------------------

`public:ccf.gov.proposals_info`
-------------------------------

`public:ccf.gov.modules`
------------------------

`public:ccf.gov.endpoints`
--------------------------

`public:ccf.gov.tls.ca_cert_bundles`
------------------------------------

`public:ccf.gov.jwt.issuers`
----------------------------

`public:ccf.gov.jwt.public_signing_keys`
----------------------------------------

`public:ccf.gov.jwt.public_signing_key_issuer`
----------------------------------------------