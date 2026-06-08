Upgrading From Classic API
==========================

Earlier versions of CCF exposed an alternative governance API, now known as the "classic API". The bulk of the endpoints from the classic API have a direct replacement in the new API, as laid out below. Note that the response format may not match exactly. For instance response fields in JSON objects will be ``camelCase`` rather than ``snake_case``, and list responses may now be paged. See the API schema for the new version for a precise description of the response format of each request.

Note that all new APIs require the ``api-version`` query parameter to be set, and will return an error if called without this parameter, or when its value does not match a known API version.

Proposals
---------

.. list-table::
   :align: left

   * - Purpose
     - Create a new proposal
   * - Classic
     - :http:POST:`/gov/proposals`
   * - Replacement
     - :http:POST:`/gov/members/proposals:create`

.. list-table::
   :align: left

   * - Purpose
     - Get single proposal
   * - Classic
     - :http:GET:`/gov/proposals/{proposal_id}`
   * - Replacement
     - :http:GET:`/gov/members/proposals/{proposalId}`

.. list-table::
   :align: left

   * - Purpose
     - Get all proposals
   * - Classic
     - :http:GET:`/gov/proposals`
   * - Replacement
     - :http:GET:`/gov/members/proposals`

.. list-table::
   :align: left

   * - Purpose
     - Get actions of proposal
   * - Classic
     - :http:GET:`/gov/proposals/{proposal_id}/actions`
   * - Replacement
     - :http:GET:`/gov/members/proposals/{proposalId}/actions`

.. list-table::
   :align: left

   * - Purpose
     - Withdraw a proposal
   * - Classic
     - :http:POST:`/gov/proposals/{proposal_id}/withdraw`
   * - Replacement
     - :http:POST:`/gov/members/proposals/{proposalId}:withdraw`

Ballots
-------

.. list-table::
   :align: left

   * - Purpose
     - Submit a ballot
   * - Classic
     - :http:POST:`/gov/proposals/{proposal_id}/ballots`
   * - Replacement
     - :http:POST:`/gov/members/proposals/{proposalId}/ballots/{memberId}:submit`

.. list-table::
   :align: left

   * - Purpose
     - Get a ballot
   * - Classic
     - :http:GET:`/gov/proposals/{proposal_id}/ballots/{member_id}`
   * - Replacement
     - :http:GET:`/gov/members/proposals/{proposalId}/ballots/{memberId}`

Member Activation
-----------------

.. note:: The payload casing has changed, ``state_digest`` has become ``stateDigest``.

.. list-table::
   :align: left

   * - Purpose
     - Get a fresh state-digest to ACK
   * - Classic
     - :http:POST:`/gov/ack/update_state_digest`
   * - Replacement
     - :http:POST:`/gov/members/state-digests/{memberId}:update`
   * - Notes
     - Can also retrieve without refreshing, with :http:GET:`/gov/members/state-digests/{memberId}`

.. list-table::
   :align: left

   * - Purpose
     - Submit signed ACK
   * - Classic
     - :http:POST:`/gov/ack`
   * - Replacement
     - :http:POST:`/gov/members/state-digests/{memberId}:ack`

Transaction Status
------------------

.. list-table::
   :align: left

   * - Purpose
     - Get status of single transaction
   * - Classic
     - :http:GET:`/gov/tx`
   * - Replacement
     - :http:GET:`/gov/service/transactions/{transactionId}`
   * - Notes
     - Transaction ID has moved from query parameter to path parameter.

.. list-table::
   :align: left

   * - Purpose
     - Get latest committed transaction
   * - Classic
     - :http:GET:`/gov/commit`
   * - Replacement
     - :http:GET:`/gov/service/transactions/commit`

.. note:: ``/node/tx`` and ``/node/commit`` remain available in the old style, for existing operator code.

Recovery
--------

.. list-table::
   :align: left

   * - Purpose
     - Get encrypted recovery share for a member
   * - Classic
     - :http:GET:`/gov/recovery_share`
   * - Replacement
     - :http:GET:`/gov/recovery/encrypted-shares/{memberId}`
   * - Notes
     - | The new endpoint is unauthenticated and takes the target member ID as a path parameter, where the Classic API required authentication as a member.
       | Since shares are encrypted, they can be safely read by anyone, without authentication.

.. list-table::
   :align: left

   * - Purpose
     - Submit signed recovery share to advance recovery
   * - Classic
     - :http:POST:`/gov/recovery_share`
   * - Replacement
     - :http:POST:`/gov/recovery/members/{memberId}:recover`

Service State
-------------

.. list-table::
   :align: left

   * - Purpose
     - Read details of currently service identity and recovery status
   * - Classic
     - :http:GET:`/gov/kv/service/info`
   * - Replacement
     - :http:GET:`/gov/service/info`

.. list-table::
   :align: left

   * - Purpose
     - Read current constitution
   * - Classic
     - :http:GET:`/gov/kv/constitution`
   * - Replacement
     - :http:GET:`/gov/service/constitution`
   * - Notes
     - The new endpoint returns a ``Content-Type: text/javascript`` response containing the raw constitution, rather than encoding it within a JSON value.

.. list-table::
   :align: left

   * - Purpose
     - Read list of current members
   * - Classic
     - | :http:GET:`/gov/kv/members/certs`
       | :http:GET:`/gov/kv/members/info`
       | :http:GET:`/gov/kv/members/encryption_public_keys`
   * - Replacement
     - :http:GET:`/gov/service/members`
   * - Notes
     - | Single endpoint replaces multiple previous endpoints.
       | Entry for single member is also available at :http:GET:`/gov/service/members/{memberId}`.

.. list-table::
   :align: left

   * - Purpose
     - Read list of current nodes
   * - Classic
     - | :http:GET:`/gov/kv/nodes/endorsed_certificates`
       | :http:GET:`/gov/kv/nodes/info`
   * - Replacement
     - :http:GET:`/gov/service/nodes`
   * - Notes
     - | Single endpoint replaces multiple previous endpoints.
       | Entry for single node is also available at :http:GET:`/gov/service/nodes/{nodeId}`.

.. list-table::
   :align: left

   * - Purpose
     - Establish what attestations are required for a new node to join the service
   * - Classic
     - | :http:GET:`/gov/kv/nodes/code_ids`
       | :http:GET:`/gov/kv/nodes/snp/host_data`
       | :http:GET:`/gov/kv/nodes/snp/uvm_endorsements`
   * - Replacement
     - :http:GET:`/gov/service/join-policy`
   * - Notes
     - | Single endpoint replaces multiple previous endpoints.

.. list-table::
   :align: left

   * - Purpose
     - Read details of currently deployed JavaScript app
   * - Classic
     - :http:GET:`/gov/kv/modules`
   * - Replacement
     - :http:GET:`/gov/service/javascript-app`

.. list-table::
   :align: left

   * - Purpose
     - Read details of accepted JWKs and their issuers
   * - Classic
     - | :http:GET:`/gov/kv/jwt/issuers`
       | ``GET /gov/kv/jwt/public_signing_keys``
   * - Replacement
     - :http:GET:`/gov/service/jwk`
   * - Notes
     - | Single endpoint replaces multiple previous endpoints.
