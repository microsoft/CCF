Member RPC API
==============

As well as the following methods, :ref:`users/rpc_api:Common Methods` are also available to members.

POST /gov/ack/update_state_digest
---------------------------------

Get the current state digest. This is signed to indicate member liveness.

.. literalinclude:: ../schemas/ack/update_state_digest_POST_result.json
    :language: json

POST /gov/ack
-------------

Sign the current state digest to indicate member liveness

.. literalinclude:: ../schemas/ack_POST_params.json
    :language: json
.. literalinclude:: ../schemas/ack_POST_result.json
    :language: json

POST /gov/proposals/{proposal_id}/complete
------------------------------------------

.. literalinclude:: ../schemas/proposals/{proposal_id}/complete_POST_result.json
    :language: json

POST /gov/proposals
-------------------

Create a new proposal

.. literalinclude:: ../schemas/proposals_POST_params.json
    :language: json
.. literalinclude:: ../schemas/proposals_POST_result.json
    :language: json

GET /gov/proposals/{proposal_id}
--------------------------------

Get an existing proposal

.. literalinclude:: ../schemas/proposals/{proposal_id}_GET_result.json
    :language: json
    
POST /gov/proposals/{proposal_id}/withdraw
------------------------------------------

Withdraw an existing proposal (only available to proposer)

.. literalinclude:: ../schemas/proposals/{proposal_id}/withdraw_POST_result.json
    :language: json

POST /gov/proposals/{proposal_id}/votes
---------------------------------------

Submit vote ballot (for or against) an existing proposal

.. literalinclude:: ../schemas/proposals/{proposal_id}/votes_POST_params.json
    :language: json
.. literalinclude:: ../schemas/proposals/{proposal_id}/votes_POST_result.json
    :language: json

GET /gov/proposals/{proposal_id}/votes/{member_id}
--------------------------------------------------

Retrieve any member's ballot on an existing proposal

.. literalinclude:: ../schemas/proposals/{proposal_id}/votes/{member_id}_GET_result.json
    :language: json

GET /gov/query
--------------

Run an arbitrary read-only query on the current state

.. literalinclude:: ../schemas/query_POST_params.json
    :language: json
.. literalinclude:: ../schemas/query_POST_result.json
    :language: json

GET /gov/read
-------------

Read a single value from a table

.. literalinclude:: ../schemas/read_POST_params.json
    :language: json
.. literalinclude:: ../schemas/read_POST_result.json
    :language: json

GET /gov/recovery_share
-----------------------

Retrieve encrypted recovery share of current member

.. literalinclude:: ../schemas/recovery_share_GET_result.json
    :language: json

POST /gov/recovery_share/submit
-------------------------------

Submit recovery share of current member

.. literalinclude:: ../schemas/recovery_share/submit_POST_params.json
    :language: json
.. literalinclude:: ../schemas/recovery_share/submit_POST_result.json
    :language: json