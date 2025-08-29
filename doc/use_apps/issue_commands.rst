Issuing Commands
================

Clients communicate with CCF using HTTP requests, over TLS.

For example, to record a message at a specific id with the :doc:`C++ sample logging application </build_apps/example>` using curl:

.. code-block:: bash

    $ cat request.json
    {
      "id": 42,
      "msg": "Hello There"
    }

    $ curl https://<ccf-node-address>/app/log/private --cacert service_cert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @request.json -H "content-type: application/json" -i
    HTTP/1.1 200 OK
    content-length: 5
    content-type: application/json
    x-ms-ccf-transaction-id: 2.23

    true

The HTTP response some CCF commit information in the headers:

- ``"x-ms-ccf-transaction-id"`` indicates the consensus view, and the unique version at which the request was executed, separated by a ``"."``.

The response body (the JSON value ``true``) indicates that the request was executed successfully. For many RPCs this will be a JSON object with more details about the execution result.

Signing
-------

In some situations CCF requires signed requests, for example for member votes. Only one signing scheme is supported as of 4.x:

COSE Sign1
~~~~~~~~~~

CCF accepts signed requests in `COSE Sign1 <https://www.rfc-editor.org/rfc/rfc8152#section-4.2>`_ format.

CCF identifies the signing identity for a request via the SHA-256 digest of its certificate, represented as a hex string.
That value must be set in the ``kid`` protected header. Additional protected headers may be necessary, for example governance endpoints
require setting ``ccf.gov.msg.type``, ``ccf.gov.msg.created_at``, and optionally ``ccf.gov.msg.proposal_id`` on the message types where it applies.

A signing script (``ccf_cose_sign1``) is provided as part of the `ccf Python package <https://pypi.org/project/ccf/>`_. The output can be piped directly into curl, or any other HTTP client.

Commands can also be signed using the `python-cwt <https://github.com/dajiaji/python-cwt/>`_ library, and sent with any standard HTTP library such as `Python HTTPX <https://www.python-httpx.org/>`_.

Idempotence
^^^^^^^^^^^

To make governance commands idempotent, and to prevent potential replay attacks where old signed requests are submitted again, a creation timestamp must be set in the ``ccf.gov.msg.created_at`` protected header parameter.

A fixed-sized window of proposal request digests is kept by CCF, and newly submitted proposal requests must not collide with existing entries nor be older than the median proposal request in the window. The size of the window is defined in :ref:`audit/builtin_maps:``service.config```.

The timestamp must be submitted as a integer number of seconds since Unix epoch (Thursday 1 January 1970 00:00:00 UT).

.. warning:: HTTP request signing could be used in previous versions of CCF, but has been removed as of 4.0, in favour of COSE Sign1.

COSE Schemas
^^^^^^^^^^^^

Each endpoint which requires a COSE signed request requires certain protected headers to be included, and a specific fields to be present in the JSON payload body. These requirements are listed below.

Proposals
"""""""""

Creating a new proposal:

.. list-table::
   :align: left

   * - Operation
     - ``POST /gov/members/proposals:create``
   * - Protected headers
     - | ``ccf.gov.msg.type = proposal``
       | ``ccf.gov.msg.created_at = <creation timestamp>``
   * - Content
     - | { "actions": [...] }
       | See :ref:`governance/proposals:Creating a Proposal` for details

Withdrawing a proposal:

.. list-table::
   :align: left

   * - Operation
     - ``POST /gov/members/proposals/{proposalId}:withdraw``
   * - Protected headers
     - | ``ccf.gov.msg.type = withdrawal``
       | ``ccf.gov.msg.created_at = <creation timestamp>``
       | ``ccf.gov.msg.proposal_id = <proposalId>``
   * - Content
     - *Empty*

Submitting a ballot:

.. list-table::
   :align: left

   * - Operation
     - ``POST /gov/members/proposals/{proposalId}/ballots/{memberId}:submit``
   * - Protected headers
     - | ``ccf.gov.msg.type = ballot``
       | ``ccf.gov.msg.created_at = <creation timestamp>``
       | ``ccf.gov.msg.proposal_id = <proposalId>``
   * - Content
     - | { "ballot": "..." }
       | See :ref:`governance/proposals:Creating a Ballot` for details

ACKs
""""

Updating state digest:

.. list-table::
   :align: left

   * - Operation
     - ``POST /gov/members/state-digests/{memberId}:update``
   * - Protected headers
     - | ``ccf.gov.msg.type = state_digest``
       | ``ccf.gov.msg.created_at = <creation timestamp>``
   * - Content
     - *Empty*

Acking state digest:

.. list-table::
   :align: left

   * - Operation
     - ``POST /gov/members/state-digests/{memberId}:ack``
   * - Protected headers
     - | ``ccf.gov.msg.type = ack``
       | ``ccf.gov.msg.created_at = <creation timestamp>``
   * - Content
     - | { "stateDigest": "<hex digest>" }
       | This should be the object returned by a previous call to ``GET /gov/members/state-digests/{memberId}``

Recovery
""""""""

Submitting recovery share:

.. list-table::
   :align: left

   * - Operation
     - ``POST /gov/recovery/members/{memberId}:recover``
   * - Protected headers
     - | ``ccf.gov.msg.type = encrypted_recovery_share``
       | ``ccf.gov.msg.created_at = <creation timestamp>``
   * - Content
     - { "share": "<base64-encoded decrypted share>" }