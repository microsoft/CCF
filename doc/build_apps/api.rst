Developer API
=============

A CCF application is composed of the following:

- The :ref:`Application Entry Point <build_apps/api:Application Entry Point>` which creates the application in CCF.
- A collection of :cpp:class:`endpoints <ccf::endpoints::Endpoint>` handling HTTP requests and grouped in a single :cpp:class:`registry <ccf::endpoints::EndpointRegistry>`. An :cpp:class:`endpoint <ccf::endpoints::Endpoint>` reads and writes to the key-value store via the :ref:`Key-Value Store API <build_apps/kv/api:Key-Value Store API>`.
- An optional set of :ref:`JavaScript FFI Plugins <build_apps/api:JavaScript FFI Plugins>` that can be registered to extend the built-in JavaScript API surface.

Application Entry Point
-----------------------

.. doxygenfunction:: ccfapp::make_user_endpoints
   :project: CCF


Application Endpoint Registration
---------------------------------

.. doxygenstruct:: ccf::endpoints::Endpoint
   :project: CCF
   :members:

.. doxygenclass:: ccf::endpoints::EndpointRegistry
   :project: CCF
   :members: install, set_default

.. doxygenclass:: ccf::CommonEndpointRegistry
   :project: CCF
   :members:

.. doxygenstruct:: ccf::EndpointMetricsEntry
   :project: CCF
   :members:

.. doxygenstruct:: ccf::EndpointMetrics
   :project: CCF
   :members:

.. doxygenclass:: ccf::BaseEndpointRegistry
   :project: CCF
   :members:

RPC Context
-----------

.. doxygenclass:: ccf::RpcContext
   :project: CCF
   :members: get_session_context, get_request_body, get_request_query, get_request_path_params, get_request_verb, get_request_path, get_request_headers, get_request_header, get_request_url, set_claims_digest

Authentication
--------------

Policies
~~~~~~~~

.. doxygenvariable:: ccf::empty_auth_policy
   :project: CCF

.. doxygenvariable:: ccf::user_cert_auth_policy
   :project: CCF

.. doxygenvariable:: ccf::user_signature_auth_policy
   :project: CCF

.. doxygenvariable:: ccf::jwt_auth_policy
   :project: CCF

Identities
~~~~~~~~~~

.. doxygenstruct:: ccf::UserCertAuthnIdentity
   :project: CCF
   :members:

.. doxygenstruct:: ccf::JwtAuthnIdentity
   :project: CCF
   :members:

.. doxygenstruct:: ccf::UserSignatureAuthnIdentity
   :project: CCF
   :members:

Supporting Types
----------------

.. doxygenenum:: ccf::TxStatus
   :project: CCF

.. doxygentypedef:: ccf::View
   :project: CCF
   
.. doxygentypedef:: ccf::SeqNo
   :project: CCF
   
.. doxygenstruct:: ccf::TxID
   :project: CCF
   
.. doxygenenum:: ccf::ApiResult
   :project: CCF
  

Historical Queries
------------------

.. doxygenfunction:: ccf::historical::adapter_v3
   :project: CCF

.. doxygenclass:: ccf::historical::AbstractStateCache
   :project: CCF
   :members: set_default_expiry_duration, get_state_at, get_store_at, get_store_range, drop_cached_states

.. doxygenstruct:: ccf::historical::State
   :project: CCF
   :members:

.. doxygenclass:: ccf::Receipt
   :project: CCF
   :members:

Indexing
--------

.. doxygenclass:: ccf::indexing::Strategy
   :project: CCF
   :members:

.. doxygenclass:: ccf::indexing::strategies::SeqnosByKey_Bucketed_Untyped
   :project: CCF
   :members:

JavaScript FFI Plugins
----------------------

.. doxygenfunction:: ccfapp::get_js_plugins
   :project: CCF
