Developer API
=============

A CCF application is composed of the following:

- The :ref:`Application Entry Point <build_apps/api:Application Entry Point>` which creates the application in CCF.
- A collection of :cpp:class:`endpoints <ccf::endpoints::Endpoint>` handling HTTP requests and grouped in a single :cpp:class:`registry <ccf::endpoints::EndpointRegistry>`. An :cpp:class:`endpoint <ccf::endpoints::Endpoint>` reads and writes to the key-value store via the :ref:`Key-Value Store API <build_apps/kv/api:Key-Value Store API>`.

Application Entry Point
-----------------------

.. doxygenfunction:: ccf::make_user_endpoints
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

.. doxygenvariable:: ccf::member_cert_auth_policy
   :project: CCF

.. doxygenvariable:: ccf::any_cert_auth_policy
   :project: CCF

.. doxygenvariable:: ccf::member_cose_sign1_auth_policy
   :project: CCF

.. doxygenvariable:: ccf::user_cose_sign1_auth_policy
   :project: CCF

.. doxygenvariable:: ccf::jwt_auth_policy
   :project: CCF

.. doxygenclass:: ccf::TypedUserCOSESign1AuthnPolicy
   :project: CCF

Identities
~~~~~~~~~~

.. doxygenstruct:: ccf::UserCertAuthnIdentity
   :project: CCF
   :members:

.. doxygenstruct:: ccf::MemberCertAuthnIdentity
   :project: CCF
   :members:

.. doxygenstruct:: ccf::AnyCertAuthnIdentity
   :project: CCF
   :members:

.. doxygenstruct:: ccf::UserCOSESign1AuthnIdentity
   :project: CCF
   :members:

.. doxygenstruct:: ccf::MemberCOSESign1AuthnIdentity
   :project: CCF
   :members:

.. doxygenstruct:: ccf::JwtAuthnIdentity
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
   :members: set_default_expiry_duration, set_soft_cache_limit, get_state_at, get_store_at, get_store_range, drop_cached_states

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

HTTP Entity Tags Matching
-------------------------

.. doxygenclass:: ccf::http::Matcher
   :project: CCF
   :members:

HTTP Accept Header Matching
---------------------------

.. doxygenstruct:: ccf::http::AcceptHeaderField
   :project: CCF
   :members:

.. doxygenfunction:: ccf::http::parse_accept_header
   :project: CCF

COSE
----

.. doxygenstruct:: ccf::cose::edit::pos::InArray
   :project: CCF

.. doxygenstruct:: ccf::cose::edit::pos::AtKey
   :project: CCF
   :members:

.. doxygentypedef:: ccf::cose::edit::pos::Type
   :project: CCF

.. doxygenfunction:: ccf::cose::edit::set_unprotected_header
   :project: CCF