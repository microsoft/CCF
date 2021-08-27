Developer API
=============

A CCF application is composed of the following:

- The :ref:`Application Entry Point <build_apps/api:Application Entry Point>` which registers the application in CCF.
- A collection of :cpp:class:`endpoints <ccf::endpoints::Endpoint>` handling HTTP requests and grouped in a single :cpp:class:`registry <ccf::endpoints::EndpointRegistry>`. An :cpp:class:`endpoint <ccf::endpoints::Endpoint>` reads and writes to the key-value store via the :ref:`Key-Value Store API <build_apps/kv/api:Key-Value Store API>`.

Application Entry Point
-----------------------

.. doxygenfunction:: ccfapp::get_rpc_handler
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

.. doxygenclass:: ccf::BaseEndpointRegistry
   :project: CCF
   :members:

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

.. doxygenfunction:: ccf::historical::adapter
   :project: CCF

.. doxygenclass:: ccf::historical::AbstractStateCache
   :project: CCF
   :members: set_default_expiry_duration, get_state_at, get_store_at, get_store_range, drop_request

.. doxygenstruct:: ccf::historical::State
   :project: CCF
   :members:
