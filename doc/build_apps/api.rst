Developer API
=============

A CCF application is composed of the following:

- The :ref:`Application Entry Point <build_apps/api:Application Entry Point>` which registers the application in CCF.
- A collection of :cpp:class:`endpoints <ccf::EndpointRegistry::Endpoint>` handling HTTP requests and grouped in a single :cpp:class:`ccf::EndpointRegistry`. An :cpp:class:`endpoint <ccf::EndpointRegistry::Endpoint>` reads and writes to the key-value store via the :ref:`Key-Value Store API <build_apps/kv/api:Key-Value Store API>`.

Application Entry Point
-----------------------

.. doxygenclass:: ccf::UserRpcFrontend
   :project: CCF
   :members:

.. doxygenfunction:: ccfapp::get_rpc_handler
   :project: CCF


Application Endpoint Registration
---------------------------------

Endpoint Registry
~~~~~~~~~~~~~~~~~

.. doxygenclass:: ccf::EndpointRegistry
   :project: CCF
   :members: install, set_default, empty_auth_policy, user_cert_auth_policy, user_signature_auth_policy, jwt_auth_policy

Endpoint
~~~~~~~~

.. doxygenstruct:: ccf::EndpointRegistry::Endpoint
   :project: CCF
   :members:

Authentication Identities
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenstruct:: ccf::UserCertAuthnIdentity
   :project: CCF
   :members:

.. doxygenstruct:: ccf::JwtAuthnIdentity
   :project: CCF
   :members:

.. doxygenstruct:: ccf::UserSignatureAuthnIdentity
   :project: CCF
   :members: