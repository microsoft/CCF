Developer API
=============

A CCF application is composed of the following:

- The :ref:`Application Entry Point <developers/api:Application Entry Point>` which registers the application in CCF.
- A collection of :cpp:class:`endpoints <ccf::EndpointRegistry::Endpoint>` handling HTTP requests and grouped in a single :cpp:class:`ccf::EndpointRegistry`. An :cpp:class:`endpoint <ccf::EndpointRegistry::Endpoint>` reads and writes to the key-value store via the :ref:`Key-Value Store API <developers/kv/api:Key-Value Store API>`.

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
   :members: install, set_default

Endpoint
~~~~~~~~

.. doxygenstruct:: ccf::EndpointRegistry::Endpoint
   :project: CCF
   :members:
