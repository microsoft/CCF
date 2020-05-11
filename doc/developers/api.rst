Developer API
=============

A CCF application is composed of the following:

- An application entry point: registers the application in CCF as a UserRpcFrontend.
- A collection of Handlers, grouped in a single HandlerRegistry.

Application Entry Point
-----------------------

.. doxygenfunction:: ccfapp::get_rpc_handler
   :project: CCF

.. doxygenclass:: ccf::UserRpcFrontend
   :project: CCF
   :members:

Application RPC Handlers
------------------------

Handler Registry
~~~~~~~~~~~~~~~~

.. doxygenclass:: ccf::HandlerRegistry
   :project: CCF

Handler
~~~~~~~

.. doxygenstruct:: ccf::HandlerRegistry::Handler
   :project: CCF
   :members:
