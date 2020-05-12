Developer API
=============

A CCF application is composed of the following:

- The :ref:`Application Entry Point <developers/api:Application Entry Point>` which registers the application in CCF.
- A collection of :cpp:class:`ccf::HandlerRegistry::Handler` as endpoints to user HTTP requests and grouped in a single :cpp:class:`ccf::HandlerRegistry`.

Application Entry Point
-----------------------

.. doxygenclass:: ccf::UserRpcFrontend
   :project: CCF
   :members:

.. doxygenfunction:: ccfapp::get_rpc_handler
   :project: CCF


Application RPC Handlers
------------------------

Handler Registry
~~~~~~~~~~~~~~~~

.. doxygenclass:: ccf::HandlerRegistry
   :project: CCF
   :members: install, set_default

Handler
~~~~~~~

.. doxygenstruct:: ccf::HandlerRegistry::Handler
   :project: CCF
   :members:
