Networking
==========

HTTP 
----

All RPC interfaces for a given node (see :ref:`operations/configuration:``network.rpc_interfaces```) currently support HTTP/1.1. A specific RPC interface can also support HTTP/2 by setting the ``"app_protocol"`` configuration entry to ``"HTTP2"`` for that interface.

HTTP/1.1 and HTTP/2 interfaces use the same endpoint redirection strategies. Requests that must execute on another node return HTTP ``307 Temporary Redirect`` with a ``Location`` header. See :doc:`/build_apps/fwd_to_redirect` for resolver configuration and client considerations.

Configuration
~~~~~~~~~~~~~

Operators can cap the size of client HTTP requests (body and header) for each RPC interface in the :ref:`operations/configuration:``network.rpc_interfaces.[name].http_configuration``` configuration section. These configuration entries are optional and have sensible default values. 

If a client HTTP request breaches any of these values, the client is returned a `413 <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/413>`_ or `431 <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/431>`_ HTTP error and the session is automatically closed by the CCF node.
