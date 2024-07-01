Networking
==========

HTTP 
----

All RPC interfaces for a given node (see :ref:`operations/configuration:``rpc_interfaces```) currently support HTTP/1.1. A specific RPC interface can also support HTTP/2 by setting the ``"app_protocol"`` configuration entry to ``"HTTP2"`` for that interface.

.. warning:: Support for HTTP/2 is currently experimental (e.g. only a single stream per session is supported). See https://github.com/microsoft/CCF/issues/3342 for progress updates.

Configuration
~~~~~~~~~~~~~

Operators can cap the size of client HTTP requests (body and header) for each RPC interface in the :ref:`operations/configuration:``http_configuration``` configuration section. These configuration entries are optional and have sensible default values. 

If a client HTTP request breaches any of these values, the client is returned a `413 <https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/413>`_ or `431 <https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/431>`_ HTTP error and the session is automatically closed by the CCF node.
