Networking
==========

HTTP 
----

All RPC interfaces for a given node (see :ref:`operations/configuration:``network.rpc_interfaces```) currently support HTTP/1.1. A specific RPC interface can also support HTTP/2 by setting the ``"app_protocol"`` configuration entry to ``"HTTP2"`` for that interface.

HTTP/1.x parsing rejects malformed framing, including empty or whitespace-only ``Transfer-Encoding`` values and invalid control characters in quoted chunk extensions. Malformed requests return ``400 Bad Request`` and the session is closed. Clients should omit ``Transfer-Encoding`` when no transfer coding is used.

.. warning:: HTTP/2 interfaces do not currently support client requests forwarding. Client requests that require forwarding to the primary node will return a `501 <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/501>`_  HTTP error.

Configuration
~~~~~~~~~~~~~

Operators can cap the size of client HTTP requests (body and header) for each RPC interface in the :ref:`operations/configuration:``network.rpc_interfaces.[name].http_configuration``` configuration section. These configuration entries are optional and have sensible default values. 

If a client HTTP request breaches any of these values, the client is returned a `413 <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/413>`_ or `431 <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/431>`_ HTTP error and the session is automatically closed by the CCF node.
