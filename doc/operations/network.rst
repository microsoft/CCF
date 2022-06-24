Network
=======

HTTP Configuration
------------------

Operators can cap the size of client HTTP requests (body and header) for each RPC interface in the ``network.rpc_interfaces.<interface_name>.http_configuration`` :doc:`configuration section </operations/configuration>`. These configuration entries are optional and have sensible default values. 

If a client HTTP request breaches any of these values, the client is returned a `413 <https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/413>`_ or `431 <https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/431>`_ HTTP error and the session is automatically closed by the CCF node.
