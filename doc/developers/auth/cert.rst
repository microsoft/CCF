Certificate Authentication
==========================

CCF's primary authentication mechanism relies on users specifying their certificate and private key in the TLS handshake (e.g. using the ``--key`` and ``--cert`` argument to ``curl``).

Users should have previously been trusted by the consortium of members for them to use this authentication mechanism (see :ref:`members/open_network.html:Adding Users`). 

This can be disabled for a specific application endpoint, via the ``set_require_client_identity`` property. If certificate authentication is disabled, the application should authenticate and authorise users based on other mechanisms (e.g. :doc:`/developers/auth/jwt`).
