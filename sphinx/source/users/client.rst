Client
======

Clients submit their commands to CCF as HTTP requests. These can be sent by standard tools, for example via curl on the command line:

.. TODO:: Add a basic HTTP example

All of the tests built on CCF's Python infrastructure use `Python Requests <https://requests.readthedocs.io/en/master/>`_ by default, but can be switched to a ``curl``-based client (printing each command to stdout) by running them with environment variable ``CURL_CLIENT`` set.

Signing
-------

In some situations CCF requires signed requests, for example for member votes. The signing scheme is compatible with the `IETF HTTP Signatures draft RFC <https://tools.ietf.org/html/draft-cavage-http-signatures-12>`_. We provide a wrapper script (``scurl.sh``) around curl to submit signed requests from the command line:

.. TODO:: Add signed HTTP example

These commands can also be signed and transmitted by external libraries. For example, the CCF test infrastructure uses `an auth plugin <https://pypi.org/project/requests-http-signature/>`_ for Python `Requests <https://requests.readthedocs.io/en/master/>`_.

Python Client
-------------

Available as part of CCF Python infra: https://github.com/microsoft/CCF/blob/master/tests/infra/clients.py.

The ``Checker`` class in `ccf.py <https://github.com/microsoft/CCF/blob/master/tests/infra/ccf.py>`_ can be used as a wrapper to wait for requests to be committed.

.. note:: CCF originally accepted user commands as framed JSON-RPC over TCP. Support for this format will be dropped in v0.8. If you still need this in the interim then it can be enabled by passing ``-DFTCP=ON`` to cmake. The Python infra client will send messages in this framed format if run with environment variable ``FTCP`` set.