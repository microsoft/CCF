Python Client
=============

.. warning:: As of CCF 2.0, the ``ccf`` Python package no longer provides utilities to issue requests to a running CCF service. This is because CCF supports widely-used client-server protocols (TLS, HTTP) that should be already be provided by libraries for all programming languages. The ``ccf`` Python package can still be used to parse and audit the ledger and snapshot files (see :doc:`/audit/python_library`).