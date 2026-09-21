Latest
======

This moving API is selected by omitting the ``api-version`` query parameter or
by passing ``api-version=latest`` to endpoints under the ``/gov`` prefix.
``latest`` does not pin a compatibility contract: it always selects the API
implemented by the running CCF build.

.. openapi:: ../../schemas/gov_openapi.json
