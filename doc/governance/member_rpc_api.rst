Member RPC API
==============

Member RPCs are exposed under the ``/gov`` prefix. Many require COSE authentication, with the payload signed by a member identity. Others provide public read access to governance state.
Authentication requirements are not represented in the API schemas below.

Multiple API versions are available, with the versions supported by the current CCF version listed below:

.. toctree::

   gov_api_schemas/2024-07-01
   gov_api_schemas/2023-06-01-preview
