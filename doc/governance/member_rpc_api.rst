Member RPC API
==============

Member RPCs are exposed under the ``/gov`` prefix. Many require COSE
authentication, with the payload signed by a member identity. Others provide
public read access to governance state. OpenAPI has no security scheme for
authentication carried in a signed request body, so COSE authentication is
represented by the ``application/cose`` request body rather than an operation
security requirement.

Omitting the ``api-version`` query parameter, or passing
``api-version=latest``, selects the API implemented by the running CCF build.
This is a moving API: its behaviour and generated OpenAPI document are pinned
by the CCF build, but older revisions of the document are not necessarily
served by future builds.

Dated API versions are frozen compatibility contracts while they remain
supported. The current and dated API documents are listed below:

.. toctree::

   gov_api_schemas/latest
   gov_api_schemas/2024-07-01
   gov_api_schemas/2023-06-01-preview
