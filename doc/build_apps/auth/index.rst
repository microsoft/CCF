User Authentication
===================

Each endpoint in CCF declares how callers should be authenticated, listing potentially multiple policies.
Each request to this endpoint will first be checked by these policies in the order they are specified, and
the handler will only be invoked if at least one of these policies accepts the request. The identity found
by this check can then be accessed by the handler to make further authorization decisions. CCF provides
some authentication policies by default, and additional custom policies can be defined in :ref:`C++ <build_apps/example_cpp:Authentication>`.

.. note::

   The experimental Rust SDK supports only ``Auth::UserCert`` and
   ``Auth::None``. It does not expose multiple/custom policies, JWT
   authentication or caller-identity access. See :doc:`../rust_api` and the
   authenticated example in :doc:`../example_rust`.

CCF provides support for two common user authentication schemes:

.. toctree::
  :maxdepth: 1

  jwt
  cert
