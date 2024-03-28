User Authentication
===================

Each endpoint in CCF declares how callers should be authenticated, listing potentially multiple policies.
Each request to this endpoint will first be checked by these policies in the order they are specified, and
the handler will only be invoked if at least one of these policies accepts the request. The identity found
by this check can then be accessed by the handler to make further authorization decisions. CCF provides
some authentication policies by default, and additional custom policies can be defined in C++.

CCF provides support for two common user authentication schemes:

.. toctree::
  :maxdepth: 1

  jwt
  cert
