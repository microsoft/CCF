JavaScript Application
======================

A JavaScript application is a collection of arbitrary JavaScript endpoints that CCF users can call via HTTP requests.
These endpoints can include a variety of JavaScript modules and read and write to CCF's replicated key-value store.
CCF includes a native ``js_generic`` application which can execute JavaScript applications proposed through governance.

The following subpages demonstrate how to build JavaScript applications using modern development tools:

.. toctree::
  :maxdepth: 1

  js_app_ts
  js_app_tsoa

The low-level deployment format for all JavaScript applications in CCF is called `bundle`.
The specification of bundles can be found here:

.. toctree::
  :maxdepth: 1

  js_app_bundle
