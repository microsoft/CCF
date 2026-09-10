JavaScript Runtime Options
==========================

We use QuickJS JavaScript Engine for JavaScript execution. QuickJS runtime options can be updated with a proposal. A sample proposal would look like:

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_js_runtime_options",
          "args": {
            "max_heap_bytes": 1024,
            "max_stack_bytes": 1024,
            "max_execution_time_ms": 1200,
            "log_exception_details": false,
            "return_exception_details": false
          }
        }
      ]
    }

Default values are ``max_heap_bytes = 100 * 1024 * 1024``, ``max_stack_bytes = 1024 * 1024``, ``max_execution_time_ms = 5000``, ``log_exception_details = false``, ``return_exception_details = false``, and ``max_cached_interpreters = 10``.

For application requests, these limits cover loading and initialising the
entry module and its imports, calling the endpoint handler, nested JavaScript
execution such as ``eval()`` and the ``Function`` constructor, and any
JavaScript invoked while converting the handler's response.

The execution time limit is enforced by QuickJS interrupt checks while it
executes bytecode. QuickJS does not perform these interrupt checks while
parsing or compiling JavaScript source. Consequently, source compilation,
including compilation performed by ``eval()`` or the ``Function`` constructor,
is constrained by the heap and stack limits but not by
``max_execution_time_ms``. CCF precompiles application modules when installing
an application by default, so this exception normally applies at application
installation rather than while handling a request. Disabling the bytecode
cache causes module source compilation to occur while loading the first
request in each interpreter, where the same exception applies.
