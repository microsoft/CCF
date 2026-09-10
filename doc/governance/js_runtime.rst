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

The heap limit includes memory already allocated by the runtime, not just allocations made by the current request. Lowering it below current usage prevents further nonzero allocations, including reuse of existing arena slots. Uncaught out-of-memory errors are reported as request failures; constructing their JavaScript stack traces must not terminate the node.
