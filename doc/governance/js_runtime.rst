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

The same limits apply to governance JavaScript evaluation, including loading
and initialising the module that contains each member ballot's ``vote``
function and the constitution's ``validate``, ``resolve`` and ``apply``
functions, as well as the subsequent calls into those functions. Governance
evaluation applies the configured ``js_runtime_options`` with a
``NO_LOWER_THAN_DEFAULTS`` floor so that operator-provided limits cannot be
lowered below the built-in defaults for governance code.

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

The heap limit includes memory already allocated by the runtime, not just allocations made by the current request. Lowering it below current usage prevents further nonzero allocations, including reuse of existing arena slots. Uncaught out-of-memory errors are reported as request failures; constructing their JavaScript stack traces must not terminate the node.
