Logging
=======

To add your own lines to the node's output you should use the ``CCF_APP_*`` macros defined in ``ccf/ds/logger.h``:

.. code-block:: cpp

    #include "ccf/ds/logger.h"

    int x = 5;
    CCF_APP_INFO("x is currently {}", x);

Applications written in JavaScript and TypeScript can produce similar log lines using standard functions ``console.log``, ``console.info``, ``console.warn``, and ``console.error``:

.. code-block:: js

    x = 5
    console.info(`x is ${x}`)

Either approach will produce a line in the node's stdout like::

    2022-07-12T12:34:56.626262Z        0   [info ][app] ../src/my_app/my_app.cpp:42    | x is 5

These logging functions do several things:

- Variable substitution. See `libfmt <https://fmt.dev/latest/>`_ for more details of the formatting syntax used in C++
- Declare the severity of the entry. CCF defines 5 levels (``trace``, ``debug``, ``info``, ``fail``, and ``fatal``), and production nodes will generally ignore entries below ``info``
- Prefix formatted metadata. The produced log line will include a timestamp, the name and line number where the line was produced, and an ``[app]`` tag
- Write without an ECALL. The final write must be handled by the host, so writing directly from the enclave would require an expensive ECALL. Instead these macros will queue writes to a ringbuffer for the host to process, so diagnostic logging should not cause significant performance drops

.. note:: The app's logging entries will be interleaved (line-by-line) with the framework's logging messages. Filter for entries containing ``[app]`` to extract only application log lines.

.. note:: Since these logs are produced during execution, they will generally only appear on a single node and not every replica. They may also log information about uncommitted or re-executed transactions, as they are emitted independently of transaction commit.
