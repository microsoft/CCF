Logging
=======

.. note:: When using CFT consensus, only the primary node will display log messages written by the application.

To add your own lines to the node's output you should use the macros defined in ``ds/logger.h``:

.. code-block:: cpp

    #include "ds/logger.h"

    int x = 5;
    LOG_INFO_FMT("x is currently {}", x);

These macros do several things:

- Variable substition. The example above will produce a message of "x is currently 5". See `libfmt <https://fmt.dev/latest/>`_ for more details of the formatting syntax.
- Declare the severity of the entry. CCF defines 5 levels (``trace``, ``debug``, ``info``, ``fail``, and ``fatal``), and production nodes will generally ignore entries below a specified severity
- Prefix formatted metadata. The produced log line will include a timestamp and the name and line number where the line was produced
- Write without an ECALL. The final write must be handled by the host, so writing directly from the enclave would require an expensive ECALL. Instead these macros will queue writes to a ringbuffer for the host to process, so diagnostic logging should not cause significant performance drops

Note that your app's logging entries will be interleaved (line-by-line) with the framework's logging messages, so you may want to prefix your app's entries so they can be more easily distinguished.
