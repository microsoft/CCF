Node Output
===========

By default node output is written to ``stdout`` and to ``stderr`` and can be handled accordingly.

To add your own lines to this output you should use the macros defined in ``ds/logger.h``:

.. code-block:: cpp

    int x = 5;
    LOG_INFO_FMT("x is currently {}", x);

These macros do several things:

- Variable substition. The example above will produce a message of "x is currently 5". See `libfmt <https://fmt.dev/latest/>`_ for more details of the formatting syntax.
- Declare the severity of the entry. CCF defines 5 levels (``trace``, ``debug``, ``info``, ``fail``, and ``fatal``), and production nodes will generally ignore entries below a specified severity
- Prefix formatted metadata. The produced log line will include a timestamp and the name and line number where the line was produced
- Write without an ECALL. The final write must be handled by the host, so writing directly from the enclave would require an expensive ECALL. Instead these macros will queue writes to a ringbuffer for the host to process, so diagnostic logging should not cause significant performance drops

Note that your app's logging entries will be interleaved (line-by-line) with the framework's logging messages, so you may want to prefix your app's entries so they can be more easily distinguished.

JSON Formatting
---------------

There is an option to generate machine-readable logs for monitoring. To enable this pass `--json-format-json` when creating a node (in either ``start`` or ``join`` mode). The generated logs will be in JSON format as displayed below.

.. code-block:: json

    {
        "e_ts": "2019-09-02T14:47:24.589386Z",
        "file": "../src/consensus/raft/raft.h",
        "h_ts": "2019-09-02T14:47:24.589384Z",
        "level": "info",
        "msg": "Deserialising signature at 24\n",
        "number": 651
    }

- ``e_ts`` is the ISO 8601 UTC timestamp of the log if logged inside the enclave (field will be missing if line was logged on the host side)
- ``h_ts`` is the ISO 8601 UTC timestamp of the log when logged on the host side
- ``file`` is the file the log originated from
- ``number`` is the line number in the file the log originated from
- ``level`` is the level of the log message [info, debug, trace, fail, fatal]
- ``msg`` is the log message