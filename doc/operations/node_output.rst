Node Output
===========

By default node output is written to ``stdout`` and to ``stderr`` and can be handled accordingly.

There is an option to generate machine-readable logs for monitoring. To enable this, set the ``logging.format`` configuration entry to ``"Json"``. The generated logs will be in JSON format as displayed below:

.. code-block:: json

    {
        "e_ts": "2019-09-02T14:47:24.589386Z",
        "file": "../src/consensus/aft/raft.h",
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

See :ref:`this page <build_apps/logging:Logging>` for steps to add application-specific logging, which will have an additional ``tag`` field set to ``app``.