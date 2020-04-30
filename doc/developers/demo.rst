End-to-end demo
===============

This document explains how the Python testing infrastructure is used to run a complete end-to-end test of CCF.

The script ``tests/e2e_scenarios.py`` reads a test scenario from json. This json file can specify which app the network should run, how many nodes it should create, and the list of transactions to run. ``tests/simple_logging_scenario.json`` is an example scenario file showing the expected format:

.. literalinclude:: ../../tests/simple_logging_scenario.json
    :language: json

To see how this is run in the main test suite, look at the `Test command` used by CTest:

.. code-block:: bash

    $ cd build
    $ ctest -VV -R end_to_end_scenario -N

    ...
    42: Test command: /usr/bin/unbuffer "python3" "/data/src/CCF/tests/e2e_scenarios.py" "-b" "." "--label" "end_to_end_scenario" "-l" "info" "-g" "/data/src/CCF/src/runtime_config/gov.lua" "--scenario" "/data/src/CCF/tests/simple_logging_scenario.json"
    42: Environment variables:
    42:  PYTHONPATH=/data/src/CCF/tests

To run manually with your own scenario:

.. code-block:: bash

    $ cd build
    $ ./tests.sh -N                           # Creates Python venv
    $ source env/bin/activate                 # Activates venv
    $ export PYTHONPATH=/data/src/CCF/tests   # Makes Python test infra importable
    $ python ../tests/e2e_scenarios.py --scenario path/to/scenario.json

This first loads the scenario from the given json file, extracting setup fields:

.. literalinclude:: ../../tests/e2e_scenarios.py
    :language: python
    :start-after: SNIPPET_START: parsing
    :end-before: SNIPPET_END: parsing
    :dedent: 2

Given the above ``scenario.json`` this should create 2 nodes on the local machine running the ``logging`` example app. The script then creates the requested CCF network:

.. literalinclude:: ../../tests/e2e_scenarios.py
    :language: python
    :start-after: SNIPPET_START: create_network
    :end-before: SNIPPET_END: create_network
    :dedent: 2

Each transaction listed in the scenario is then sent to either the `primary` or a `backup` node. Any ``Write`` transactions (which modify the KV) must be processed by the `primary`. If a ``Write`` transaction is sent to a `backup` it will be forwarded to the `primary`.

The response to each transaction is printed at the ``DEBUG`` logging level, and also compared against the expected result. For instance, given this transaction in the scenario file:

.. code-block:: json

    {
      "method": "users/LOG_record",
      "params": {
        "id": 42,
        "msg": "Hello world"
      },
      "expected": true
    }

There should be a corresponding entry in the Python output, similar to:

.. code-block:: text

    | INFO     | infra.clients:log_request:122 - users/LOG_record {'id': 42, 'msg': 'Hello world'}
    | DEBUG    | infra.clients:log_response:135 - {'status': 200, 'result': True, 'error': None, 'commit': 23, 'term': 2, 'global_commit': 22}

The ``e2e`` test script takes several additional parameters, documented by passing ``-h`` on the command line. To debug a node it may be useful to increase the node's verbosity by altering the ``--log-level`` option [#log_location]_, or to attach a debugger to a node at launch with the ``--debug-nodes`` option. If passed the ``--network-only`` option the script will keep the network alive, rather than closing immediately after transactions have completed, allowing additional transactions to be sent manually.

.. rubric:: Footnotes

.. [#log_location] The log location should be visible in the Python output. By default, node ``N`` will log to files ``out`` and ``err`` in ``CCF/build/workspace/end_to_end_scenario_{N}``

