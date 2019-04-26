End-to-end demo
===============

This document explains how the Python testing infrastructure is used to run a complete end-to-end test of CCF.

The script ``tests/e2e_scenarios.py`` reads a test scenario from json. This json file can specify which app the network should run, how many nodes it should create, and the list of transactions to run. ``tests/simple_logging_scenario.json`` is an example scenario file showing the expected format:

.. literalinclude:: ../../tests/simple_logging_scenario.json
    :language: json

To execute this scenario first follow the instructions in :ref:`getting_started` and then, from the ``build`` directory, run:

.. code-block:: bash

    python ../tests/e2e_scenarios.py --scenario ../tests/simple_logging_scenario.json

This first loads the scenario from the given json file, extracting initial fields:

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

Each transaction listed in the scenario is then sent to either the `primary` or a `follower` node. As the current implementation uses Raft for consensus, any ``Write`` transactions (which modify the KV) must be sent to the `primary`. Sending them to a `follower` will result in a ``TX_NOT_LEADER`` error response. ``Read`` transactions can be go to any node.

The response to each transaction is printed at the ``DEBUG`` logging level, and also compared against the expected result. For instance, given this transaction in the scenario file:

.. code-block:: json

    {
      "method": "LOG_record",
      "params": {
        "id": 42,
        "msg": "Hello world"
      },
      "expected": "OK"
    }

There should be a corresponding entry in the Python output, similar to:

.. code-block:: text

    | INFO     | infra.jsonrpc:request:192 - #0 LOG_record {'id': 42, 'msg': 'Hello world'}
    | DEBUG    | infra.jsonrpc:response:209 - #0 {'id': 0, 'result': 'OK', 'error': None, 'jsonrpc': '2.0', 'commit': 5, 'term': 2, 'global_commit': 4}

The ``e2e`` test script takes several additional parameters, documented by passing ``-h`` on the command line. To debug a node it may be useful to increase the node's verbosity by altering the ``--log-level`` option [#log_location]_, or to attach a debugger to a node at launch with the ``--debug-nodes`` option. If passed the ``--network-only`` option the script will keep the network alive rather, than closing immediately after transactions have completed, allowing additional transactions to be sent manually.

.. rubric:: Footnotes

.. [#log_location] The log location should be visible in the Python output. By default, node ``N`` will log to files ``out`` and ``err`` in ``/tmp/{USER}_{N}``

