Quickstart
==========

First, you should :ref:`setup a CCF-compatible environment <Environment Setup>`. Then, you will be able to :ref:`build CCF from source and run CCF test suite <Building CCF>`. Note that for rapid prototyping, you can run a `virtual` build of CCF that does not require Intel SGX.

Once this is done, you can quickly spin up a CCF network and start :ref:`issuing commands to the deployed application <Issuing Commands>`:

.. code-block:: bash

    $ cd CCF/build
    $ ../start_test_network.sh ./libloggingenc.so.signed
    Setting up Python environment...
    Python environment successfully setup
    [2019-10-29 14:47:41.562] Starting 3 CCF nodes...
    [2019-10-29 14:48:12.138] Started CCF network with the following nodes:
    [2019-10-29 14:48:12.138]   Node [ 0] = 127.177.10.108:37765
    [2019-10-29 14:48:12.138]   Node [ 1] = 127.169.74.37:58343
    [2019-10-29 14:48:12.138]   Node [ 2] = 127.131.108.179:50532
    [2019-10-29 14:48:12.138] You can now issue business transactions to the ./libloggingenc.so.signed application.
    [2019-10-29 14:48:12.138] See https://microsoft.github.io/CCF/users/issue_commands.html for more information.
    [2019-10-29 14:48:12.138] Press Ctrl+C to shutdown the network.

You should also get familiar with some of :ref:`CCF concepts`. You will then be able to:

1. :ref:`Create a consortium and agree on the constitution <Member Governance>`
2. :ref:`Develop a CCF application, based on the example logging application <Example App>`
3. :ref:`Start a new CCF network to deploy the application <Starting a New Network>`
4. :ref:`Let the consortium configure and open the network to users <Opening a Network>`
5. :ref:`Have users issue business transactions to the application <Using CCF Applications>`

.. toctree::
    :maxdepth: 2
    :caption: Contents:

    requirements
    oeengine
    build