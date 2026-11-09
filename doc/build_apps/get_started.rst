Quickstart
==========

This page walks through the shortest path from a fresh machine to a running CCF application that you can modify.
Each step links to the page describing it in more detail.
For background on CCF itself, start with :ref:`overview/what_is_ccf:What is CCF?` and :ref:`overview/what_is_ccf:Core Concepts`.

1. Set Up a Development Environment
-----------------------------------

CCF builds and runs on Linux.
The quickest way to get a working environment is to use the `ccf-app-template <https://github.com/microsoft/ccf-app-template>`__ repository, which provides a development container with CCF, `NodeJS <https://nodejs.org/en>`__ and `NPM <https://docs.npmjs.com/downloading-and-installing-node-js-and-npm/>`__ pre-installed, along with minimal TypeScript and C++ applications:

- VS Code Dev Container: |Open in VSCode|
- GitHub Codespace: |Github codespace|

The `ccf-app-samples <https://github.com/microsoft/ccf-app-samples>`__ repository contains further, more complete sample applications.

2. Install CCF
--------------

Outside of the development container, install the latest CCF release as described in :doc:`/build_apps/install_bin`.
This installs CCF under ``/opt/ccf``, including the ``js_generic`` application, which hosts JavaScript applications, and the ``sandbox.sh`` script.

3. Start a Sandbox Network
--------------------------

Start a local, single-node network running the sample JavaScript logging application:

.. code-block:: bash

    $ /opt/ccf/bin/sandbox.sh

``sandbox.sh`` generates member and user identities, starts the node, deploys the application and issues all the governance requests required to open the network to users.
Once it prints the address of the node (by default ``https://127.0.0.1:8000``), the network is ready to accept requests.
See :doc:`/build_apps/run_app` for details of what the script does and the options it accepts.

4. Issue a First Request
------------------------

In a different terminal, copy the generated service certificate and user identity to the current directory:

.. code-block:: bash

    $ cp workspace/sandbox_common/*.pem .

Then record a message using the ``/app/log/private`` endpoint of the logging application, and read it back:

.. code-block:: bash

    $ curl https://127.0.0.1:8000/app/log/private -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": 42, "msg": "Hello CCF"}'
    true
    $ curl "https://127.0.0.1:8000/app/log/private?id=42" -X GET --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem
    {"msg":"Hello CCF"}

The service certificate (``--cacert``) authenticates the service to the client, and the user certificate and key (``--cert`` and ``--key``) authenticate the client to the service.
See :doc:`/use_apps/issue_commands` for more ways to interact with an application, and :doc:`/use_apps/verify_tx` to check that a transaction is committed and obtain a receipt for it.

5. Write and Deploy Your Own Application
----------------------------------------

JavaScript and TypeScript applications are deployed as :doc:`application bundles </build_apps/js_app_bundle>`: a directory containing the application's modules and an ``app.json`` file mapping endpoints to handler functions.
To create your own:

- Write the application in TypeScript, as described in :doc:`/build_apps/js_app_ts`, or start from the template application in `ccf-app-template <https://github.com/microsoft/ccf-app-template#run-js-app>`__.
- Build the bundle, then start a sandbox that runs it on the ``js_generic`` application:

  .. code-block:: bash

      $ /opt/ccf/bin/sandbox.sh --package /opt/ccf/bin/js_generic --js-app-bundle /path/to/bundle

- Call your endpoints under ``/app``, as in the previous step.

``sandbox.sh`` deploys the bundle through a governance proposal on your behalf.
On a real service, members submit and vote on this proposal, as described in :ref:`build_apps/js_app_bundle:Deployment`.

Next Steps
----------

- To run a service rather than a local sandbox, see :doc:`/operations/start_network` and :doc:`/governance/open_network`.
  Members govern the service through :doc:`proposals </governance/proposals>`, which are accepted according to the :doc:`constitution </governance/constitution>`.
- To control who can call your endpoints, see :doc:`/build_apps/auth/index`.
- To learn how application state is stored and replicated, see :doc:`/build_apps/kv/index`.

.. Preserves the anchor used by older links to this page.
.. _packaging-your-c-app:

Applications can also be written in C++ (see :doc:`/build_apps/example_cpp`, which also describes how to build and package them) or, experimentally, in Rust (see :doc:`/build_apps/example_rust`).
Native applications offer better performance than JavaScript applications, but are compiled into their own executable, so deploying a new version requires a :doc:`code upgrade </operations/code_upgrade>`.

.. |Open in VSCode| image:: https://img.shields.io/static/v1?label=Open+in&message=VSCode&logo=visualstudiocode&color=007ACC&logoColor=007ACC&labelColor=2C2C32
   :target: https://github.com/microsoft/ccf-app-template#quickstart
.. |Github codespace| image:: https://img.shields.io/static/v1?label=Open+in&message=GitHub+codespace&logo=github&color=2F363D&logoColor=white&labelColor=2C2C32
   :target: https://github.com/microsoft/ccf-app-template#quickstart