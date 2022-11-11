Get Started: Application Development using CCF
==============================================

Overview
========

What is CCF: The `Confidential Consortium Framework
(CCF) <https://ccf.dev/>`__ is an open-source framework for building a
new category of secure, highly available, and performant applications
that focus on multi-party compute and data.

-  Read the `CCF
   overview <https://microsoft.github.io/CCF/main/overview/index.html>`__
   and get familiar with `CCF’s core
   concepts <https://microsoft.github.io/CCF/main/overview/what_is_ccf.html>`__
   and `Azure confidential
   computing <https://learn.microsoft.com/en-us/azure/confidential-computing/>`__
-  `Build new CCF
   applications <https://microsoft.github.io/CCF/main/build_apps/index.html>`__
   in TypeScript/JavaScript or C++
-  CCF `Modules API
   reference <https://microsoft.github.io/CCF/main/js/ccf-app/modules.html>`__
-  CCF application get started repos

   -  `CCF application
      template <https://github.com/microsoft/ccf-app-template>`__
   -  `CCF application
      samples <https://github.com/microsoft/ccf-app-samples>`__

Supported Programing Languages
------------------------------

Applications can be written in

-  TypeScript
-  JavaScript
-  C++
-  More languages support upcoming in 2023

Development environment
-----------------------

-  VS Code Dev Container |Open in VSCode|
-  Github codespace: |Github codespace|
-  Linux Machine (`Creating a Virtual Machine in Azure to run
   CCF <https://github.com/microsoft/CCF/blob/main/getting_started/azure_vm/README.md>`__)


(JavaScript/Typescript) Applications
------------------------------------

CCF apps can also be written in JavaScript or Typescript, To test a ccf
application you need go through the following steps:

-  Start a CCF Network with at least one node
-  Initialize the CCF network with at least one (active member - user),
   this can be done through `Network Governance
   Proposals <https://microsoft.github.io/CCF/main/governance/proposals.html>`__.
-  Create an application `deployment
   proposal <https://microsoft.github.io/CCF/main/build_apps/js_app_bundle.html>`__
-  Submit the app deployment proposal to the network and all members
   accept it through voting. This is a part of `Network
   Governance <https://microsoft.github.io/CCF/main/governance/proposals.html>`__.
-  Open the CCF network for users
-  Start to test your application endpoints

Build Application
~~~~~~~~~~~~~~~~~

The application building prerequisites [`CCF <#ccf-install>`__, NodeJS
and NPM] must be installed,all will be preinstalled if you are using
devcontainer environment, otherwise you need to install them manually .

In the checkout of
`ccf-app-samples <https://github.com/microsoft/ccf-app-samples>`__
repository:

.. code:: bash

   # carried out on the dev-container start up
   cd banking-app && npm install

   # build and generate the application bundle and deployment proposal
   make build

   # a dist folder is created with app bundle and deployment proposal.

Testing your Application
~~~~~~~~~~~~~~~~~~~~~~~~

There are several approaches to test your application

-  `Sandbox.sh <#testing-using-sandboxsh>`__

   -  Build an initialized CCF network and automatically deploy your app
      on top of it
   -  Support both ccf network types [virtual - enclave (TEE hardware)]
   -  No governance steps required

-  `Docker container <#testing-using-docker-containers>`__

   -  Support both ccf network types [virtual - enclave (TEE hardware)]
   -  Governance steps required to deploy your app, initialize, and
      start the network

-  `Azure Virtual Machine
   (Linux) <#testing-using-azure-virtual-machine>`__

   -  Support both ccf network types [virtual - enclave (TEE hardware)]
   -  Governance steps required to deploy your app, initialize, and
      start the network

-  `Azure Managed CCF <#testing-using-azure-managed-ccf>`__

   -  Support only a ccf network in enclave mode (TEE hardware)
   -  No governance steps required to start up your network, but you
      need to use governance to propose your application

Testing: Using Sandbox.sh
~~~~~~~~~~~~~~~~~~~~~~~~~

By running sandbox.sh script, it is automatically starts a CCF network
and deploys your application on it. The app is up and ready to receive
calls and all the governance work is done for you.

Start in a CCF Network in Enclave mode

.. code:: bash

   /opt/ccf/bin/sandbox.sh --js-app-bundle ./banking-app/dist/  --enclave-type release -p /opt/ccf/lib/libjs.enclave.so.signed
   ...
   [12:00:00.000] Press Ctrl+C to shutdown the network
   # It is then possible to interact with the service

Start in a CCF Network in Virtual mode (the default mode for testing)

.. code:: bash

   /opt/ccf/bin/sandbox.sh --js-app-bundle ./banking-app/dist/
   ...
   [12:00:00.000] Press Ctrl+C to shutdown the network
   # It is then possible to interact with the service

Testing: Using docker containers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Build and run one of these docker files [“ccf_app_js.virtual” or
“ccf_app_js.enclave”] to start a CCF network with one node and one
member. After that, you need to execute governance steps to deploy the
application and open the network for users to begin access the app
endpoints. All the governance steps need to be done manually using
`proposal submit and vote
process <https://microsoft.github.io/CCF/main/governance/proposals.html>`__.

Build and run docker container to start a CCF network
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Start in a CCF Network in Enclave mode, via docker container based on
config file “./config/cchost_config_enclave_js.json”

.. code:: bash

    docker build -t ccf-app-samples:js-enclave -f docker/ccf_app_js.enclave .
    docker run -d --device /dev/sgx_enclave:/dev/sgx_enclave --device /dev/sgx_provision:/dev/sgx_provision -v /dev/sgx:/dev/sgx ccf-app-samples:js-enclave
    ...
    # CCF Network initialization needed before the interaction with the service

Start in a CCF Network in Virtual mode, based on virtual config file:
“./config/cchost_config_virtual_js.json”:

.. code:: bash

    docker build -t ccf-app-samples:js-virtual -f docker/ccf_app_js.virtual .
    docker run -d ccf-app-samples:js-virtual
    ...
    # CCF Network initialization needed before the interaction with the service

Now, a network is started with one node and one member, you need to
execute the following governance steps to initialize the network, `check
Network governance section <#network-governance>`__

-  Activate the network existing member (to start a network governance)
-  Build the application and `create a deployment
   proposal <#build-application>`__
-  Deploy the application proposal, `using governance
   calls <#network-governance>`__
-  Optionally Create and submit `an add users
   proposal <#new-user-proposal>`__
-  Open the network for users (`using
   proposal <#open-network-proposal>`__)

CCF Node Configuration file
^^^^^^^^^^^^^^^^^^^^^^^^^^^

To start or join new node you need some configs, The configuration for
each CCF node must be contained in a single JSON configuration file like
[cchost_config_enclave_js.json - cchost_config_virtual_js.json], `CCF
node config file
documentation <https://microsoft.github.io/CCF/main/operations/configuration.html>`__

Testing: Using Azure Virtual Machine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To Start a test CCF network on a VM, it requires `CCF to be
intalled <https://microsoft.github.io/CCF/main/build_apps/install_bin.html>`__.

To create a ready CCF VM please check `Creating a Virtual Machine in
Azure to run
CCF <https://github.com/microsoft/CCF/blob/main/getting_started/azure_vm/README.md>`__

Start the CCF network using the cchost in enclave mode

.. code:: bash

    /opt/ccf/bin/cchost --config ./config/cchost_config_enclave_js.json
    ...
    # CCF Network initialization needed before the interaction with the service

Or virtual mode

.. code:: bash

   /opt/ccf/bin/cchost --config ./config/cchost_config_virtual_js.json
   ...
    # CCF Network initialization needed before the interaction with the service

Now, a network is started with one node and one member, you need to
execute the following governance steps to initialize the network, `check
Network governance section <#network-governance>`__

-  Activate the network existing member (to start a network governance)
-  Build the application and `create a deployment
   proposal <#build-application>`__
-  Deploy the application proposal, `using governance
   calls <#network-governance>`__
-  Create and submit `an add users proposal <#new-user-proposal>`__
-  Open the network for users (`using
   proposal <#open-network-proposal>`__)

.. _ccf-node-configuration-file-1:

CCF Node Configuration file
^^^^^^^^^^^^^^^^^^^^^^^^^^^

To start or join new node you need some configs, The configuration for
each CCF node must be contained in a single JSON configuration file like
[cchost_config_enclave_js.json - cchost_config_virtual_js.json], `CCF
node config file
documentation <https://microsoft.github.io/CCF/main/operations/configuration.html>`__

Testing: Using `Azure Managed CCF <https://techcommunity.microsoft.com/t5/azure-confidential-computing/microsoft-introduces-preview-of-azure-managed-confidential/ba-p/3648986>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To test you application using Managed CCF, you can create Azure Managed
CCF serivce on your subscription, the service will create a ready CCF
network

-  First, create the network’s initial member certificate, please check
   `Certificates
   generation <https://microsoft.github.io/CCF/release/3.x/governance/adding_member.html>`__
-  Create a new Azure Managed CCF serivce (the initial member
   certificate required as input)
-  Build the application and `create a deployment
   proposal <#build-application>`__
-  Deploy the application proposal, `using governance
   calls <#network-governance>`__
-  Create and submit `an add users proposal <#new-user-proposal>`__

Testing: Application Endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To check samples on how to test your application endpoints, please check
these repositories.

-  `Banking
   Application <https://github.com/microsoft/ccf-app-samples/tree/main/banking-app>`__
-  `Template
   Application <https://github.com/microsoft/ccf-app-template>`__

C++ Applications
----------------

CCF apps can also be written in C++. This offers better performance than
JavaScript apps but requires a compilation step and a restart of the CCF
node for deployment. please check
`ccf-app-template <https://github.com/microsoft/ccf-app-template>`__
repository.

The C++ sample app is located in the ```cpp/`` <cpp/>`__ directory.

Build C++ app
~~~~~~~~~~~~~

In the checkout of
`ccf-app-template <https://github.com/microsoft/ccf-app-template>`__
repository:

.. code:: bash

    cd cpp/
    mkdir build && cd build
    CC="/opt/oe_lvi/clang-10" CXX="/opt/oe_lvi/clang++-10" cmake -GNinja ..
    ninja
    ls

   #libccf_app.enclave.so.signed # SGX-enabled application
   #libccf_app.virtual.so # Virtual application (i.e. insecure!)

Run C++ app: Using Sandbox.sh
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

   $ /opt/ccf/bin/sandbox.sh -p ./libccf_app.virtual.so
   [12:00:00.000] Press Ctrl+C to shutdown the network

Or, for an SGX-enabled application (unavailable in development
container):
``$ /opt/ccf/bin/sandbox.sh -p ./libccf_app.enclave.so.signed -e release``

Run C++ app: Using Docker
~~~~~~~~~~~~~~~~~~~~~~~~~

It is possible to build a runtime image of the C++ application via
docker:

.. code:: bash

   $ docker build -t ccf-app-template:cpp-enclave -f docker/ccf_app_cpp.enclave .
   $ docker run --device /dev/sgx_enclave:/dev/sgx_enclave --device /dev/sgx_provision:/dev/sgx_provision -v /dev/sgx:/dev/sgx ccf-app-template:cpp-enclave

   # Or, for the non-SGX (a.k.a. virtual) variant:

   $ docker build -t ccf-app-template:cpp-virtual -f docker/ccf_app_cpp.virtual .
   $ docker run ccf-app-template:virtual
   ...
   2022-01-01T12:00:00.000000Z -0.000 0   [info ] ../src/node/node_state.h:1790        | Network TLS connections now accepted
   ...
   # CCF Network initialization needed before the interaction with the service


Network Governance
------------------

a Consortium of trusted Members `governs the CCF
network <https://microsoft.github.io/CCF/main/governance/index.html>`__.
members can submit proposals to CCF and these proposals are accepted
based on the rules defined in the
`Constitution <https://microsoft.github.io/CCF/main/governance/constitution.html>`__.
Governance changes are submitted to a `network as
Proposals <https://microsoft.github.io/CCF/main/governance/proposals.html>`__,
and put to a vote from members.

Submit a proposal

.. code:: bash

   proposal0_out=$(/opt/ccf/bin/scurl.sh "https://ccf_service_url/gov/proposals" --cacert service_cert.pem --signing-key member0_privk.pem --signing-cert member0_cert.pem --data-binary @proposal.json -H "content-type: application/json")
   proposal0_id=$( jq -r  '.proposal_id' <<< "${proposal0_out}" )

Members vote to accept or reject the proposal

.. code:: bash

   /opt/ccf/bin/scurl.sh "https://ccf_service_url/gov/proposals/$proposal0_id/ballots" --cacert service_cert.pem --signing-key member0_privk.pem --signing-cert member0_cert.pem --data-binary @vote_accept.json -H "content-type: application/json" | jq
   /opt/ccf/bin/scurl.sh "https://ccf_service_url/gov/proposals/$proposal0_id/ballots" --cacert service_cert.pem --signing-key member1_privk.pem --signing-cert member1_cert.pem --data-binary @vote_accept.json -H "content-type: application/json" | jq

::

   Note: The initial member's certificate and private key, must be generated before starting a CCF network, please check [Certificates generation](https://microsoft.github.io/CCF/release/3.x/governance/adding_member.html).

Network Governance: Activating network members
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default the CCF network needs at least one member to be started,
after the network is started this member must be activated. `Adding or
activating
members <https://microsoft.github.io/CCF/main/governance/adding_member.html>`__

Activate member
^^^^^^^^^^^^^^^

.. code:: bash

   curl "https://ccf_service_url/gov/ack/update_state_digest" -X POST --cacert service_cert.pem --key member0_privk.pem --cert member0_cert.pem --silent | jq > request.json
   cat request.json
   /opt/ccf/bin/scurl.sh "https://ccf_service_url/gov/ack"  --cacert service_cert.pem --signing-key member0_privk.pem --signing-cert member0_cert.pem --header "Content-Type: application/json" --data-binary @request.json

New member proposal
^^^^^^^^^^^^^^^^^^^

.. code:: json

   {
     "actions": [
       {
         "name": "set_member",
         "args": {
           "cert": "member_cert",
           "encryption_pub_key": <member_encryption_pub_key>
         }
       }
     ]
   }

Network Governance: Adding users
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Users directly interact with the application running in CCF. Their
public identities should be voted in by members before they are allowed
to issue requests

Once a CCF network is successfully started and an acceptable number of
nodes have joined, members should vote to open the network to Users.
First, the identities of trusted users should be generated,see
`Generating Member Keys and
Certificates <https://microsoft.github.io/CCF/main/governance/adding_member.html#generating-member-keys-and-certificates>`__
and `Adding Users
docs <https://microsoft.github.io/CCF/main/governance/open_network.html>`__

New user proposal
^^^^^^^^^^^^^^^^^

.. code:: json

   {
     "actions": [
       {
         "name": "set_user",
         "args": {
           "cert": <user_cert>
         }
       }
     ]
   }

Network Governance: Application deployment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The native format for JavaScript applications in CCF is a `JavaScript
application
bundle <https://microsoft.github.io/CCF/main/build_apps/js_app_bundle.html>`__,
or short app bundle. A bundle can be wrapped directly into a governance
proposal for deployment.

Application deployment proposal
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: json

   {
     "actions": [
       {
         "name": "set_js_app",
         "args": {
           "bundle": {
             "metadata": { "endpoints": {<endpoints>} },
             "modules": [<modules>]
           }
         }
       }
     ]
   }

Network Governance: Open network for users
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once users are added to the network, members should create a `proposal
to open the
network <https://microsoft.github.io/CCF/main/governance/open_network.html>`__,
Other members are then able to vote for the proposal using the returned
proposal id.

Once the proposal has received enough votes under the rules of the
Constitution (ie. ballots which evaluate to true), the network is opened
to users. It is only then that users are able to execute transactions on
the deployed application.

Open network proposal
^^^^^^^^^^^^^^^^^^^^^

.. code:: json

   {
     "actions": [
       {
         "name": "transition_service_to_open",
         "args": {
           "next_service_identity": <service_cert>
         }
       }
     ]
   }

Dependencies Installation
-------------------------------------

-  `CCF Setup <https://microsoft.github.io/CCF/main/build_apps/install_bin.html>`__
-  `NodeJS & NPM <https://nodejs.org/en/download/package-manager/>`__

.. |Open in VSCode| image:: https://img.shields.io/static/v1?label=Open+in&message=VSCode&logo=visualstudiocode&color=007ACC&logoColor=007ACC&labelColor=2C2C32
   :target: https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/microsoft/ccf-app-samples
.. |Github codespace| image:: https://img.shields.io/static/v1?label=Open+in&message=GitHub+codespace&logo=github&color=2F363D&logoColor=white&labelColor=2C2C32
   :target: https://github.com/codespaces/new?hide_repo_select=true&ref=main&repo=496290904&machine=basicLinux32gb&devcontainer_path=.devcontainer.json&location=WestEurope
