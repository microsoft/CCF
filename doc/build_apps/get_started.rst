Quick Start
===========

Application Development using CCF Overview
-------------------------------------------

-  :ref:`What is Confidential Consortium Framework (CCF) <overview/what_is_ccf:What is CCF?>`
-  Read the :doc:`CCF overview </overview/index>` and get familiar with :ref:`overview/what_is_ccf:Core Concepts` and `Azure confidential computing <https://learn.microsoft.com/en-us/azure/confidential-computing/>`__
-  :doc:`Build new CCF applications </build_apps/index>` in TypeScript/JavaScript or C++
-  CCF `JavaScript module API reference <https://microsoft.github.io/CCF/main/js/ccf-app/modules.html>`__
-  CCF application get started repos `CCF application template <https://github.com/microsoft/ccf-app-template>`__ and  `CCF application samples <https://github.com/microsoft/ccf-app-samples>`__

Development environment
-----------------------

-  VS Code Dev Container |Open in VSCode|
-  Github codespace: |Github codespace|
-  Virtual Machine (`Creating a Virtual Machine in Azure to run CCF <https://github.com/microsoft/CCF/blob/main/getting_started/azure_vm/README.md>`__)

(JavaScript/Typescript) Applications
------------------------------------

CCF apps can be written in JavaScript/Typescript. To test a JS/TS CCF application you need go through the following steps:

-  :doc:`Start a CCF Network with at least one node </operations/start_network>`
-  Initialise the CCF network with at least one active member and one user :ref:`governance/open_network:Opening a Network`,
   this can be done through :ref:`Proposals <governance/proposals:Summary>`.
-  Create an application :ref:`deployment proposal <build_apps/js_app_bundle:Deployment>`
-  Submit the app deployment proposal to the network and all members accept it through voting. This is a part of :ref:`Network Governance <governance/proposals:Submitting a New Proposal>`.
-  :doc:`Open the CCF network for users </governance/open_network>`
-  Start testing of your application endpoints

Build Application
~~~~~~~~~~~~~~~~~

The application building prerequisites [:doc:`CCF </build_apps/install_bin>`, `NodeJS <https://nodejs.org>`__ and `NPM <https://www.npmjs.com>`__] must be installed, all will be preinstalled if you are using the devcontainer environment, otherwise you need to install them manually.

Please follow `ccf-app-template build process <https://github.com/microsoft/ccf-app-template#run-js-app>`__

Testing your Application
~~~~~~~~~~~~~~~~~~~~~~~~

There are several approaches to run and test your application

Run app: Using Sandbox.sh
^^^^^^^^^^^^^^^^^^^^^^^^^

-  Running the `sandbox.sh` script automatically starts a CCF network and deploys your application on it. The app is up and ready to receive calls and the initial governance steps are done for you
-  Support both ccf network types [virtual - enclave (TEE hardware)]
-  No initial governance steps required

   -  :doc:`/build_apps/run_app`
   -  `CCF Application template repository <https://github.com/microsoft/ccf-app-template#run-js-app>`__

Run app: Using Docker
^^^^^^^^^^^^^^^^^^^^^

-  A CCF network can be started using Docker containers; please check the `docker file samples <https://github.com/microsoft/ccf-app-template/tree/main/docker>`__
-  Support both ccf network types [virtual - enclave (TEE hardware)]
-  Initial governance steps are required to initialize, deploy your app, and start the network. `check Network governance section <https://github.com/microsoft/ccf-app-template#network-governance>`__

   -  Start a CCF network using docker files. please follow `ccf-app-template <https://github.com/microsoft/ccf-app-template#docker>`__
   -  The network is started with one node and one member, you need to
      execute the initial governance steps to initialize the network, `check Network governance section <https://github.com/microsoft/ccf-app-template#network-governance>`__

Run app: Using ``cchost`` on a VM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  The application can be tested using `cchost` and :doc:`CCF config file </operations/configuration>`,
   To Start a test CCF network on a Linux environment, it requires :doc:`CCF to be intalled </build_apps/install_bin>`
   or you can create a ready CCF VM using `Creating a Virtual Machine in Azure to run CCF <https://github.com/microsoft/CCF/blob/main/getting_started/azure_vm/README.md>`__
-  Support both ccf network types [virtual - enclave (TEE hardware)]
-  Initial governance steps are required to initialize, deploy your app, and start the network. `check Network governance section <https://github.com/microsoft/ccf-app-template#network-governance>`__

   -  Start a CCF network using cchost and :doc:`CCF node config file </operations/configuration>`. please follow `ccf-app-template <https://github.com/microsoft/ccf-app-template#bare-vm>`__
   -  The network is started with one node and one member, you need to execute the initial governance steps to initialize the network, `check Network governance section <https://github.com/microsoft/ccf-app-template#network-governance>`__

Run app: Using Managed CCF
^^^^^^^^^^^^^^^^^^^^^^^^^^

-  To test your application using Managed CCF, you can create `Azure Managed CCF <https://techcommunity.microsoft.com/t5/azure-confidential-computing/microsoft-introduces-preview-of-azure-managed-confidential/ba-p/3648986>`__ service on your subscription, the service will create a ready CCF network
-  Support only a ccf network in enclave mode (TEE hardware)
-  No initial governance steps required to start up your network, but you need to use governance to propose your application

   -  First, create the network’s initial member certificate, please check :doc:`Certificates generation </governance/adding_member>`
   -  Create a new Azure Managed CCF serivce (the initial member certificate required as input)
   -  Build the application and create a :ref:`build_apps/js_app_bundle:Deployment` proposal
   -  Deploy the application proposal, :ref:`governance/proposals:Submitting a New Proposal`
   -  Create and submit proposal for :ref:`governance/open_network:Adding Users` 

Testing: Application Endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To check samples on how to test your application endpoints, please check these repositories:

-  `CCF-app-template repo <https://github.com/microsoft/ccf-app-template#--javascript>`__
-  `Banking Application sample <https://github.com/microsoft/ccf-app-samples/tree/main/banking-app#how-to-run-the-tests>`__

C++ Applications
----------------

CCF apps can also be written in C++. This offers better performance than JavaScript apps but requires a compilation step and a restart of the CCF node for deployment. please check `ccf-app-template <https://github.com/microsoft/ccf-app-template>`__ repository.

The C++ sample app is located in the ```cpp/`` <cpp/>`__ directory.

Build C++ app
~~~~~~~~~~~~~

Please check `ccf-app-template build process <https://github.com/microsoft/ccf-app-template#build-c-app>`__

Run C++ app: Using Sandbox.sh
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Please check `run ccf-app-template using sandbox.sh <https://github.com/microsoft/ccf-app-template#run-c-app>`__

Run C++ app: Using Docker
~~~~~~~~~~~~~~~~~~~~~~~~~

Please check `run ccf-app-template using docker <https://github.com/microsoft/ccf-app-template#docker-1>`__

Network Governance
------------------

A Consortium of trusted Members :doc:`governs the CCF network </governance/index>`. Members can submit proposals to CCF and these proposals are accepted based on the rules defined in the :ref:`Constitution <governance/constitution:Constitution>`. Governance changes are submitted to a :ref:`network as Proposals <governance/proposals:Summary>`, and put to a vote from members.

-  :ref:`Submitting a New Proposal <governance/proposals:Submitting a New Proposal>`
-  :ref:`Members can then vote to accept or reject the proposal <governance/proposals:Summary>`

.. note:: The initial member's certificate and private key, must be generated before starting a CCF network, please check :doc:`/governance/adding_member` .

Activating network members
~~~~~~~~~~~~~~~~~~~~~~~~~~

By default the CCF network needs at least one member to be started, after the network is started this member must be activated. 

- :ref:`New member proposal sample <governance/proposals:Submitting a New Proposal>`
- :ref:`Activating a New Member <governance/adding_member:Activating a New Member>`

Adding network users
~~~~~~~~~~~~~~~~~~~~

Users directly interact with the application running in CCF. Their public identities should be voted in by members before they are allowed to issue requests. 
Once a CCF network is successfully started and an acceptable number of nodes have joined, members should vote to open the network to Users. First, the identities of trusted users should be generated,
see :ref:`Generating Member Keys and Certificates <governance/adding_member:Generating Member Keys and Certificates>` and :ref:`Adding Users docs <governance/open_network:Adding Users>`

:ref:`New user proposal sample <governance/open_network:Adding Users>`

Application deployment
~~~~~~~~~~~~~~~~~~~~~~

The native format for JavaScript applications in CCF is a :ref:`JavaScript application bundle <build_apps/js_app_bundle:JavaScript Application Bundle>`, or short app bundle. A bundle can be wrapped directly into a governance proposal for deployment.

:ref:`Application deployment proposal sample <build_apps/js_app_bundle:Deployment>`

Open network for users
~~~~~~~~~~~~~~~~~~~~~~

Once users are added to the network, members should create a :ref:`proposal to open the network <governance/open_network:Opening a Network>`, Other members are then able to vote for the proposal using the returned proposal id.

Once the proposal has received enough votes under the rules of the Constitution (ie. ballots which evaluate to true), the network is opened to users. It is only then that users are able to execute transactions on the deployed application.

:ref:`Open network proposal sample <governance/open_network:Opening the Network>`

.. |Open in VSCode| image:: https://img.shields.io/static/v1?label=Open+in&message=VSCode&logo=visualstudiocode&color=007ACC&logoColor=007ACC&labelColor=2C2C32
   :target: https://github.com/microsoft/ccf-app-template#quickstart
.. |Github codespace| image:: https://img.shields.io/static/v1?label=Open+in&message=GitHub+codespace&logo=github&color=2F363D&logoColor=white&labelColor=2C2C32
   :target: https://github.com/microsoft/ccf-app-template#quickstart