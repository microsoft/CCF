Submitter
=========

Overview
--------

The Submitter component is written in C++ and submits multiple requests with a very high speed to
stress test a system. In order to run the submitter, the required libraries should 
be installed. The following command in the ``CCF/getting-started/setup_vm`` directory installs them:

.. code-block:: bash

    $ ./run.sh ccf-dev.yml


Run submitter
--------------

To run the submitter it first needs to be built from the ``CCF/build`` directory. The submitter 
is compiled using the root CMakeLists.txt in the ``CCF`` directory. If the CCF project is 
already built before in your directory it can be compiled and run using the following commands:

.. code-block:: bash

    $ ninja submit
    $ ./submit manual_configurations

If this is the first run of the CCF, the compilation commands are the following:

.. code-block:: bash

    $ mkdir build
    $ cd build
    $ cmake -DCOMPILE_TARGET=sgx -GNinja ..
    $ ninja 
    $ ./submit manual_configurations

If the compilation target is not sgx then replace it with ``virtual``. All the components including 
the submitter should now be compiled under ``CCF/build`` directory.

The manual_configurations on the execution command should be replaced by calling all or most of 
the following arguments 

* ``-h,--help``: Print this help message and exit
* ``-c,--cert``: Use the provided certificate file when working with a SSL-based protocol.
* ``-k,--key``: Specify the path to the file containing the private key.
* ``--cacert``: Use the specified file for certificate verification.
* ``-a,--server-address``: Specify the address to submit requests. *(default: 127.0.0.1:8000)*
* ``-s,--send-filepath``: Path to parquet file to store the submitted requests. *REQUIRED*
* ``-r,--response-filepath``: Path to parquet file to store the responses from the submitted requests. *REQUIRED*
* ``-g,--generator-filepath``: Path to parquet file with the generated requests to be submitted. *REQUIRED*
* ``-m,--max-inflight-requests``: Specifies the number of outstanding requests sent to the server while waiting for a response. When this option is set to 0 there will be no pipelining. Any other value will enable pipelining. A positive value will specify a window of outstanding requests on the server while waiting for a response. -1 or a negative value will set the window of outstanding requests to maximum i.e. to submit requests without waiting for a response. *(default: 0)*

Once the component finishes submitting and receiving responses for all the requests it 
will then store the results into two ``.parquet`` files. Hence, the path to file with the 
requests that were generated from the previous component, as well as the path to store 
the submission results must be declared.
