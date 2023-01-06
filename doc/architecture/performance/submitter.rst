Submitter
=========

Overview
--------

The Submitter component is written in C++ and submits multiple requests with a very high speed to
stress test a system. In order to run the submitter, the required libraries should 
be installed following the :doc:`/contribute/build_setup`.


Run submitter
--------------

To run the submitter it first needs to be built in a ``build`` directory. The submitter 
is compiled using the CMakeLists.txt in the root directory. If the CCF project is 
already built in your directory it can be compiled and run using the following commands:

.. code-block:: bash

    $ ninja submit
    $ ./submit manual_configurations

If this is the first run of the CCF, please check on :doc:`/contribute/build_ccf`.:

The ``manual_configurations`` on the execution command should be replaced by calling all or most of 
the following arguments 

::

    -h,--help Print this help message and exit
    -c,--cert TEXT:FILE Use the provided certificate file when working with a SSL-based protocol.
    -k,--key TEXT:FILE Specify the path to the file containing the private key.
    --cacert TEXT:FILE Use the specified file for certificate verification.
    -a,--server-address TEXT=127.0.0.1:8000 Specify the address to submit requests.
    -s,--send-filepath TEXT REQUIRED Path to parquet file to store the submitted requests.
    -r,--response-filepath TEXT REQUIRED Path to parquet file to store the responses from the submitted requests.
    -g,--generator-filepath TEXT REQUIRED Path to parquet file with the generated requests to be submitted.
    -m,--max-writes-ahead INT=0 Specifies the number of outstanding requests sent to the server while waiting for response. When this options is set to 0 there will be no pipelining. Any other value will enable pipelining. A positive value will specify a window of outstanding requests on the server while waiting for a response. -1 or a negative value will set the window of outstanding requests to maximum i.e. submit requests without waiting for a response

Once the component finishes submitting and receiving responses for all the requests it 
will then store the results into two ``.parquet`` files. Hence, the path to file with the 
requests that were generated from the previous component, as well as the path to store 
the submission results must be declared.
