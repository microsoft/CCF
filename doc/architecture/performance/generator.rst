Generator
=========

Overview
--------

This component is responsible for generating requests and storing them in a format 
that could be submitted to the server. The user can declare the requests by leveraging
the functions inside the library in :ccf_repo:`tests/infra/piccolo/generator.py`.
The user can generate requests from the library by either calling the command line tool 
in :ccf_repo:`tests/infra/piccolo/generate_packages.py` or by creating a script 
calling the functions of the library, such as the :ccf_repo:`tests/infra/piccolo/logging_generator.py` 
which contains a sample generation of requests for the logging CCF application.

Run generator
-------------

The generator component offers a command-line tool for basic scenarios as well as 
a sample for an application for more complex scenarios.

Command-Line Tool
#################

For the command line option you need to run the following:

.. code-block:: bash

    $ python3 generate_packages.py

After executing this command there will be a ``.parquet`` file produced in the same directory
containing the data with the requests. You can configure the generated requests using the 
following arguments:

:: 

    -h, --help show this help message and exit
    -hs HOST, --host HOST The host to submit the request. (default: 127.0.0.1:8000)
    -p PATH, --path PATH  The relative path to submit the request. (default: /app/log/private)
    -vr VERB, --verb VERB The request action. (default: POST)
    -r ROWS, --rows ROWS  The number of requests to send. (default: 16)
    -rt REQUEST_TYPE, --request_type REQUEST_TYPE The transfer protocol for the request. (default: HTTP/1.1)
    -pf PATH_TO_PARQUET, --path_to_parquet PATH_TO_PARQUET Path to the parquet file to store the generated requests (default: ./requests.parquet)
    -ct CONTENT_TYPE, --content_type CONTENT_TYPE The Content-Type representation header is used to indicate the original media type of the resource. (default: application-json)
    -d DATA, --data DATA  A string with the data to be sent with a request (default: {"id": 1, "msg": "Send message with id 1"})

Scripting Requests
##################

To script requests, first create a ``Messages`` object and call ``append()`` for each request.
``append()`` serialises the path, HTTP method and optional version, content type, headers, and body,
then stores the request with a generated message ID.

After finishing the generation of the requests, call ``to_parquet_file()`` to write the stored requests
to the file specified in the arguments. Then you
can run your script as you would run any python file:

.. code-block:: bash

    $ python3 logging_generator.py


Parquet files are an easy and well-compressed way of storing requests generated from this component 
to run the same generated requests multiple times on the same submitter under 
different circumstances.