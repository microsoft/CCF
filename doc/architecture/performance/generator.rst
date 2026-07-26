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

For a full description of all options, run:

.. code-block:: bash

    $ python3 generate_packages.py --help

Some example invocations:

.. code-block:: bash

    # Generate 1000 POST requests to /app/log/private against a local node
    $ python3 generate_packages.py \
        --rows 1000 \
        --path /app/log/private \
        --verb POST

    # Generate requests and save to a custom parquet file
    $ python3 generate_packages.py \
        --rows 500 \
        --path /app/log/private \
        --verb POST \
        --path_to_parquet my_requests.parquet

After executing this command there will be a ``.parquet`` file produced containing
the generated requests, ready to be passed to the :doc:`submitter`.

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