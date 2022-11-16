Analyzer
========

Overview
--------

The Analysis component produces some metrics based on the results and the ``.parquet`` 
files produced by previous components. This component is produced in Python and 
provides the functionality of a library called either from a command-line tool 
or by creating a script to call the library functions.

In order to run this component the dependencies need to be installed. If 
these are not already installed, you can run from the :ccf_repo:`tests/perf-system/` 
directory the following command:

.. code-block:: bash

    $ pip install -r requirements.txt


Run Analyzer
------------

The command line tool in :ccf_repo:`tests/perf-system/analyze/analyze_packages.py` 

provide a default analysis that returns some throughput and latency metrics. 
For more targeted analysis you can create your own scripts, such as 
:ccf_repo:`tests/perf-system/analyze/throughput_analysis.py`.


Command-Line Tool
#################

For the default analysis of the command line tool you need to run the 
following command from the :ccf_repo:`tests/perf-system/analyze/` 

directory:

.. code-block:: bash

    $ python3 analyze_packages.py

You can specify the ``.parquet`` file paths you want to include in your 
analysis using the following arguments:

:: 

    -h, --help show this help message and exit
    -sf SEND_FILE_PATH, --send_file_path SEND_FILE_PATH Path to the parquet file that contains the submitted requests (default: ../submitter/cpp_send.parquet)
    -rf RESPONSE_FILE_PATH, --response_file_path RESPONSE_FILE_PATH Path to the parquet file that contains the responses from the submitted requests (default: ../submitter/cpp_respond.parquet)

Running this file will produce some tables on the terminals with the metrics 
such as analysis-table_ and some images with graphs exported to the 
same directory.

.. _analysis-table:

+----------------+----------------+----------+----------+--------------------+
| Total Requests | Total Time (s) | Pass (%) | Fail (%) | Throughput (req/s) |
+----------------+----------------+----------+----------+--------------------+
|     92000      |     49.466     |  100.0   |   0.0    |       1859.9       |
+----------------+----------------+----------+----------+--------------------+

Scripting Analysis
##################

To use the library to create your own analysis, you need first to read the 
parquet files as dataframes using ``get_df_from_parquet_file()`` providing 
the path to the file as an argument.



To use the analysis functions for your dataframes, you first need to 
create a new ``Analyze`` object. It is suggested to first call the 
``iter_for_success_and_latency()`` function which based on the 
dataframes given as arguments, will populate the latency lists 
and the percentage of the successful requests for your dataframes. Based 
on these results you can calculate the total time of the experiment 
with ``total_time_in_sec()`` to get throughput, or you could 
customize your own metrics table with ``customize_table()`` 
providing the lists for the field names and the values. For 
more information about the provided functions, you can see the 
library code on the :ccf_repo:`tests/perf-system/analyze/analyzer.py`.