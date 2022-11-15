Performance Testing Tool
========================

CCF has its own performance testing tool under the ``CCF/tests/perf-system`` directory, to measure the performance of the system and its applications.
The aim of this tool is to generate loads of requests, submit them to CCF as fast as possible, producing metrics about the system's efficiency.
It consists of three distinct components, which are listed below. 

.. panels::

    :fa:`gears` :doc:`generator`
    ^^^^^^^^^^^^^^^^^^^^^^^^^

    Generate requests

    ---
    
    :fa:`paper-plane` :doc:`submitter`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Submit requests to the server

    ---

    :fa:`headset` :doc:`analysis`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Analyze responses and requests


.. toctree::
    :hidden:
    :maxdepth: 1

    generator
    submitter
    analysis