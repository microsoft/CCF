Command-Line Interface
======================

Each CCF executable exposes the following command-line interface (CLI) options:

.. code-block:: bash

    $ /opt/ccf/bin/js_generic --help

        Run a single CCF node, based on the given configuration file.
        Some parameters are marked "(security critical)" - these must be passed on the CLI rather than within a configuration file, so that (on relevant platforms) their value is captured in an attestation even if the configuration file itself is unattested.

        Usage: /opt/ccf/bin/js_generic [OPTIONS]

        Options:
        -h,--help                   Print this help message and exit
        -c,--config TEXT REQUIRED   Path to JSON configuration file
        --config-timeout TEXT       Configuration file read timeout, for example 5s or 1min
        --check                     Verify configuration file and exit
        -v,--version                Display CCF version and exit
        --log-level ENUM:value in {debug->1,fail->3,fatal->4,info->2,trace->0} OR {1,3,4,2,0}
                                    Logging level for the node (security critical)

Note that the ``--enclave-log-level`` option is security critical.
They must be passed on the command line rather than in a configuration file, so that their values are captured in an attestation even if the configuration file itself is not attested, for example because it is mounted from an external, un-attested, filesystem.

The ``--config-timeout`` option specifies how long to wait for the configuration file to be available before giving up. This is useful when running CCF in a container, where the configuration file may not be immediately available.