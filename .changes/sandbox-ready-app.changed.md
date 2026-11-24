`sandbox.sh` and `start_network.py` now wait for each node's `/node/ready/app` endpoint instead of `/app/commit`, so they can also start applications that don't install the built-in `/app` endpoints.
See [Running CCF Applications](doc/build_apps/run_app.rst).
