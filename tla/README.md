# TLA+ specifications

This directory contains some formal specifications of CCF. For more information, please refer to the CCF TLA+ documentation: https://microsoft.github.io/CCF/main/architecture/raft_tla.html.

You can also interact with these specifications using codespaces:

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://github.com/codespaces/new?hide_repo_select=true&ref=main&repo=180112558&machine=xLargePremiumLinux&devcontainer_path=.devcontainer%2Ftlaplus%2Fdevcontainer.json&location=WestEurope)

## Trace validation

You can produce fresh traces quickly from the driver by running the `make_traces.sh` script from this directory.

Calling the trace validation on, for example, the `startup` scenario can then be done with `JSON=../build/startup.ndjson ./tlc.sh consensus/Traceccfraft.tla`.
