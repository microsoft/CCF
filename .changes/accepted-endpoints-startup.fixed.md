A node now rejects an `accepted_endpoints` pattern that isn't a valid regular expression when it validates its configuration, including with `--check`, and builds the patterns at startup instead of on its first requests, so that concurrent first requests no longer race and fail.
See [node configuration](doc/operations/configuration.rst).
