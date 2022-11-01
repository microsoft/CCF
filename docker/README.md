# Docker images for CCF

- `app_run`: Builds the image containing all runtime dependencies for CCF, as well as the latest release of CCF (as per https://github.com/microsoft/CCF/releases/latest). To be used by CCF operators.
- `app_dev`: Builds the image containing all build dependencies for CCF applications. To be used by CCF application developers.
- `ccf_ci`: Builds the image containing all build dependencies for CCF itself. To be used by CCF contributors. It is also used by CCF Continuous Integration pipeline.

To build all release containers, run:

```bash
$ cd CCF/
$ ./build_release_containers.sh ccfmsrc.azurecr.io <version>
```
