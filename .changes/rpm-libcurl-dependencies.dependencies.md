CCF application RPM packages now require `libcurl` instead of `curl`, allowing minimal Azure Linux images with `libcurl-minimal` to satisfy the runtime dependency without installing the `curl` CLI.
The `ccf_devel` RPM package now requires `libcurl-devel` instead of `curl-devel`.
