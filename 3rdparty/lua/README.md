Created from https://github.com/lua/lua at commit f59e6a93c0ad38a27a420e51abf8f13d962446b5
The following modules were removed: lbitlib, liolib, loadlib, loslib, ldblib. Further, ltest.c/.h, linit.c/.h were removed. 
In the remaining sources, some file and I/O related functions were removed or altered. These changes can be toggled with the NO_IO preprocessor definition.
The diff can be found in no_io.patch.