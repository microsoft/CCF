## Branch strategy

The master branch is maintained at commercial quality. It only supports
COSE_Sign1. Changes against it must be very complete. Periodically a
new 1.x release is made from the master branch.

The "dev" branch is to become t_cose 2.0 when it gets to commercial
quality. It is to support COSE_Mac, COSE_Encrypt, multiple signers and
such.  PRs to it mainly need to not break the build and the CI.


## Tests and CI

Generally any PR should still have all these tests passing before it
will be merged.

### Basic tests

Running the standard make will produce `t_cose_test` for a particular
crypto library. It runs a thorough set of tests.

### CI tests

GitHub CI is used to build and test against several crypto libraries.

### tdv/b.sh tests

In the "tdv" repository there are some makes files and build scripts
that do some more thorough testing.  They are too large and take too
long to run to make them part of normal CI. Here's a few things they
do:

* Build with a fairly maximal set of compiler warning flags set (e.g.,
  -Wall)

* Build and test every combination of `#define` for configuration (this
  is what takes a long time)

* Build for use in a C++ program

* Measure and output code size


## PR Characteristics

I review PRs pretty thoroughly largely because I assume I am going to
have to provide support for them long term as I aim to make sure this
is high-quality, tested commercial code.  No one pays me for this and
there is no team or company behind this.

Here's a few notes on getting PRs merged:

* Only change what you need to. Don't beautify code that is not
  related to your change. Don't adjust tabs and spaces. Don't fix
  spelling mistakes or comment formatting that is not related to the
  change. This helps reduce merge conflicts and makes review
  easier. If you want to beautify and such, please do, but in
  separate PRs so intent is clear.

* Make sure all the tests mentioned above in Tests and CI are passing

* Target the right branch. It is fairly easy to change the target
  branch of a PR in GitHub.



## Makefile and project files

There are makefiles for both cmake and regular make. Both sets need to
be kept up to date and functioning.

The GitHub CI uses cmake.

There are several "Makefile"s for different crypto
libraries. Generally, a change to one means a change to the others
(though we can probably make that better with a little more work).


## Coding Style

QCBOR uses camelCase and t_cose follows [Arm's coding
guidelines](https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git/tree/docs/contributing/coding_guide.rst)
resulting in code with mixed styles. For better or worse, an Arm-style
version of UsefulBuf is created and used and so there is a duplicate
of UsefulBuf. The two are identical. They just have different names.
