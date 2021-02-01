To use the OE-defined LVI mitigations requires this fix:
https://github.com/openenclave/openenclave/pull/3285

Pending a release with this fix included, we work around it by maintaining a local copy of the necessary CMake setup here. The files in this directory are minor adaptations of files taken from https://github.com/openenclave/openenclave/tree/master/cmake
