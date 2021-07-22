#!/bin/sh
# Adapted from: https://github.com/pmer/tla-bin
exec java -XX:+IgnoreUnrecognizedVMOptions -XX:+UseParallelGC -Xms2G -Xmx2G -cp tla2tools.jar tlc2.TLC "$@" -workers auto