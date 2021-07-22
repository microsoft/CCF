#!/bin/sh
# Adapted from: https://github.com/pmer/tla-bin
exec java -XX:+IgnoreUnrecognizedVMOptions -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC "$@" -workers auto