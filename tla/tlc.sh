#!/bin/sh
# Adapted from: https://github.com/pmer/tla-bin

DEFAULT_JAVA_OPTS="-XX:+IgnoreUnrecognizedVMOptions -XX:+UseParallelGC"

if [ -z "$JAVA_OPTS" ]; then
  JAVA_OPTS="$DEFAULT_JAVA_OPTS"
fi

exec java $JAVA_OPTS -cp tla2tools.jar tlc2.TLC "$@" -workers auto