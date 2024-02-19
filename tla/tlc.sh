#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# Original License below
# Adapted from: https://github.com/pmer/tla-bin

if [ "${CI}" ] || [ "${SYSTEM_TEAMFOUNDATIONCOLLECTIONURI}" ]; then
    JVM_OPTIONS+=("-Dtlc2.TLC.ide=Github" "-Dutil.ExecutionStatisticsCollector.id=be29f6283abeed2fb1fd0be898bc6601")
fi

# See https://docs.oracle.com/en/java/javase/20/gctuning/available-collectors.html#GUID-F215A508-9E58-40B4-90A5-74E29BF3BD3C
# > If (a) peak application performance is the first priority and (b) there are no pause-time requirements or pauses of one second or longer are acceptable,
# > then let the VM select the collector or select the parallel collector with -XX:+UseParallelGC.
# Simulation, nor Model Checking seem to work well with G1GC, but Trace Validation does not for some reason, and is much slower unless -XX:+UseParallelGC is used.
# In all cases, pauses don't matter, only throughput does.

exec java -XX:+UseParallelGC -Dtlc2.tool.impl.Tool.cdot=true "${JVM_OPTIONS[@]}" -cp tla2tools.jar:CommunityModules-deps.jar tlc2.TLC "$@" -checkpoint 0 -lncheck final


# Original License
# Copyright 2017 Paul Merrill

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.