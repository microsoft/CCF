# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import polars as pl
import sys
from collections import defaultdict
import hvplot
import hvplot.pandas
import json

"""
A little script to plot TLC action count

Run TLC with -Dtlc2.TLCGlobals.coverage=1, and pip the input in, e.g.:
ls -tr <spec>_coverage.json | xargs cat | python3 actions.py

The spec needs to have constraint like:

SerializeCoverage ==
    Serialize(<<TLCGet("spec")>>, CoverageFilename, [format |-> "NDJSON", charset |-> "UTF-8", openOptions |-> <<"WRITE", "CREATE", "APPEND">>])

"""

TOP = 5

if __name__ == "__main__":
    ts = defaultdict(list)
    for line in sys.stdin:
        cov_dump = json.loads(line)
        actions = {}
        # De-duplicate actions by name
        for action in cov_dump["actions"]:
            actions[action["name"]] = action["coverage"]["distinct"]
        for action, count in actions.items():
            ts[action].append(count)
    df = pl.DataFrame(ts)
    # There's surely a nice way to do this in polars, but I did not find it.
    # Just get the top TOP columns by last action count.
    col_max = sorted([(col, df[-1][col][-1]) for col in df.columns], key=lambda x: x[1])
    top_TOP = [x[0] for x in col_max[-TOP:]]
    df_TOP = df[top_TOP]
    print(df_TOP)
    plot = df_TOP.plot.line(
        y=df_TOP.columns, width=1200, height=600, title=f"Top {TOP} distinct actions"
    )
    if len(sys.argv) > 1:
        hvplot.save(plot, sys.argv[1])
    else:
        hvplot.show(plot)
