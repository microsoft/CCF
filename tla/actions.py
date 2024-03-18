# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import polars as pl
import sys
from collections import defaultdict
import hvplot
import hvplot.pandas

"""
A little script to plot TLC action count

Run TLC with -coverage 1 (or higher), filter the output through
egrep "<.*\sline.*>:" | grep -v Inv
To only get action states lines, and remove invariants, and then
pipe the output to this script.
"""

TOP=5

if __name__ == "__main__":
    ts = defaultdict(list)
    for line in sys.stdin:
        words = line.split(" ")
        action = words[0][1:]
        unique = words[-1].split(":")[0]
        ts[action].append(int(unique))
    df = pl.DataFrame(ts)
    # There's surely a nice way to do this in polars, but I did not find it.
    # Just get the top TOP columns by last action count.
    col_max = sorted([(col, df[-1][col][-1]) for col in df.columns], key=lambda x: x[1])
    top_TOP = [x[0] for x in col_max[-TOP:]] # + ["AppendRetiredCommitted"]
    df_TOP = df[top_TOP]
    print(df_TOP)
    plot = df_TOP.plot.line(y=df_TOP.columns, width=1200, height=600, title=f"Top {TOP} actions")
    hvplot.show(plot)