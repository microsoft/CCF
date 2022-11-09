# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import analyzer

analysis = analyzer.Analyze()

df_sends = analysis.get_df_from_parquet_file("../submitter/cpp_send.parquet")
df_responses = analysis.get_df_from_parquet_file("../submitter/cpp_respond.parquet")

successful_percent = analysis.iter_for_success_and_latency(df_sends, df_responses)

time_spent = analysis.total_time_in_sec(df_sends, df_responses)

col_names = ["Reqs", "Time", "Pass", "Throughput"]
rows = [
    [
        len(df_sends.index),
        round(time_spent, 3),
        round(successful_percent, 1),
        round(len(df_sends.index) / time_spent, 1),
    ]
]
my_table = analysis.customize_table(col_names, rows)

print(my_table)
analysis.plot_throughput_per_block(df_responses, 0.1)

analysis.plot_latency_distribution(0.1)
