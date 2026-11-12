Node operations outside endpoint execution now retry or skip until their next scheduled run instead of aborting when they race with compaction, including snapshot evidence, primary lookup before snapshot fetch, JWT key auto-refresh and network identity fetch.
Backups also no longer abort when a fetched snapshot cannot be written to disk.
