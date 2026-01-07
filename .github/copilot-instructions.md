Never comment on code formatting when performing code reviews.

When shell scripts or bash scripts are created or modified, if they contain any use of the pipe (|) operator, they must also set the pipefail option (set -o pipefail). Remind the PR author if they have missed that. 
