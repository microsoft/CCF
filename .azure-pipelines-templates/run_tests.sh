readarray -t TEST_CASES_SPLIT <<< `ctest -N`
for TEST_CASE_RAW in "${TEST_CASES_SPLIT[@]}"; do
    echo $TEST_CASE_RAW
    if [[ "$TEST_CASE_RAW" =~ .*#([0-9]+):\ (.*) ]]; then
        ./tests.sh -VV -T Test -R ${BASH_REMATCH[2]}
    fi
done