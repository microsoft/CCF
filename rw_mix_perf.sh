function get_throughput()
{
  prefix=$1
  shift
  echo $prefix
  cmd="python /home/azureuser/eddy/CCF/tests/infra/basicperf.py -b . -c ./submit --host-log-level info --enclave-log-level info --worker-threads 10 --constitution /home/azureuser/eddy/CCF/samples/constitutions/default/actions.js --constitution /home/azureuser/eddy/CCF/samples/constitutions/default/validate.js --constitution /home/azureuser/eddy/CCF/samples/constitutions/default/resolve.js --constitution /home/azureuser/eddy/CCF/samples/constitutions/default/apply.js --label pi_basic_mt_sgx_cft^ --snapshot-tx-interval 10000 --package samples/apps/basic/libbasic -e release -t sgx --client-timeout-s 180 -n ssh://${NODE_0} -n ssh://${NODE_1} -n ssh://${NODE_2} $@"
  echo "Running: $cmd"
  result=$($cmd | grep -A 4 "Average throughput")
  echo "$result"
}

# Splitting 2,400,000 requests between writes and reads
# NB: Not any more

get_throughput "100% writes" --workspace /home/azureuser/eddy/write_100_sgx --client-def 6,write,200000,primary

# get_throughput "75% writes, 25% reads" --workspace /home/azureuser/eddy/write_75 --client-def 6,write,300000,primary --client-def 12,read,50000,backup

get_throughput "50% writes, 50% reads" --workspace /home/azureuser/eddy/write_50_sgx --client-def 6,write,200000,primary --client-def 12,read,200000,backup

# get_throughput "25% writes, 75% reads" --workspace /home/azureuser/eddy/write_25 --client-def 6,write,100000,primary --client-def 12,read,150000,backup

get_throughput "100% reads" --workspace /home/azureuser/eddy/write_0_sgx --client-def 12,read,200000,backup