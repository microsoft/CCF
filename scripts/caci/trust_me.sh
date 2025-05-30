#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

DEFAULT_MEMBER="member0"
DEFAULT_ADDRESS="127.0.0.1:443"

member=$DEFAULT_MEMBER
node_rpc_address=${CCF_NODE:-$DEFAULT_ADDRESS}

function usage()
{
    echo "Usage:"
    echo "  $0 [--node $DEFAULT_ADDRESS] [--member $DEFAULT_MEMBER]"
    echo "Submit a set_snp_minimum_tcb_version proposal using the values from the given node's attestation."
    echo "Can also set node address with the CCF_NODE env var."
}

while [ "$1" != "" ]; do
    case $1 in
        -h|-\?|--help)
            usage
            exit 0
            ;;
        -n|--node)
            node_rpc_address="$2"
            shift
            ;;
        -m|--member)
            member="$2"
            shift
            ;;
        *)
            break
    esac
    shift
done

attestation_path="./raw.attestation"
echo "Fetching attestation from ${node_rpc_address} to ${attestation_path}"
curl -k --silent "${node_rpc_address}/node/quotes/self" \
  | jq -r '.raw' \
  | base64 --decode \
  > "${attestation_path}"

# Parsing based on structures defined in attestation_sev_snp.h
# NB: This isn't heavily tested - in practice we only ever see Milan and Genoa
cpuid_fam_id=$((16#$(hexdump --skip 0x188 --length 1 -ve '1/1 "%.2x"' ${attestation_path})))
cpuid_mod_id=$((16#$(hexdump --skip 0x189 --length 1 -ve '1/1 "%.2x"' ${attestation_path})))
cpuid_step=$((16#$(hexdump --skip 0x18A --length 1 -ve '1/1 "%.2x"' ${attestation_path})))

echo "Attestation reports Family=${cpuid_fam_id}, Model=${cpuid_mod_id}"

if [ $cpuid_fam_id -gt 15 ]; then
  cpuid_fam_base=$((15))
  cpuid_fam_ext=$((cpuid_fam_id - 15))
else
  cpuid_fam_base=$cpuid_fam_id
  cpuid_fam_ext=$((0))
fi


cpuid_mod_base=$((cpuid_mod_id % 16))
cpuid_mod_ext=$((cpuid_mod_id / 16))

cpuid=$(printf "0%02x%x0%x%x%x" ${cpuid_fam_ext} ${cpuid_mod_ext} ${cpuid_fam_base} ${cpuid_mod_base} ${cpuid_step} )

echo "CPUID nibbles extracted from ${attestation_path}:"
printf "  Reserved        =  0 (0)\n"
printf "  Extended Family = %2d (%02x) (1 byte)\n" ${cpuid_fam_ext} ${cpuid_fam_ext}
printf "  Extended Model  = %2d (%x)\n" ${cpuid_mod_ext} ${cpuid_mod_ext}
printf "  Reserved        =  0 (0)\n"
printf "  Base Family     = %2d (%x)\n" ${cpuid_fam_base} ${cpuid_fam_base}
printf "  Base Model      = %2d (%x)\n" ${cpuid_mod_base} ${cpuid_mod_base}
printf "  Stepping        = %2d (%x)\n" ${cpuid_step} ${cpuid_step}
echo "Producing hex-string cpuid: ${cpuid}"

# Output each byte of the platform_version field (a TcbVersion) as hex, one-per-line
mapfile -t tcb_version < <(hexdump --skip 0x38 --length 8 -ve '1/1 "%.2x\n"' ${attestation_path})

boot_loader=$((16#${tcb_version[0]}))
tee=$((16#${tcb_version[1]}))
snp=$((16#${tcb_version[6]}))
microcode=$((16#${tcb_version[7]}))

filename="./set_tcb.json"
echo "Writing proposal to ${filename}"
jq -n "{
  actions: [
    {
      name: \"set_snp_minimum_tcb_version\",
      args: {
        cpuid: \"${cpuid}\",
        tcb_version: {
          boot_loader: ${boot_loader},
          tee: ${tee},
          snp: ${snp},
          microcode: ${microcode}
        }
      }
    }
  ]
}" > $filename

PATH_HERE=$(dirname "$(realpath -s "$0")")
echo "Submitting proposal"
"${PATH_HERE}/member_propose.sh" \
  --node "${node_rpc_address}" \
  --member "${member}" \
  --proposal "$filename"

echo "Done"
