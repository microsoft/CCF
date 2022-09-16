// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#  include "pal/attestation_snp.cpp"
#  include "pal/attestation_virtual.cpp"
#else
#  include "pal/attestation_sgx.cpp"
#endif

namespace ccf::pal::attestation {

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
    auto is_snp = access(snp::constants::DEVICE, F_OK) == 0;
#endif

    ReportData make_report_data(crypto::Sha256Hash& node_public_key_hash) {
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
        return is_snp ?
            snp::make_report_data(node_public_key_hash) :
            insecure_virtual::make_report_data(node_public_key_hash);
#else
        return sgx::make_report_data(node_public_key_hash);
#endif
    }

    ReportData get_report_data(Attestation& attestation) {
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
        return is_snp ?
            snp::get_report_data(attestation) :
            insecure_virtual::get_report_data(attestation);
#else
        return sgx::get_report_data(attestation);
#endif
    }

    Attestation generate(ReportData& report_data) {
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
        return is_snp ?
            snp::generate(report_data) :
            insecure_virtual::generate(report_data);
#else
        return sgx::generate(report_data);
#endif
    }

    bool verify(Attestation& attestation) {
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
        return is_snp ?
            snp::verify(attestation) :
            insecure_virtual::verify(attestation);
#else
        return sgx::verify(attestation);
#endif
    }

    std::optional<MREnclave> get_mrenclave(Attestation& attestation) {
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
        return is_snp ?
            snp::get_mrenclave(attestation) :
            insecure_virtual::get_mrenclave(attestation);
#else
        return sgx::get_mrenclave(attestation);
#endif
    }

    std::optional<Measurement> get_measurement(Attestation& attestation) {
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
        return is_snp ?
            snp::get_measurement(attestation) :
            insecure_virtual::get_measurement(attestation);
#else
        return sgx::get_measurement(attestation);
#endif
    }

    std::optional<HostData> get_host_data(Attestation& attestation) {
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
        return is_snp ?
            snp::get_host_data(attestation) :
            insecure_virtual::get_host_data(attestation);
#else
        return sgx::get_host_data(attestation);
#endif
    }

    std::optional<SecurityPolicy> get_policy(Attestation& attestation) {
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
        return is_snp ?
            snp::get_policy(attestation) :
            insecure_virtual::get_policy(attestation);
#else
        return sgx::get_policy(attestation);
#endif
    }

}