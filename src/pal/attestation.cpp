// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#  include "pal/attestation_virtual.cpp"
#  include "pal/attestation_snp.cpp"

namespace ccf::pal::attestation {

    auto is_snp = access(snp::constants::DEVICE, F_OK) == 0;

    ReportData make_report_data(crypto::Sha256Hash& node_public_key_hash) {
        return is_snp ?
            snp::make_report_data(node_public_key_hash) :
            insecure_virtual::make_report_data(node_public_key_hash);
    }

    ReportData get_report_data(Attestation& attestation) {
        return is_snp ?
            snp::get_report_data(attestation) :
            insecure_virtual::get_report_data(attestation);
    }

    Attestation generate(ReportData& report_data) {
        return is_snp ?
            snp::generate(report_data) :
            insecure_virtual::generate(report_data);
    }

    bool verify(Attestation& attestation) {
        return is_snp ?
            snp::verify(attestation) :
            insecure_virtual::verify(attestation);
    }

    std::optional<MREnclave> get_mrenclave(Attestation& attestation) {
        return is_snp ?
            snp::get_mrenclave(attestation) :
            insecure_virtual::get_mrenclave(attestation);
    }

    std::optional<Measurement> get_measurement(Attestation& attestation) {
        return is_snp ?
            snp::get_measurement(attestation) :
            insecure_virtual::get_measurement(attestation);
    }

    std::optional<HostData> get_host_data(Attestation& attestation) {
        return is_snp ?
            snp::get_host_data(attestation) :
            insecure_virtual::get_host_data(attestation);
    }

    std::optional<SecurityPolicy> get_policy(Attestation& attestation) {
        return is_snp ?
            snp::get_policy(attestation) :
            insecure_virtual::get_policy(attestation);
    }

}