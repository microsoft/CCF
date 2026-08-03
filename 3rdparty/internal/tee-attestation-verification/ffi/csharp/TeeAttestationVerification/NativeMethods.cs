// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;

namespace TeeAttestationVerification;

internal static partial class NativeMethods
{
    // Platform-neutral name: .NET's default resolution probes the
    // platform-appropriate file name and picks the runtimes/<rid>/native asset
    // for the running platform, so the package contents are the only statement
    // of which platforms are supported.
    private const string LibraryName = "tee_attestation_verification_ffi";

    // Handles cross the boundary as SafeHandle so the generated marshaller holds a
    // reference for the duration of the call. The four tav_*_free imports are the
    // only exception; each is annotated where it is declared.

    [LibraryImport(LibraryName, EntryPoint = "tav_error_code")]
    internal static partial int ErrorCode(SafeErrorHandle error);

    [LibraryImport(LibraryName, EntryPoint = "tav_error_message")]
    internal static partial IntPtr ErrorMessage(SafeErrorHandle error);

    // Runs from SafeHandle.ReleaseHandle: the reference count is already zero, so the
    // raw handle is passed and no marshaller reference can be taken.
    [LibraryImport(LibraryName, EntryPoint = "tav_error_free")]
    internal static partial void ErrorFree(IntPtr error);

    [LibraryImport(LibraryName, EntryPoint = "tav_byte_buffer_data")]
    internal static partial IntPtr ByteBufferData(SafeByteBufferHandle buffer);

    [LibraryImport(LibraryName, EntryPoint = "tav_byte_buffer_len")]
    internal static partial nuint ByteBufferLength(SafeByteBufferHandle buffer);

    // Runs from SafeHandle.ReleaseHandle: the reference count is already zero, so the
    // raw handle is passed and no marshaller reference can be taken.
    [LibraryImport(LibraryName, EntryPoint = "tav_byte_buffer_free")]
    internal static partial void ByteBufferFree(IntPtr buffer);

    [LibraryImport(LibraryName, EntryPoint = "tav_verify_snp_attestation")]
    internal static partial IntPtr VerifySnpAttestation(
        IntPtr reportBytes,
        nuint reportLength,
        IntPtr arkPem,
        nuint arkPemLength,
        IntPtr askPem,
        nuint askPemLength,
        IntPtr vcekPem,
        nuint vcekPemLength,
        out IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_version")]
    internal static partial uint SnpVersion(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_guest_svn")]
    internal static partial uint SnpGuestSvn(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy")]
    internal static partial ulong SnpPolicy(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_abi_minor")]
    internal static partial byte SnpPolicyAbiMinor(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_abi_major")]
    internal static partial byte SnpPolicyAbiMajor(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_smt")]
    internal static partial byte SnpPolicySmt(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_migrate_ma")]
    internal static partial byte SnpPolicyMigrateMa(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_debug")]
    internal static partial byte SnpPolicyDebug(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_single_socket")]
    internal static partial byte SnpPolicySingleSocket(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_cxl_allow")]
    internal static partial byte SnpPolicyCxlAllow(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_mem_aes_256_xts")]
    internal static partial byte SnpPolicyMemAes256Xts(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_rapl_dis")]
    internal static partial byte SnpPolicyRaplDis(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_ciphertext_hiding_dram")]
    internal static partial byte SnpPolicyCiphertextHidingDram(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_policy_page_swap_disable")]
    internal static partial byte SnpPolicyPageSwapDisable(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_vmpl")]
    internal static partial uint SnpVmpl(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_signature_algo")]
    internal static partial uint SnpSignatureAlgorithm(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_platform_info")]
    internal static partial ulong SnpPlatformInfo(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_flags")]
    internal static partial uint SnpFlags(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_flags_author_key_en")]
    internal static partial byte SnpFlagsAuthorKeyEnabled(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_flags_mask_chip_key")]
    internal static partial byte SnpFlagsMaskChipKey(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_flags_signing_key")]
    internal static partial byte SnpFlagsSigningKey(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_cpuid_fam_id")]
    internal static partial byte SnpCpuidFamilyId(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_cpuid_mod_id")]
    internal static partial byte SnpCpuidModelId(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_cpuid_step")]
    internal static partial byte SnpCpuidStepping(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_current_build")]
    internal static partial byte SnpCurrentBuild(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_current_minor")]
    internal static partial byte SnpCurrentMinor(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_current_major")]
    internal static partial byte SnpCurrentMajor(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_committed_build")]
    internal static partial byte SnpCommittedBuild(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_committed_minor")]
    internal static partial byte SnpCommittedMinor(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_committed_major")]
    internal static partial byte SnpCommittedMajor(SafeSnpReportHandle report);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_family_id")]
    internal static partial void SnpFamilyId(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_image_id")]
    internal static partial void SnpImageId(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_platform_version")]
    internal static partial void SnpPlatformVersion(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_report_data")]
    internal static partial void SnpReportData(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_measurement")]
    internal static partial void SnpMeasurement(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_host_data")]
    internal static partial void SnpHostData(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_id_key_digest")]
    internal static partial void SnpIdKeyDigest(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_author_key_digest")]
    internal static partial void SnpAuthorKeyDigest(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_report_id")]
    internal static partial void SnpReportId(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_report_id_ma")]
    internal static partial void SnpReportIdMa(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_reported_tcb")]
    internal static partial void SnpReportedTcb(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_chip_id")]
    internal static partial void SnpChipId(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_committed_tcb")]
    internal static partial void SnpCommittedTcb(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_launch_tcb")]
    internal static partial void SnpLaunchTcb(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_signature_r")]
    internal static partial void SnpSignatureR(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_signature_s")]
    internal static partial void SnpSignatureS(
        SafeSnpReportHandle report, out IntPtr data, out nuint length);

    // Runs from SafeHandle.ReleaseHandle: the reference count is already zero, so the
    // raw handle is passed and no marshaller reference can be taken.
    [LibraryImport(LibraryName, EntryPoint = "tav_snp_attestation_report_free")]
    internal static partial void SnpReportFree(IntPtr report);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_from_bytes")]
    internal static partial IntPtr CborFromBytes(
        IntPtr bytes, nuint length, out IntPtr value);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_to_bytes")]
    internal static partial IntPtr CborToBytes(
        SafeCborValueHandle value, out IntPtr bytes);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_kind")]
    internal static partial int CborKind(SafeCborValueHandle value);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_int")]
    internal static partial IntPtr CborInt(SafeCborValueHandle value, out long result);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_simple")]
    internal static partial IntPtr CborSimple(SafeCborValueHandle value, out byte result);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_bytes")]
    internal static partial IntPtr CborBytes(
        SafeCborValueHandle value, out IntPtr data, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_text")]
    internal static partial IntPtr CborText(
        SafeCborValueHandle value, out IntPtr text, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_tag")]
    internal static partial IntPtr CborTag(SafeCborValueHandle value, out ulong tag);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_tagged_payload")]
    internal static partial IntPtr CborTaggedPayload(
        SafeCborValueHandle value, out IntPtr payload);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_len")]
    internal static partial IntPtr CborLength(SafeCborValueHandle value, out nuint length);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_array_at")]
    internal static partial IntPtr CborArrayAt(
        SafeCborValueHandle value, nuint index, out IntPtr child);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_at_int")]
    internal static partial IntPtr CborMapAtInt(
        SafeCborValueHandle value, long key, out IntPtr child);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_at_text")]
    internal static partial IntPtr CborMapAtText(
        SafeCborValueHandle value, IntPtr key, nuint keyLength, out IntPtr child);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_at")]
    internal static partial IntPtr CborMapAt(
        SafeCborValueHandle value, SafeCborValueHandle key, out IntPtr child);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_has_int_key")]
    internal static partial IntPtr CborMapHasInt(
        SafeCborValueHandle value, long key, out byte result);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_has_text_key")]
    internal static partial IntPtr CborMapHasText(
        SafeCborValueHandle value, IntPtr key, nuint keyLength, out byte result);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_has_key")]
    internal static partial IntPtr CborMapHas(
        SafeCborValueHandle value, SafeCborValueHandle key, out byte result);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_entry_at")]
    internal static partial IntPtr CborMapEntryAt(
        SafeCborValueHandle value, nuint index, out IntPtr key, out IntPtr child);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_key_at")]
    internal static partial IntPtr CborMapKeyAt(
        SafeCborValueHandle value, nuint index, out IntPtr key);

    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_map_value_at")]
    internal static partial IntPtr CborMapValueAt(
        SafeCborValueHandle value, nuint index, out IntPtr child);

    [LibraryImport(LibraryName, EntryPoint = "tav_validate_cose_sign1")]
    internal static partial IntPtr ValidateCoseSign1(
        SafeCborValueHandle value, out IntPtr sign1);

    // Runs from SafeHandle.ReleaseHandle: the reference count is already zero, so the
    // raw handle is passed and no marshaller reference can be taken.
    [LibraryImport(LibraryName, EntryPoint = "tav_cbor_value_free")]
    internal static partial void CborFree(IntPtr value);

    [LibraryImport(LibraryName, EntryPoint = "tav_verify_cose_sign1_embedded")]
    internal static partial IntPtr VerifyCoseSign1Embedded(
        SafeCborValueHandle sign1,
        IntPtr spkiDer,
        nuint spkiDerLength,
        int coseAlgorithm);

    [LibraryImport(LibraryName, EntryPoint = "tav_verify_cose_sign1_detached")]
    internal static partial IntPtr VerifyCoseSign1Detached(
        SafeCborValueHandle sign1,
        IntPtr payload,
        nuint payloadLength,
        IntPtr spkiDer,
        nuint spkiDerLength,
        int coseAlgorithm);

    [LibraryImport(LibraryName, EntryPoint = "tav_verify_caci_uvm_endorsement")]
    internal static partial IntPtr VerifyCaciUvmEndorsement(
        IntPtr uvmEndorsement,
        nuint uvmEndorsementLength,
        IntPtr trustedDidX509,
        nuint trustedDidX509Length,
        out IntPtr value);

    [LibraryImport(LibraryName, EntryPoint = "tav_verify_caci_attestation")]
    internal static partial IntPtr VerifyCaciAttestation(
        SafeSnpReportHandle attestation,
        IntPtr minimumTcbCpuids,
        IntPtr minimumTcbValues,
        nuint minimumTcbCount,
        IntPtr trustedPolicyDigests,
        nuint trustedPolicyDigestCount,
        SafeCborValueHandle uvmEndorsement,
        IntPtr uvmFeed,
        nuint uvmFeedLength,
        ulong minimumSvn,
        out IntPtr reportData);
}
