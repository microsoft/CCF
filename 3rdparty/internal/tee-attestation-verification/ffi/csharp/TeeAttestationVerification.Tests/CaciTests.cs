// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace TeeAttestationVerification.Tests;

public sealed class CaciTests
{
    [Fact]
    public void CaciVerificationReturnsExpectedReportData()
    {
        CaciInputs input = FixtureData.LoadCaci();
        using SnpAttestationReport attestation =
            AttestationVerifier.VerifySnpAttestation(
                input.Report, input.Ark, input.Ask, input.Vcek);

        using CborValue uvm = AttestationVerifier.VerifyUvmEndorsement(
            input.UvmEndorsement, FixtureData.TrustedDidX509);
        using CoseSign1 sign1 = uvm.AsCoseSign1();
        Assert.NotEmpty(sign1.GetPayload());
        ReadOnlyMemory<byte>[] trustedPolicies = PolicyDigests(input.Policies);

        byte[] reportData = AttestationVerifier.VerifyCaciAttestation(
            attestation,
            input.MinimumTcb,
            trustedPolicies,
            uvm,
            input.UvmFeed,
            input.MinimumSvn);

        Assert.Equal(64, reportData.Length);
        Assert.Equal(attestation.ReportData(), reportData);

        byte[] withoutMinimumTcb = AttestationVerifier.VerifyCaciAttestation(
            attestation,
            [],
            trustedPolicies,
            uvm,
            input.UvmFeed,
            input.MinimumSvn);
        Assert.Equal(reportData, withoutMinimumTcb);
    }

    [Fact]
    public void CaciVerificationForwardsNativeErrorsAndValidatesManagedInputs()
    {
        CaciInputs input = FixtureData.LoadCaci();
        using SnpAttestationReport attestation =
            AttestationVerifier.VerifySnpAttestation(
                input.Report, input.Ark, input.Ask, input.Vcek);
        using CborValue uvm = AttestationVerifier.VerifyUvmEndorsement(
            input.UvmEndorsement, FixtureData.TrustedDidX509);

        VerifyException didError = Assert.Throws<VerifyException>(() =>
            AttestationVerifier.VerifyUvmEndorsement(
                input.UvmEndorsement,
                "did:x509:0:sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                "::eku:1.3.6.1.4.1.311.76.59.1.2"));
        Assert.Equal(ErrorCode.CaciDidX509, didError.Code);
        Assert.NotEmpty(didError.Message);

        byte[] untrustedPolicy = (byte[])input.Policies[0].Clone();
        untrustedPolicy[0] ^= 0xff;
        VerifyException policyError = Assert.Throws<VerifyException>(() =>
            AttestationVerifier.VerifyCaciAttestation(
                attestation,
                input.MinimumTcb,
                PolicyDigests([untrustedPolicy]),
                uvm,
                input.UvmFeed,
                input.MinimumSvn));
        Assert.Equal(ErrorCode.CaciPolicy, policyError.Code);

        Assert.Throws<ArgumentException>(() =>
            AttestationVerifier.VerifyCaciAttestation(
                attestation, input.MinimumTcb, [],
                uvm, input.UvmFeed, input.MinimumSvn));
        Assert.Throws<ArgumentException>(() =>
            AttestationVerifier.VerifyCaciAttestation(
                attestation, input.MinimumTcb, PolicyDigests([new byte[31]]),
                uvm, input.UvmFeed, input.MinimumSvn));

        ReadOnlyMemory<byte>[] trustedPolicies = PolicyDigests(input.Policies);
        ArgumentException invalidLength = Assert.Throws<ArgumentException>(() =>
            AttestationVerifier.VerifyCaciAttestation(
                attestation, [(0x00a00f11u, new ReadOnlyMemory<byte>(new byte[7]))],
                trustedPolicies,
                uvm, input.UvmFeed, input.MinimumSvn));

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            AttestationVerifier.VerifyCaciAttestation(
                attestation, new OversizedMinimumTcbCollection(),
                trustedPolicies,
                uvm, input.UvmFeed, input.MinimumSvn));
        Assert.Contains("must be 8 bytes, got 7", invalidLength.Message);

        Assert.Throws<ArgumentNullException>(() =>
            AttestationVerifier.VerifyCaciAttestation(
                attestation, null!,
                trustedPolicies,
                uvm, input.UvmFeed, input.MinimumSvn));
    }

    [Fact]
    public void DuplicateMinimumTcbCpuidIsRejected()
    {
        CaciInputs input = FixtureData.LoadCaci();
        using SnpAttestationReport attestation =
            AttestationVerifier.VerifySnpAttestation(
                input.Report, input.Ark, input.Ask, input.Vcek);
        using CborValue uvm = AttestationVerifier.VerifyUvmEndorsement(
            input.UvmEndorsement, FixtureData.TrustedDidX509);
        ReadOnlyMemory<byte>[] trustedPolicies = PolicyDigests(input.Policies);

        ArgumentException error = Assert.Throws<ArgumentException>(() =>
            AttestationVerifier.VerifyCaciAttestation(
                attestation,
                [
                    (0x00a00f11u, new ReadOnlyMemory<byte>(new byte[8])),
                    (0x00a00f11u, new ReadOnlyMemory<byte>(new byte[8])),
                ],
                trustedPolicies,
                uvm,
                input.UvmFeed,
                input.MinimumSvn));
        Assert.Contains("Duplicate minimum TCB CPUID 0x00a00f11", error.Message);
    }

    private static ReadOnlyMemory<byte>[] PolicyDigests(byte[][] policies) =>
        policies.Select(bytes => (ReadOnlyMemory<byte>)bytes).ToArray();

    private sealed class OversizedMinimumTcbCollection :
        IReadOnlyCollection<(uint Cpuid, ReadOnlyMemory<byte> Tcb)>
    {
        public int Count => (NativeMaximumInputLength / 8) + 1;

        private const int NativeMaximumInputLength = 1024 * 1024 * 1024;

        public IEnumerator<(uint Cpuid, ReadOnlyMemory<byte> Tcb)> GetEnumerator() =>
            throw new InvalidOperationException("Oversized input must not be enumerated.");

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() =>
            GetEnumerator();
    }
}
