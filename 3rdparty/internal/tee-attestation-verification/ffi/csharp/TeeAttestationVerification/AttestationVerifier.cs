// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace TeeAttestationVerification;

/// <summary>Provides synchronous SNP, CACI, and certificate helper operations.</summary>
public static class AttestationVerifier
{
    private const int TcbVersionLength = 8;
    private const int PolicyDigestLength = 32;
    private const int MaximumMinimumTcbEntries =
        NativeInput.MaximumInputLength / TcbVersionLength;
    private const int MaximumPolicyDigestEntries =
        NativeInput.MaximumInputLength / PolicyDigestLength;

    private static readonly Regex PemCertificatePattern = new(
        "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----",
        RegexOptions.CultureInvariant);

    /// <summary>Splits a PEM bundle into normalized certificate PEM strings.</summary>
    /// <param name="pemBundle">One or more concatenated PEM certificate blocks.</param>
    /// <returns>The certificates in source order.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pemBundle"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="pemBundle"/> is empty.</exception>
    /// <exception cref="FormatException">The bundle is malformed or contains non-certificate content.</exception>
    public static IReadOnlyList<string> SplitPemBundle(string pemBundle)
    {
        ArgumentNullException.ThrowIfNull(pemBundle);
        if (string.IsNullOrWhiteSpace(pemBundle))
        {
            throw new ArgumentException("Certificate bundle PEM is empty.", nameof(pemBundle));
        }

        List<string> certificates = [];
        int consumed = 0;
        foreach (Match match in PemCertificatePattern.Matches(pemBundle))
        {
            RequireOnlyWhitespace(
                pemBundle.AsSpan(consumed, match.Index - consumed));
            try
            {
                using X509Certificate2 certificate = X509Certificate2.CreateFromPem(match.Value);
                certificates.Add(certificate.ExportCertificatePem());
            }
            catch (CryptographicException exception)
            {
                throw new FormatException(
                    $"Failed to parse certificate bundle PEM: {exception.Message}",
                    exception);
            }

            consumed = match.Index + match.Length;
        }

        if (certificates.Count == 0)
        {
            throw new FormatException("Failed to parse certificate bundle PEM: no certificates found.");
        }

        RequireOnlyWhitespace(pemBundle.AsSpan(consumed));
        return certificates.AsReadOnly();
    }

    /// <summary>Authenticates an AMD SEV-SNP report and returns its verified claims.</summary>
    /// <param name="reportBytes">The binary SNP attestation report.</param>
    /// <param name="arkPem">The AMD root key certificate in PEM form.</param>
    /// <param name="askPem">The AMD signing key certificate in PEM form.</param>
    /// <param name="vcekPem">The VCEK leaf certificate in PEM form.</param>
    /// <returns>An owned verified report. Dispose it after use.</returns>
    /// <exception cref="VerifyException">Native parsing or verification fails.</exception>
    public static SnpAttestationReport VerifySnpAttestation(
        ReadOnlyMemory<byte> reportBytes,
        string arkPem,
        string askPem,
        string vcekPem)
    {
        byte[] report = NativeInput.Snapshot(reportBytes, nameof(reportBytes));
        byte[] ark = NativeInput.Utf8(arkPem, nameof(arkPem));
        byte[] ask = NativeInput.Utf8(askPem, nameof(askPem));
        byte[] vcek = NativeInput.Utf8(vcekPem, nameof(vcekPem));
        unsafe
        {
            fixed (byte* reportPointer = report)
            fixed (byte* arkPointer = ark)
            fixed (byte* askPointer = ask)
            fixed (byte* vcekPointer = vcek)
            {
                IntPtr error = NativeMethods.VerifySnpAttestation(
                    (IntPtr)reportPointer,
                    (nuint)report.Length,
                    (IntPtr)arkPointer,
                    (nuint)ark.Length,
                    (IntPtr)askPointer,
                    (nuint)ask.Length,
                    (IntPtr)vcekPointer,
                    (nuint)vcek.Length,
                    out IntPtr verifiedReport);
                NativeResult.ThrowIfError(error);
                return new SnpAttestationReport(verifiedReport);
            }
        }
    }

    private static void RequireOnlyWhitespace(ReadOnlySpan<char> content)
    {
        if (!content.Trim().IsEmpty)
        {
            throw new FormatException(
                "Failed to parse certificate bundle PEM: unexpected content outside certificate blocks.");
        }
    }

    /// <summary>Authenticates a CACI UVM endorsement against a trusted DID x509 policy.</summary>
    /// <param name="uvmEndorsement">The encoded COSE UVM endorsement.</param>
    /// <param name="trustedDidX509">The trusted DID x509 policy string.</param>
    /// <returns>An owned verified CBOR endorsement. Dispose it after use.</returns>
    /// <exception cref="VerifyException">Native parsing or verification fails.</exception>
    public static CborValue VerifyUvmEndorsement(
        ReadOnlyMemory<byte> uvmEndorsement,
        string trustedDidX509)
    {
        byte[] endorsement = NativeInput.Snapshot(
            uvmEndorsement, nameof(uvmEndorsement));
        byte[] trustedDid = NativeInput.Utf8(trustedDidX509, nameof(trustedDidX509));
        unsafe
        {
            fixed (byte* endorsementPointer = endorsement)
            fixed (byte* trustedDidPointer = trustedDid)
            {
                IntPtr error = NativeMethods.VerifyCaciUvmEndorsement(
                    (IntPtr)endorsementPointer,
                    (nuint)endorsement.Length,
                    (IntPtr)trustedDidPointer,
                    (nuint)trustedDid.Length,
                    out IntPtr value);
                NativeResult.ThrowIfError(error);
                return CborValue.FromOwnedHandle(value);
            }
        }
    }

    /// <summary>
    /// Applies the CACI relying-party policy to verified SNP and UVM artifacts.
    /// </summary>
    /// <param name="attestation">A report returned by <see cref="VerifySnpAttestation"/>.</param>
    /// <param name="minimumTcb">
    /// CPUID and eight-byte TCB pairs, or an empty sequence for no minimum. The
    /// Milan/Genoa byte layout is [boot loader, TEE, reserved x4, SNP, microcode];
    /// Turin is [FMC, boot loader, TEE, SNP, reserved x3, microcode]. Duplicate
    /// CPUIDs are rejected. The sequence and TCB bytes are copied before entering
    /// native code.
    /// </param>
    /// <param name="trustedCaciExecutionPolicies">
    /// One or more trusted 32-byte CACI execution-policy digests. The sequence
    /// and digest bytes are copied before entering native code.
    /// </param>
    /// <param name="uvm">A value returned by <see cref="VerifyUvmEndorsement"/>.</param>
    /// <param name="uvmFeed">The required UVM feed identifier.</param>
    /// <param name="minimumSvn">The minimum accepted UVM security version number.</param>
    /// <returns>A copy of the verified 64-byte SNP report data.</returns>
    /// <exception cref="ArgumentNullException">A required reference argument is null.</exception>
    /// <exception cref="ArgumentException">
    /// A TCB value is not eight bytes, a CPUID occurs more than once, the policy
    /// digest collection is empty, or a policy digest is not 32 bytes.
    /// </exception>
    /// <exception cref="VerifyException">Native policy verification fails.</exception>
    public static byte[] VerifyCaciAttestation(
        SnpAttestationReport attestation,
        IEnumerable<(uint Cpuid, ReadOnlyMemory<byte> Tcb)> minimumTcb,
        IEnumerable<ReadOnlyMemory<byte>> trustedCaciExecutionPolicies,
        CborValue uvm,
        string uvmFeed,
        ulong minimumSvn)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        ArgumentNullException.ThrowIfNull(minimumTcb);
        ArgumentNullException.ThrowIfNull(trustedCaciExecutionPolicies);
        ArgumentNullException.ThrowIfNull(uvm);
        (uint[] cpuids, byte[] tcbValues) = SnapshotMinimumTcb(minimumTcb);
        (byte[] policies, int policyCount) =
            SnapshotPolicyDigests(trustedCaciExecutionPolicies);
        byte[] feed = NativeInput.Utf8(uvmFeed, nameof(uvmFeed));

        unsafe
        {
            fixed (uint* cpuidsPointer = cpuids)
            fixed (byte* tcbValuesPointer = tcbValues)
            fixed (byte* policiesPointer = policies)
            fixed (byte* feedPointer = feed)
            {
                IntPtr error = NativeMethods.VerifyCaciAttestation(
                    attestation.Handle,
                    (IntPtr)cpuidsPointer,
                    (IntPtr)tcbValuesPointer,
                    (nuint)cpuids.Length,
                    (IntPtr)policiesPointer,
                    (nuint)policyCount,
                    uvm.Handle,
                    (IntPtr)feedPointer,
                    (nuint)feed.Length,
                    minimumSvn,
                    out IntPtr reportData);
                NativeResult.ThrowIfError(error);
                if (reportData == IntPtr.Zero)
                {
                    throw new InvalidOperationException(
                        "Native CACI verification returned a null report-data buffer.");
                }

                return NativeMemory.CopyOwnedBytes(reportData);
            }
        }
    }

    private static (byte[] Values, int Count) SnapshotPolicyDigests(
        IEnumerable<ReadOnlyMemory<byte>> trustedCaciExecutionPolicies)
    {
        bool hasCount = trustedCaciExecutionPolicies.TryGetNonEnumeratedCount(
            out int count);
        if (!hasCount &&
            trustedCaciExecutionPolicies is IReadOnlyCollection<ReadOnlyMemory<byte>> collection)
        {
            count = collection.Count;
            hasCount = true;
        }

        if (hasCount && count > MaximumPolicyDigestEntries)
        {
            throw new ArgumentOutOfRangeException(
                nameof(trustedCaciExecutionPolicies),
                "CACI policy digests exceed the maximum input size.");
        }

        ReadOnlyMemory<byte>[] digests = trustedCaciExecutionPolicies.ToArray();
        if (digests.Length == 0)
        {
            throw new ArgumentException(
                "At least one CACI policy digest is required.",
                nameof(trustedCaciExecutionPolicies));
        }
        if (digests.Length > MaximumPolicyDigestEntries)
        {
            throw new ArgumentOutOfRangeException(
                nameof(trustedCaciExecutionPolicies),
                "CACI policy digests exceed the maximum input size.");
        }

        byte[] values = new byte[digests.Length * PolicyDigestLength];
        for (int index = 0; index < digests.Length; index++)
        {
            ReadOnlyMemory<byte> digest = digests[index];
            if (digest.Length != PolicyDigestLength)
            {
                throw new ArgumentException(
                    $"CACI policy digest at index {index} must be {PolicyDigestLength} bytes, got {digest.Length}.",
                    nameof(trustedCaciExecutionPolicies));
            }

            digest.Span.CopyTo(
                values.AsSpan(index * PolicyDigestLength, PolicyDigestLength));
        }

        return (values, digests.Length);
    }

    private static (uint[] Cpuids, byte[] Values) SnapshotMinimumTcb(
        IEnumerable<(uint Cpuid, ReadOnlyMemory<byte> Tcb)> minimumTcb)
    {
        bool hasCount = minimumTcb.TryGetNonEnumeratedCount(out int count);
        if (!hasCount &&
            minimumTcb is IReadOnlyCollection<(uint Cpuid, ReadOnlyMemory<byte> Tcb)> collection)
        {
            count = collection.Count;
            hasCount = true;
        }

        if (hasCount && count > MaximumMinimumTcbEntries)
        {
            throw new ArgumentOutOfRangeException(
                nameof(minimumTcb),
                $"Minimum TCB exceeds the {MaximumMinimumTcbEntries}-entry maximum.");
        }

        (uint Cpuid, ReadOnlyMemory<byte> Tcb)[] entries = minimumTcb.ToArray();
        if (entries.Length > MaximumMinimumTcbEntries)
        {
            throw new ArgumentOutOfRangeException(
                nameof(minimumTcb),
                $"Minimum TCB exceeds the {MaximumMinimumTcbEntries}-entry maximum.");
        }

        uint[] cpuids = new uint[entries.Length];
        byte[] values = new byte[entries.Length * TcbVersionLength];
        HashSet<uint> seen = [];

        for (int index = 0; index < entries.Length; index++)
        {
            (uint cpuid, ReadOnlyMemory<byte> tcb) = entries[index];
            if (!seen.Add(cpuid))
            {
                throw new ArgumentException(
                    $"Duplicate minimum TCB CPUID 0x{cpuid:x8}.",
                    nameof(minimumTcb));
            }
            if (tcb.Length != TcbVersionLength)
            {
                throw new ArgumentException(
                    $"Minimum TCB at index {index} must be {TcbVersionLength} bytes, got {tcb.Length}.",
                    nameof(minimumTcb));
            }

            cpuids[index] = cpuid;
            tcb.Span.CopyTo(values.AsSpan(index * TcbVersionLength, TcbVersionLength));
        }

        return (cpuids, values);
    }

}
