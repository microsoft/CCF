// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Globalization;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace TeeAttestationVerification.Tests;

internal static class FixtureData
{
    internal const string TrustedDidX509 =
        "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s" +
        "::eku:1.3.6.1.4.1.311.76.59.1.2";

    internal static readonly string RepositoryRoot =
        Assembly.GetExecutingAssembly()
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .Single(attribute => attribute.Key == "RepositoryRoot")
            .Value!;

    internal static MilanInputs LoadMilan()
    {
        return new(
            ReadBytes("attestation/tests/test_data/milan_attestation_report.bin"),
            ReadText("attestation/src/pinned_arks/milan_ark.pem"),
            ReadText("attestation/tests/test_data/milan_ask.pem"),
            ReadText("attestation/tests/test_data/milan_vcek.pem"));
    }

    internal static CaciInputs LoadCaci()
    {
        using JsonDocument manifest = JsonDocument.Parse(
            ReadText("demos/caci-attestation-verify/test-data/manifest.json"));
        using JsonDocument hostAmdCert = JsonDocument.Parse(
            Convert.FromBase64String(RemoveWhitespace(
                ReadText("demos/caci-attestation-verify/test-data/host-amd-cert.base64"))));

        string vcek = hostAmdCert.RootElement.GetProperty("vcekCert").GetString()!;
        string chain = hostAmdCert.RootElement.GetProperty("certificateChain").GetString()!;
        IReadOnlyList<string> split = AttestationVerifier.SplitPemBundle(chain);

        JsonElement root = manifest.RootElement;
        (uint Cpuid, ReadOnlyMemory<byte> Tcb)[] minimumTcb =
            root.GetProperty("minimum_tcb")
                .EnumerateObject()
                .Select(entry => (
                    uint.Parse(entry.Name, NumberStyles.HexNumber, CultureInfo.InvariantCulture),
                    (ReadOnlyMemory<byte>)Convert.FromHexString(entry.Value.GetString()!)))
                .ToArray();
        byte[][] policies = root.GetProperty("trusted_caci_execution_policies")
            .EnumerateArray()
            .Select(item => Convert.FromHexString(item.GetString()!))
            .ToArray();

        return new(
            Convert.FromHexString(RemoveWhitespace(
                ReadText("demos/caci-attestation-verify/test-data/aci-report.hex"))),
            split[1],
            split[0],
            vcek,
            Convert.FromBase64String(RemoveWhitespace(
                ReadText("demos/caci-attestation-verify/test-data/reference-info.base64"))),
            minimumTcb,
            policies,
            root.GetProperty("uvm_feed").GetString()!,
            root.GetProperty("minimum_svn").GetUInt64());
    }

    internal static byte[] PemToDer(string pem)
    {
        using X509Certificate2 certificate = X509Certificate2.CreateFromPem(pem);
        return certificate.RawData;
    }

    internal static string ReadText(string relativePath) =>
        File.ReadAllText(Path.Combine(RepositoryRoot, relativePath), Encoding.UTF8);

    internal static byte[] ReadBytes(string relativePath) =>
        File.ReadAllBytes(Path.Combine(RepositoryRoot, relativePath));

    internal static string RemoveWhitespace(string text) =>
        string.Concat(text.Where(character => !char.IsWhiteSpace(character)));
}

internal sealed record MilanInputs(byte[] Report, string Ark, string Ask, string Vcek);

internal sealed record CaciInputs(
    byte[] Report,
    string Ark,
    string Ask,
    string Vcek,
    byte[] UvmEndorsement,
    (uint Cpuid, ReadOnlyMemory<byte> Tcb)[] MinimumTcb,
    byte[][] Policies,
    string UvmFeed,
    ulong MinimumSvn);
