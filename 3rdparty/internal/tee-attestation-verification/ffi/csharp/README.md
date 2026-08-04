# TeeAttestationVerification for .NET

Linux x64 .NET 8 bindings for verifying SNP and CACI attestations through the
repository's native C ABI.

## Install

Add the package from your configured NuGet feed:

```bash
dotnet add package TeeAttestationVerification --version 1.0.4
```

The runtime environment must provide:

- a Linux x64 process;
- glibc 2.35 or newer;
- OpenSSL 3 (`libssl.so.3` and `libcrypto.so.3`).

## Verify a CACI attestation

```csharp
using TeeAttestationVerification;

byte[] reportBytes = File.ReadAllBytes("attestation-report.bin");
string arkPem = File.ReadAllText("ark.pem");
string askPem = File.ReadAllText("ask.pem");
string vcekPem = File.ReadAllText("vcek.pem");
byte[] uvmEndorsement = File.ReadAllBytes("uvm-endorsement.cose");
string trustedDidX509 = File.ReadAllText("trusted-did-x509.txt").Trim();
ReadOnlyMemory<byte>[] trustedPolicyDigests =
[
    File.ReadAllBytes("trusted-caci-policy.sha256"),
];
(uint Cpuid, ReadOnlyMemory<byte> Tcb)[] minimumTcb =
[
    (0x00a00f11u, File.ReadAllBytes("minimum-tcb.bin")),
];
string uvmFeed = File.ReadAllText("uvm-feed.txt").Trim();
ulong minimumSvn = ulong.Parse(File.ReadAllText("minimum-svn.txt"));

try
{
    SnpAttestationReport report = AttestationVerifier.VerifySnpAttestation(
        reportBytes,
        arkPem,
        askPem,
        vcekPem);
    CborValue uvm = AttestationVerifier.VerifyUvmEndorsement(
        uvmEndorsement,
        trustedDidX509);

    byte[] reportData = AttestationVerifier.VerifyCaciAttestation(
        report,
        minimumTcb,
        trustedPolicyDigests,
        uvm,
        uvmFeed,
        minimumSvn);

    Console.WriteLine(Convert.ToHexString(reportData));
}
catch (VerifyException error)
{
    Console.Error.WriteLine($"{error.Code}: {error.Message}");
}
```

`VerifySnpAttestation` authenticates the AMD certificate chain and SNP report,
`VerifyUvmEndorsement` authenticates the UVM endorsement, and
`VerifyCaciAttestation` applies the relying-party policy before returning the
verified 64-byte report data. Load the trusted DID, policy digests, minimum TCB,
feed, and minimum SVN from relying-party configuration, not from the attester.

Native calls fail with `DllNotFoundException` when the package does not carry a
native asset for the running platform, or when the OpenSSL 3 runtime libraries
are missing.

## Ownership and errors

All passed values are snapshotted before a synchronous native call, and all
returned values are managed copies or managed wrappers. Native resources held by
managed wrappers are reclaimed by garbage collection; `SnpAttestationReport`,
`CborValue`, and `CoseSign1` also implement `IDisposable` for faster release.
Native failures become `VerifyException` with a stable `ErrorCode`; managed input
errors use standard .NET exceptions.

## Build and test from source

Run from `ffi/csharp`:

```bash
python3 run_tests.py --configuration Release
```

The runner packs a uniquely versioned NuGet into a temporary feed, restores the
public xUnit consumer suite against that exact package, and tests the complete
NuGet → C# → C ABI → Rust path. It also checks the package layout and OpenSSL
dependencies.

Source builds require Rust, the OpenSSL development headers, and `pkg-config`.
The MSBuild project invokes Cargo with `crypto_openssl` for every build.

To create a release package:

```bash
dotnet pack \
  TeeAttestationVerification/TeeAttestationVerification.csproj \
  --configuration Release
```

The native asset is packaged at
`runtimes/linux-x64/native/libtee_attestation_verification_ffi.so`.
