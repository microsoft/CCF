// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace TeeAttestationVerification;

/// <summary>An owned, cryptographically verified AMD SEV-SNP attestation report.</summary>
/// <remarks>Byte-array methods return new managed copies on each call.</remarks>
public sealed class SnpAttestationReport : IDisposable
{
    private readonly object _sync = new();
    private readonly SafeSnpReportHandle _handle;

    internal SnpAttestationReport(IntPtr handle)
    {
        if (handle == IntPtr.Zero)
        {
            throw new InvalidOperationException("Native verification returned a null report.");
        }

        _handle = new SafeSnpReportHandle(handle);
    }

    /// <summary>Gets the report format version.</summary>
    public uint Version => Get(NativeMethods.SnpVersion);
    /// <summary>Gets the guest security version number.</summary>
    public uint GuestSvn => Get(NativeMethods.SnpGuestSvn);
    /// <summary>Gets the raw guest policy value.</summary>
    public ulong Policy => Get(NativeMethods.SnpPolicy);
    /// <summary>Gets the minimum ABI minor version from the guest policy.</summary>
    public byte PolicyAbiMinor => Get(NativeMethods.SnpPolicyAbiMinor);
    /// <summary>Gets the minimum ABI major version from the guest policy.</summary>
    public byte PolicyAbiMajor => Get(NativeMethods.SnpPolicyAbiMajor);
    /// <summary>Gets whether simultaneous multithreading is permitted.</summary>
    public bool PolicySmt => Get(NativeMethods.SnpPolicySmt) != 0;
    /// <summary>Gets whether migration-agent association is permitted.</summary>
    public bool PolicyMigrateMa => Get(NativeMethods.SnpPolicyMigrateMa) != 0;
    /// <summary>Gets whether debugging is permitted.</summary>
    public bool PolicyDebug => Get(NativeMethods.SnpPolicyDebug) != 0;
    /// <summary>Gets whether the guest must remain on one socket.</summary>
    public bool PolicySingleSocket => Get(NativeMethods.SnpPolicySingleSocket) != 0;
    /// <summary>Gets whether CXL devices are permitted.</summary>
    public bool PolicyCxlAllow => Get(NativeMethods.SnpPolicyCxlAllow) != 0;
    /// <summary>Gets whether AES-256-XTS memory encryption is required.</summary>
    public bool PolicyMemAes256Xts => Get(NativeMethods.SnpPolicyMemAes256Xts) != 0;
    /// <summary>Gets whether RAPL is disabled.</summary>
    public bool PolicyRaplDis => Get(NativeMethods.SnpPolicyRaplDis) != 0;
    /// <summary>Gets whether DRAM ciphertext hiding is required.</summary>
    public bool PolicyCiphertextHidingDram =>
        Get(NativeMethods.SnpPolicyCiphertextHidingDram) != 0;
    /// <summary>Gets whether page swapping is disabled.</summary>
    public bool PolicyPageSwapDisable => Get(NativeMethods.SnpPolicyPageSwapDisable) != 0;
    /// <summary>Gets the virtual machine privilege level.</summary>
    public uint Vmpl => Get(NativeMethods.SnpVmpl);
    /// <summary>Gets the report signature algorithm identifier.</summary>
    public uint SignatureAlgorithm => Get(NativeMethods.SnpSignatureAlgorithm);
    /// <summary>Gets the raw platform information value.</summary>
    public ulong PlatformInfo => Get(NativeMethods.SnpPlatformInfo);
    /// <summary>Gets the raw report flags.</summary>
    public uint Flags => Get(NativeMethods.SnpFlags);
    /// <summary>Gets whether the report was signed using an author key.</summary>
    public bool FlagsAuthorKeyEnabled => Get(NativeMethods.SnpFlagsAuthorKeyEnabled) != 0;
    /// <summary>Gets whether the chip key is masked.</summary>
    public bool FlagsMaskChipKey => Get(NativeMethods.SnpFlagsMaskChipKey) != 0;
    /// <summary>Gets the signing-key selector.</summary>
    public byte FlagsSigningKey => Get(NativeMethods.SnpFlagsSigningKey);
    /// <summary>Gets the reported processor family identifier.</summary>
    public byte CpuidFamilyId => Get(NativeMethods.SnpCpuidFamilyId);
    /// <summary>Gets the reported processor model identifier.</summary>
    public byte CpuidModelId => Get(NativeMethods.SnpCpuidModelId);
    /// <summary>Gets the reported processor stepping.</summary>
    public byte CpuidStepping => Get(NativeMethods.SnpCpuidStepping);
    /// <summary>Gets the current firmware build number.</summary>
    public byte CurrentBuild => Get(NativeMethods.SnpCurrentBuild);
    /// <summary>Gets the current firmware minor version.</summary>
    public byte CurrentMinor => Get(NativeMethods.SnpCurrentMinor);
    /// <summary>Gets the current firmware major version.</summary>
    public byte CurrentMajor => Get(NativeMethods.SnpCurrentMajor);
    /// <summary>Gets the committed firmware build number.</summary>
    public byte CommittedBuild => Get(NativeMethods.SnpCommittedBuild);
    /// <summary>Gets the committed firmware minor version.</summary>
    public byte CommittedMinor => Get(NativeMethods.SnpCommittedMinor);
    /// <summary>Gets the committed firmware major version.</summary>
    public byte CommittedMajor => Get(NativeMethods.SnpCommittedMajor);
    /// <summary>Returns a copy of the 16-byte family identifier.</summary>
    public byte[] FamilyId() => GetBytes(NativeMethods.SnpFamilyId);
    /// <summary>Returns a copy of the 16-byte image identifier.</summary>
    public byte[] ImageId() => GetBytes(NativeMethods.SnpImageId);
    /// <summary>Returns a copy of the raw platform TCB version.</summary>
    public byte[] PlatformVersion() => GetBytes(NativeMethods.SnpPlatformVersion);
    /// <summary>Returns a copy of the 64-byte caller-supplied report data.</summary>
    public byte[] ReportData() => GetBytes(NativeMethods.SnpReportData);
    /// <summary>Returns a copy of the 48-byte launch measurement.</summary>
    public byte[] Measurement() => GetBytes(NativeMethods.SnpMeasurement);
    /// <summary>Returns a copy of the 32-byte host data.</summary>
    public byte[] HostData() => GetBytes(NativeMethods.SnpHostData);
    /// <summary>Returns a copy of the 48-byte identity-key digest.</summary>
    public byte[] IdKeyDigest() => GetBytes(NativeMethods.SnpIdKeyDigest);
    /// <summary>Returns a copy of the 48-byte author-key digest.</summary>
    public byte[] AuthorKeyDigest() => GetBytes(NativeMethods.SnpAuthorKeyDigest);
    /// <summary>Returns a copy of the 32-byte report identifier.</summary>
    public byte[] ReportId() => GetBytes(NativeMethods.SnpReportId);
    /// <summary>Returns a copy of the 32-byte migration-agent report identifier.</summary>
    public byte[] ReportIdMa() => GetBytes(NativeMethods.SnpReportIdMa);
    /// <summary>Returns a copy of the reported TCB version.</summary>
    public byte[] ReportedTcb() => GetBytes(NativeMethods.SnpReportedTcb);
    /// <summary>Returns a copy of the 64-byte chip identifier.</summary>
    public byte[] ChipId() => GetBytes(NativeMethods.SnpChipId);
    /// <summary>Returns a copy of the committed TCB version.</summary>
    public byte[] CommittedTcb() => GetBytes(NativeMethods.SnpCommittedTcb);
    /// <summary>Returns a copy of the launch TCB version.</summary>
    public byte[] LaunchTcb() => GetBytes(NativeMethods.SnpLaunchTcb);
    /// <summary>Returns a copy of the report signature R component.</summary>
    public byte[] SignatureR() => GetBytes(NativeMethods.SnpSignatureR);
    /// <summary>Returns a copy of the report signature S component.</summary>
    public byte[] SignatureS() => GetBytes(NativeMethods.SnpSignatureS);

    /// <summary>Releases the verified native report.</summary>
    public void Dispose()
    {
        lock (_sync)
        {
            _handle.Dispose();
        }
    }

    internal SafeSnpReportHandle Handle => _handle;

    private T Get<T>(Func<SafeSnpReportHandle, T> accessor) => accessor(_handle);

    private byte[] GetBytes(BytesAccessor accessor)
    {
        lock (_sync)
        {
            try
            {
                accessor(_handle, out IntPtr data, out nuint length);
                return NativeMemory.CopyBytes(data, length);
            }
            finally
            {
                GC.KeepAlive(_handle);
            }
        }
    }

    private delegate void BytesAccessor(
        SafeSnpReportHandle report,
        out IntPtr data,
        out nuint length);
}
