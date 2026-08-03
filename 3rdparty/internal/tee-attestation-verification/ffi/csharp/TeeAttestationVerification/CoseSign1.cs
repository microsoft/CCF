// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace TeeAttestationVerification;

/// <summary>An owned native view of a validated COSE_Sign1 envelope.</summary>
public sealed class CoseSign1 : IDisposable
{
    private readonly SafeCborValueHandle _handle;

    private CoseSign1(SafeCborValueHandle handle)
    {
        if (handle.IsInvalid)
        {
            throw new InvalidOperationException("Native COSE validation returned a null value.");
        }

        _handle = handle;
    }

    /// <summary>Returns a managed copy of the encoded protected header.</summary>
    public byte[] GetProtectedBytes()
    {
        using CborValue value = ArrayAt(0);
        return value.GetByteString();
    }

    /// <summary>Returns an independently owned view of the unprotected header map.</summary>
    public CborValue GetUnprotectedHeader() => ArrayAt(1);

    /// <summary>Returns a managed copy of the embedded payload.</summary>
    /// <exception cref="VerifyException">The envelope has no embedded byte-string payload.</exception>
    public byte[] GetPayload()
    {
        using CborValue value = ArrayAt(2);
        return value.GetByteString();
    }

    /// <summary>Returns a managed copy of the signature bytes.</summary>
    public byte[] GetSignature()
    {
        using CborValue value = ArrayAt(3);
        return value.GetByteString();
    }

    /// <summary>Parses and returns the protected header as an owned CBOR value.</summary>
    public CborValue GetProtectedHeader() => CborValue.FromBytes(GetProtectedBytes());

    /// <summary>Verifies a COSE_Sign1 envelope with an embedded payload.</summary>
    /// <param name="spkiDer">The verification public key in SubjectPublicKeyInfo DER form.</param>
    /// <param name="coseAlgorithm">The signature algorithm required by the relying party.</param>
    /// <exception cref="VerifyException">Key import, envelope validation, or signature verification fails.</exception>
    public void VerifyEmbedded(
        ReadOnlyMemory<byte> spkiDer,
        CoseAlgorithm coseAlgorithm)
    {
        byte[] key = NativeInput.Snapshot(spkiDer, nameof(spkiDer));
        unsafe
        {
            fixed (byte* keyPointer = key)
            {
                IntPtr error = NativeMethods.VerifyCoseSign1Embedded(
                    _handle,
                    (IntPtr)keyPointer,
                    (nuint)key.Length,
                    (int)coseAlgorithm);
                NativeResult.ThrowIfError(error);
            }
        }
    }

    /// <summary>Verifies a COSE_Sign1 envelope with a detached payload.</summary>
    /// <param name="payload">The detached payload bytes.</param>
    /// <param name="spkiDer">The verification public key in SubjectPublicKeyInfo DER form.</param>
    /// <param name="coseAlgorithm">The signature algorithm required by the relying party.</param>
    /// <exception cref="VerifyException">Key import, envelope validation, or signature verification fails.</exception>
    public void VerifyDetached(
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> spkiDer,
        CoseAlgorithm coseAlgorithm)
    {
        byte[] payloadSnapshot = NativeInput.Snapshot(payload, nameof(payload));
        byte[] key = NativeInput.Snapshot(spkiDer, nameof(spkiDer));
        unsafe
        {
            fixed (byte* payloadPointer = payloadSnapshot)
            fixed (byte* keyPointer = key)
            {
                IntPtr error = NativeMethods.VerifyCoseSign1Detached(
                    _handle,
                    (IntPtr)payloadPointer,
                    (nuint)payloadSnapshot.Length,
                    (IntPtr)keyPointer,
                    (nuint)key.Length,
                    (int)coseAlgorithm);
                NativeResult.ThrowIfError(error);
            }
        }
    }

    /// <summary>Releases this native COSE_Sign1 view.</summary>
    public void Dispose() => _handle.Dispose();

    private CborValue ArrayAt(int index)
    {
        IntPtr error = NativeMethods.CborArrayAt(
            _handle, (nuint)index, out IntPtr value);
        NativeResult.ThrowIfError(error);
        return CborValue.FromOwnedHandle(value);
    }

    internal static CoseSign1 FromOwnedHandle(IntPtr pointer)
    {
        SafeCborValueHandle? handle = new(pointer);
        try
        {
            CoseSign1 value = new(handle);
            handle = null;
            return value;
        }
        finally
        {
            handle?.Dispose();
        }
    }
}
