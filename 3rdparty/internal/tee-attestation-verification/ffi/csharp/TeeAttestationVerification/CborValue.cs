// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace TeeAttestationVerification;

/// <summary>An owned view of an immutable native CBOR document.</summary>
/// <remarks>
/// Navigation returns independently owned views that share the parsed document.
/// Dispose every returned value. Byte and text results are managed copies.
/// </remarks>
public sealed class CborValue : IDisposable
{
    private readonly object _sync = new();
    private readonly SafeCborValueHandle _handle;

    private CborValue(SafeCborValueHandle handle)
    {
        if (handle.IsInvalid)
        {
            throw new InvalidOperationException("Native operation returned a null CBOR handle.");
        }

        _handle = handle;
    }

    /// <summary>Gets the CBOR major type.</summary>
    public CborKind Kind => (CborKind)NativeMethods.CborKind(_handle);

    /// <summary>Gets the element count of an array or map.</summary>
    /// <exception cref="VerifyException">This value is not an array or map.</exception>
    public int GetLength()
    {
        IntPtr error = NativeMethods.CborLength(_handle, out nuint nativeLength);
        NativeResult.ThrowIfError(error);
        return NativeMemory.ToManagedLength(nativeLength);
    }

    /// <summary>Parses an encoded CBOR document.</summary>
    /// <param name="bytes">The encoded CBOR bytes, copied before native parsing.</param>
    /// <returns>An owned root value.</returns>
    /// <exception cref="VerifyException">The input is not valid supported CBOR.</exception>
    public static unsafe CborValue FromBytes(ReadOnlyMemory<byte> bytes)
    {
        byte[] snapshot = NativeInput.Snapshot(bytes, nameof(bytes));
        fixed (byte* bytesPointer = snapshot)
        {
            IntPtr error = NativeMethods.CborFromBytes(
                (IntPtr)bytesPointer, (nuint)snapshot.Length, out IntPtr value);
            NativeResult.ThrowIfError(error);
            return FromOwnedHandle(value);
        }
    }

    /// <summary>Serializes this value as deterministic CBOR.</summary>
    /// <returns>A managed copy of the encoding.</returns>
    public byte[] ToBytes()
    {
        IntPtr error = NativeMethods.CborToBytes(_handle, out IntPtr bytes);
        NativeResult.ThrowIfError(error);
        if (bytes == IntPtr.Zero)
        {
            throw new InvalidOperationException("Native CBOR serialization returned a null buffer.");
        }

        return NativeMemory.CopyOwnedBytes(bytes);
    }

    /// <summary>Reads this value as a signed integer.</summary>
    /// <exception cref="VerifyException">This value is not an integer.</exception>
    public long GetInt64()
    {
        IntPtr error = NativeMethods.CborInt(_handle, out long value);
        NativeResult.ThrowIfError(error);
        return value;
    }

    /// <summary>Reads this value as a CBOR simple value.</summary>
    /// <exception cref="VerifyException">This value is not a simple value.</exception>
    public byte GetSimpleValue()
    {
        IntPtr error = NativeMethods.CborSimple(_handle, out byte value);
        NativeResult.ThrowIfError(error);
        return value;
    }

    /// <summary>Reads this value as a byte string.</summary>
    /// <returns>A managed copy of the bytes.</returns>
    /// <exception cref="VerifyException">This value is not a byte string.</exception>
    public byte[] GetByteString()
    {
        lock (_sync)
        {
            try
            {
                IntPtr error = NativeMethods.CborBytes(
                    _handle, out IntPtr data, out nuint length);
                NativeResult.ThrowIfError(error);
                return NativeMemory.CopyBytes(data, length);
            }
            finally
            {
                GC.KeepAlive(_handle);
            }
        }
    }

    /// <summary>Reads this value as a UTF-8 text string.</summary>
    /// <exception cref="VerifyException">This value is not a text string.</exception>
    public string GetTextString()
    {
        lock (_sync)
        {
            try
            {
                IntPtr error = NativeMethods.CborText(
                    _handle, out IntPtr text, out nuint length);
                NativeResult.ThrowIfError(error);
                return NativeMemory.CopyUtf8(text, length);
            }
            finally
            {
                GC.KeepAlive(_handle);
            }
        }
    }

    /// <summary>Reads the tag number of a tagged value.</summary>
    /// <exception cref="VerifyException">This value is not tagged.</exception>
    public ulong GetTag()
    {
        IntPtr error = NativeMethods.CborTag(_handle, out ulong tag);
        NativeResult.ThrowIfError(error);
        return tag;
    }

    /// <summary>Returns an independently owned view of a tagged payload.</summary>
    /// <exception cref="VerifyException">This value is not tagged.</exception>
    public CborValue TaggedPayload()
    {
        IntPtr error = NativeMethods.CborTaggedPayload(_handle, out IntPtr payload);
        NativeResult.ThrowIfError(error);
        return FromOwnedHandle(payload);
    }

    /// <summary>Returns an independently owned array element.</summary>
    /// <param name="index">The zero-based array index.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is negative.</exception>
    /// <exception cref="VerifyException">This value is not an array or the index is invalid.</exception>
    public CborValue ArrayAt(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        IntPtr error = NativeMethods.CborArrayAt(
            _handle, (nuint)index, out IntPtr child);
        NativeResult.ThrowIfError(error);
        return FromOwnedHandle(child);
    }

    /// <summary>Returns an independently owned map value selected by an integer key.</summary>
    /// <param name="key">The signed integer key.</param>
    /// <exception cref="VerifyException">This value is not a map or the key is absent.</exception>
    public CborValue MapAt(long key)
    {
        IntPtr error = NativeMethods.CborMapAtInt(_handle, key, out IntPtr child);
        NativeResult.ThrowIfError(error);
        return FromOwnedHandle(child);
    }

    /// <summary>Returns an independently owned map value selected by a text key.</summary>
    /// <param name="key">The text key.</param>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    /// <exception cref="VerifyException">This value is not a map or the key is absent.</exception>
    public unsafe CborValue MapAt(string key)
    {
        byte[] utf8 = NativeInput.Utf8(key, nameof(key));
        fixed (byte* keyPointer = utf8)
        {
            IntPtr error = NativeMethods.CborMapAtText(
                _handle, (IntPtr)keyPointer, (nuint)utf8.Length, out IntPtr child);
            NativeResult.ThrowIfError(error);
            return FromOwnedHandle(child);
        }
    }

    /// <summary>Returns an independently owned map value selected by a CBOR key.</summary>
    /// <param name="key">The CBOR key.</param>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    /// <exception cref="VerifyException">This value is not a map or the key is absent.</exception>
    public CborValue MapAt(CborValue key)
    {
        ArgumentNullException.ThrowIfNull(key);
        IntPtr error = NativeMethods.CborMapAt(
            _handle, key._handle, out IntPtr child);
        NativeResult.ThrowIfError(error);
        return FromOwnedHandle(child);
    }

    /// <summary>Attempts to get a map value selected by an integer key.</summary>
    /// <param name="key">The signed integer key.</param>
    /// <param name="value">The independently owned value when found; otherwise null.</param>
    /// <returns><see langword="true"/> when the key exists; otherwise <see langword="false"/>.</returns>
    public bool TryGetValue(long key, out CborValue? value)
    {
        IntPtr error = NativeMethods.CborMapHasInt(_handle, key, out byte result);
        NativeResult.ThrowIfError(error);
        if (result == 0)
        {
            value = null;
            return false;
        }

        value = MapAt(key);
        return true;
    }

    /// <summary>Attempts to get a map value selected by a text key.</summary>
    /// <param name="key">The text key.</param>
    /// <param name="value">The independently owned value when found; otherwise null.</param>
    /// <returns><see langword="true"/> when the key exists; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    public unsafe bool TryGetValue(string key, out CborValue? value)
    {
        byte[] utf8 = NativeInput.Utf8(key, nameof(key));
        fixed (byte* keyPointer = utf8)
        {
            IntPtr error = NativeMethods.CborMapHasText(
                _handle, (IntPtr)keyPointer, (nuint)utf8.Length, out byte result);
            NativeResult.ThrowIfError(error);
            if (result == 0)
            {
                value = null;
                return false;
            }
        }

        value = MapAt(key);
        return true;
    }

    /// <summary>Attempts to get a map value selected by a CBOR key.</summary>
    /// <param name="key">The CBOR key.</param>
    /// <param name="value">The independently owned value when found; otherwise null.</param>
    /// <returns><see langword="true"/> when the key exists; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    public bool TryGetValue(CborValue key, out CborValue? value)
    {
        ArgumentNullException.ThrowIfNull(key);
        IntPtr error = NativeMethods.CborMapHas(
            _handle, key._handle, out byte result);
        NativeResult.ThrowIfError(error);
        if (result == 0)
        {
            value = null;
            return false;
        }

        value = MapAt(key);
        return true;
    }

    /// <summary>Returns independently owned key and value views for a map entry.</summary>
    /// <param name="index">The zero-based map-entry index.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is negative.</exception>
    /// <exception cref="VerifyException">This value is not a map or the index is invalid.</exception>
    public KeyValuePair<CborValue, CborValue> MapEntryAt(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        IntPtr error = NativeMethods.CborMapEntryAt(
            _handle, (nuint)index, out IntPtr keyPointer, out IntPtr valuePointer);
        NativeResult.ThrowIfError(error);

        CborValue? key = null;
        try
        {
            key = FromOwnedHandle(keyPointer);
            CborValue value = FromOwnedHandle(valuePointer);
            return new(key, value);
        }
        catch
        {
            key?.Dispose();
            throw;
        }
    }

    /// <summary>Returns an independently owned key view for a map entry.</summary>
    public CborValue MapKeyAt(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        IntPtr error = NativeMethods.CborMapKeyAt(
            _handle, (nuint)index, out IntPtr key);
        NativeResult.ThrowIfError(error);
        return FromOwnedHandle(key);
    }

    /// <summary>Returns an independently owned value view for a map entry.</summary>
    public CborValue MapValueAt(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        IntPtr error = NativeMethods.CborMapValueAt(
            _handle, (nuint)index, out IntPtr value);
        NativeResult.ThrowIfError(error);
        return FromOwnedHandle(value);
    }

    /// <summary>Validates this value as COSE_Sign1 and returns an owned view.</summary>
    /// <exception cref="VerifyException">The value is not a valid COSE_Sign1 envelope.</exception>
    public CoseSign1 AsCoseSign1()
    {
        IntPtr error = NativeMethods.ValidateCoseSign1(_handle, out IntPtr sign1);
        NativeResult.ThrowIfError(error);
        return CoseSign1.FromOwnedHandle(sign1);
    }

    /// <summary>Releases this native CBOR view.</summary>
    public void Dispose()
    {
        lock (_sync)
        {
            _handle.Dispose();
        }
    }

    internal static CborValue FromOwnedHandle(IntPtr pointer)
    {
        SafeCborValueHandle? handle = new(pointer);
        try
        {
            CborValue value = new(handle);
            handle = null;
            return value;
        }
        finally
        {
            handle?.Dispose();
        }
    }

    internal SafeCborValueHandle Handle => _handle;
}
