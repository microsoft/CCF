// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text;

namespace TeeAttestationVerification;

// Connects .NET disposal and finalization to the C ABI destructors for
// Rust-owned objects.
internal sealed class SafeErrorHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeErrorHandle(IntPtr handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.ErrorFree(handle);
        return true;
    }
}

internal sealed class SafeByteBufferHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeByteBufferHandle(IntPtr handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.ByteBufferFree(handle);
        return true;
    }
}

internal sealed class SafeSnpReportHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeSnpReportHandle(IntPtr handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.SnpReportFree(handle);
        return true;
    }
}

internal sealed class SafeCborValueHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeCborValueHandle(IntPtr handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.CborFree(handle);
        return true;
    }
}

// Translates native errors into managed exceptions.
internal static class NativeResult
{
    internal static void ThrowIfError(IntPtr error)
    {
        if (error == IntPtr.Zero)
        {
            return;
        }

        using SafeErrorHandle handle = new(error);
        ErrorCode code = (ErrorCode)NativeMethods.ErrorCode(handle);
        string message = Marshal.PtrToStringUTF8(NativeMethods.ErrorMessage(handle))
            ?? "native verification failed without an error message";
        throw new VerifyException(code, message);
    }
}

// Copies owned buffers and borrowed views from native into managed memory.
internal static class NativeMemory
{
    internal static byte[] CopyOwnedBytes(IntPtr buffer)
    {
        using SafeByteBufferHandle handle = new(buffer);
        return CopyBytes(
            NativeMethods.ByteBufferData(handle),
            NativeMethods.ByteBufferLength(handle));
    }

    internal static byte[] CopyBytes(IntPtr data, nuint length)
    {
        if (length > int.MaxValue)
        {
            throw new InvalidOperationException("Native buffer is too large for a managed array.");
        }

        int managedLength = checked((int)length);
        if (managedLength == 0)
        {
            return [];
        }

        if (data == IntPtr.Zero)
        {
            throw new InvalidOperationException("Native buffer pointer is null.");
        }

        byte[] result = new byte[managedLength];
        Marshal.Copy(data, result, 0, managedLength);
        return result;
    }

    internal static string CopyUtf8(IntPtr data, nuint length)
    {
        byte[] bytes = CopyBytes(data, length);
        return new UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true).GetString(bytes);
    }

    internal static int ToManagedLength(nuint length)
    {
        if (length > int.MaxValue)
        {
            throw new InvalidOperationException("Native length exceeds Int32.MaxValue.");
        }

        return checked((int)length);
    }
}

// Validates and snapshots managed inputs before native calls.
internal static class NativeInput
{
    internal const int MaximumInputLength = 1024 * 1024 * 1024;

    internal static byte[] Snapshot(ReadOnlyMemory<byte> input, string name)
    {
        ValidateLength(input.Length, name);
        return input.ToArray();
    }

    internal static byte[] Utf8(string input, string name)
    {
        ArgumentNullException.ThrowIfNull(input);
        int length = Encoding.UTF8.GetByteCount(input);
        ValidateLength(length, name);
        return Encoding.UTF8.GetBytes(input);
    }

    private static void ValidateLength(int length, string name)
    {
        if (length > MaximumInputLength)
        {
            throw new ArgumentOutOfRangeException(
                name,
                $"Input exceeds the {MaximumInputLength}-byte maximum.");
        }
    }
}
