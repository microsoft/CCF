// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace TeeAttestationVerification;

/// <summary>Stable error codes returned by the native TAV ABI.</summary>
public enum ErrorCode
{
    /// <summary>No error.</summary>
    Ok = 0,
    /// <summary>An argument was invalid.</summary>
    InvalidArgument = 1,
    /// <summary>An error accessor received a null error handle.</summary>
    ErrorIsNull = 2,
    /// <summary>A Rust panic was caught at the native ABI boundary.</summary>
    Panic = 3,
    /// <summary>The SNP report identifies an unsupported processor.</summary>
    UnsupportedProcessor = 101,
    /// <summary>The supplied AMD root certificate is invalid.</summary>
    InvalidRootCertificate = 102,
    /// <summary>The AMD certificate chain could not be verified.</summary>
    CertificateChainError = 103,
    /// <summary>The SNP report signature could not be verified.</summary>
    SignatureVerificationError = 104,
    /// <summary>The SNP report TCB values failed verification.</summary>
    TcbVerificationError = 105,
    /// <summary>CBOR processing failed during COSE handling.</summary>
    CoseCbor = 201,
    /// <summary>A COSE or CBOR value had an unexpected type.</summary>
    CoseUnexpectedType = 202,
    /// <summary>The requested COSE algorithm is unsupported.</summary>
    CoseUnsupportedAlgorithm = 203,
    /// <summary>The COSE verification key could not be imported.</summary>
    CoseKeyImport = 204,
    /// <summary>The COSE signature could not be verified.</summary>
    CoseVerification = 205,
    /// <summary>COSE processing failed during CACI verification.</summary>
    CaciCose = 301,
    /// <summary>A certificate failed CACI verification.</summary>
    CaciCertificate = 302,
    /// <summary>The DID x509 trust policy failed.</summary>
    CaciDidX509 = 303,
    /// <summary>The CACI endorsement signature failed verification.</summary>
    CaciSignature = 304,
    /// <summary>The CACI measurement or reference information is invalid.</summary>
    CaciMeasurement = 305,
    /// <summary>The CACI relying-party policy rejected the attestation.</summary>
    CaciPolicy = 306,
}

/// <summary>The CBOR major type represented by a <see cref="CborValue"/>.</summary>
public enum CborKind
{
    /// <summary>A signed integer.</summary>
    Int = 1,
    /// <summary>A CBOR simple value.</summary>
    Simple = 2,
    /// <summary>A byte string.</summary>
    Bytes = 3,
    /// <summary>A UTF-8 text string.</summary>
    Text = 4,
    /// <summary>An array.</summary>
    Array = 5,
    /// <summary>A map.</summary>
    Map = 6,
    /// <summary>A tagged value.</summary>
    Tagged = 7,
}

/// <summary>A COSE signature algorithm supported by TAV verification.</summary>
public enum CoseAlgorithm
{
    /// <summary>ECDSA using P-256 and SHA-256.</summary>
    Es256 = -7,
    /// <summary>ECDSA using P-384 and SHA-384.</summary>
    Es384 = -35,
    /// <summary>ECDSA using P-521 and SHA-512.</summary>
    Es512 = -36,
    /// <summary>RSA-PSS using SHA-256.</summary>
    Ps256 = -37,
    /// <summary>RSA-PSS using SHA-384.</summary>
    Ps384 = -38,
    /// <summary>RSA-PSS using SHA-512.</summary>
    Ps512 = -39,
}

/// <summary>An exception reported by the native TAV verification ABI.</summary>
public sealed class VerifyException : Exception
{
    internal VerifyException(ErrorCode code, string message)
        : base(message)
    {
        Code = code;
    }

    /// <summary>Gets the stable native error code.</summary>
    public ErrorCode Code { get; }
}
