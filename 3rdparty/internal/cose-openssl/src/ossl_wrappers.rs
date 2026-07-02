use openssl_sys as ossl;
use std::ffi::CString;
use std::marker::PhantomData;
use std::ptr;

// Not exposed by openssl-sys 0.9, but available at link time (OpenSSL 3.0+).
unsafe extern "C" {
    fn EVP_PKEY_is_a(
        pkey: *const ossl::EVP_PKEY,
        name: *const std::ffi::c_char,
    ) -> std::ffi::c_int;

    fn EVP_PKEY_get_group_name(
        pkey: *const ossl::EVP_PKEY,
        name: *mut std::ffi::c_char,
        name_sz: usize,
        gname_len: *mut usize,
    ) -> std::ffi::c_int;

    fn ERR_error_string_n(
        e: std::ffi::c_ulong,
        buf: *mut std::ffi::c_char,
        len: usize,
    );
}

/// Drain the OpenSSL error queue and return the last (newest) error.
pub(crate) fn ossl_err_string() -> String {
    unsafe {
        let mut last_code: std::ffi::c_ulong = 0;
        loop {
            let code = ossl::ERR_get_error();
            if code == 0 {
                break;
            }
            last_code = code;
        }
        if last_code == 0 {
            return "(no OpenSSL error)".to_string();
        }
        let mut buf = [0u8; 256];
        ERR_error_string_n(
            last_code,
            buf.as_mut_ptr() as *mut std::ffi::c_char,
            buf.len(),
        );
        std::ffi::CStr::from_ptr(buf.as_ptr() as *const std::ffi::c_char)
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(feature = "pqc")]
#[derive(Debug)]
pub enum WhichMLDSA {
    P44,
    P65,
    P87,
}

#[cfg(feature = "pqc")]
impl WhichMLDSA {
    fn openssl_str(&self) -> &'static str {
        match self {
            WhichMLDSA::P44 => "ML-DSA-44",
            WhichMLDSA::P65 => "ML-DSA-65",
            WhichMLDSA::P87 => "ML-DSA-87",
        }
    }
}

#[derive(Debug)]
pub enum WhichRSA {
    PS256,
    PS384,
    PS512,
}

impl WhichRSA {
    fn key_bits(&self) -> u32 {
        match self {
            WhichRSA::PS256 => 2048,
            WhichRSA::PS384 => 3072,
            WhichRSA::PS512 => 4096,
        }
    }
}

#[derive(Debug)]
pub enum WhichEC {
    P256,
    P384,
    P521,
}

impl WhichEC {
    fn openssl_str(&self) -> &'static str {
        match self {
            WhichEC::P256 => "P-256",
            WhichEC::P384 => "P-384",
            WhichEC::P521 => "P-521",
        }
    }

    fn openssl_group(&self) -> &'static str {
        match self {
            WhichEC::P256 => "prime256v1",
            WhichEC::P384 => "secp384r1",
            WhichEC::P521 => "secp521r1",
        }
    }
}

#[derive(Debug)]
pub enum KeyType {
    EC(WhichEC),
    RSA(WhichRSA),

    #[cfg(feature = "pqc")]
    MLDSA(WhichMLDSA),
}

#[derive(Debug)]
pub struct EvpKey {
    pub key: *mut ossl::EVP_PKEY,
    pub typ: KeyType,
}

impl EvpKey {
    pub fn new(typ: KeyType) -> Result<Self, String> {
        unsafe {
            let key = match &typ {
                KeyType::EC(which) => {
                    let crv = CString::new(which.openssl_str()).unwrap();
                    let alg = CString::new("EC").unwrap();
                    ossl::EVP_PKEY_Q_keygen(
                        ptr::null_mut(),
                        ptr::null_mut(),
                        alg.as_ptr(),
                        crv.as_ptr(),
                    )
                }

                KeyType::RSA(which) => {
                    let alg = CString::new("RSA").unwrap();
                    ossl::EVP_PKEY_Q_keygen(
                        ptr::null_mut(),
                        ptr::null_mut(),
                        alg.as_ptr(),
                        which.key_bits() as std::ffi::c_uint,
                    )
                }

                #[cfg(feature = "pqc")]
                KeyType::MLDSA(which) => {
                    let alg = CString::new(which.openssl_str()).unwrap();
                    ossl::EVP_PKEY_Q_keygen(
                        ptr::null_mut(),
                        ptr::null_mut(),
                        alg.as_ptr(),
                    )
                }
            };

            if key.is_null() {
                return Err(format!(
                    "EVP_PKEY_Q_keygen failed: {}",
                    ossl_err_string()
                ));
            }

            Ok(EvpKey { key, typ })
        }
    }

    /// Create an `EvpKey` from a DER-encoded SubjectPublicKeyInfo.
    /// Automatically detects key type (EC curve or ML-DSA variant).
    pub fn from_der_public(der: &[u8]) -> Result<Self, String> {
        let key = unsafe {
            let mut ptr = der.as_ptr();
            let key =
                ossl::d2i_PUBKEY(ptr::null_mut(), &mut ptr, der.len() as i64);
            if key.is_null() {
                return Err(format!(
                    "d2i_PUBKEY failed: {}",
                    ossl_err_string()
                ));
            }
            key
        };

        let typ = match Self::detect_key_type_raw(key) {
            Ok(t) => t,
            Err(e) => {
                unsafe {
                    ossl::EVP_PKEY_free(key);
                }
                return Err(e);
            }
        };

        Ok(EvpKey { key, typ })
    }

    /// Create an `EvpKey` from a DER-encoded private key
    /// (PKCS#8 or traditional format).
    /// Automatically detects key type (EC curve or ML-DSA variant).
    pub fn from_der_private(der: &[u8]) -> Result<Self, String> {
        let key = unsafe {
            let mut ptr = der.as_ptr();
            let key = ossl::d2i_AutoPrivateKey(
                ptr::null_mut(),
                &mut ptr,
                der.len() as i64,
            );
            if key.is_null() {
                return Err(format!(
                    "d2i_AutoPrivateKey failed: {}",
                    ossl_err_string()
                ));
            }
            key
        };

        let typ = match Self::detect_key_type_raw(key) {
            Ok(t) => t,
            Err(e) => {
                unsafe {
                    ossl::EVP_PKEY_free(key);
                }
                return Err(e);
            }
        };

        Ok(EvpKey { key, typ })
    }

    fn detect_key_type_raw(
        pkey: *mut ossl::EVP_PKEY,
    ) -> Result<KeyType, String> {
        unsafe {
            let rsa = CString::new("RSA").unwrap();
            if EVP_PKEY_is_a(pkey as *const _, rsa.as_ptr()) == 1 {
                let bits = ossl::EVP_PKEY_bits(pkey);
                let which = match bits {
                    ..=2048 => WhichRSA::PS256,
                    2049..=3072 => WhichRSA::PS384,
                    _ => WhichRSA::PS512,
                };
                return Ok(KeyType::RSA(which));
            }

            let ec = CString::new("EC").unwrap();
            if EVP_PKEY_is_a(pkey as *const _, ec.as_ptr()) == 1 {
                let mut buf = [0u8; 64];
                let mut len: usize = 0;
                if EVP_PKEY_get_group_name(
                    pkey as *const _,
                    buf.as_mut_ptr() as *mut std::ffi::c_char,
                    buf.len(),
                    &mut len,
                ) != 1
                {
                    return Err(format!(
                        "EVP_PKEY_get_group_name failed: {}",
                        ossl_err_string()
                    ));
                }
                let group = std::str::from_utf8(&buf[..len])
                    .map_err(|_| "EC group name is not UTF-8".to_string())?;

                for variant in [WhichEC::P256, WhichEC::P384, WhichEC::P521] {
                    if group == variant.openssl_group() {
                        return Ok(KeyType::EC(variant));
                    }
                }
                return Err(format!("Unsupported EC curve: {}", group));
            }

            #[cfg(feature = "pqc")]
            for variant in [WhichMLDSA::P44, WhichMLDSA::P65, WhichMLDSA::P87] {
                let cname = CString::new(variant.openssl_str()).unwrap();
                if EVP_PKEY_is_a(pkey as *const _, cname.as_ptr()) == 1 {
                    return Ok(KeyType::MLDSA(variant));
                }
            }

            Err("Unsupported key type".to_string())
        }
    }

    /// Export the public key as DER-encoded SubjectPublicKeyInfo.
    pub fn to_der_public(&self) -> Result<Vec<u8>, String> {
        unsafe {
            let mut der_ptr: *mut u8 = ptr::null_mut();
            let len = ossl::i2d_PUBKEY(self.key, &mut der_ptr);

            if len <= 0 || der_ptr.is_null() {
                return Err(format!(
                    "i2d_PUBKEY returned {}: {}",
                    len,
                    ossl_err_string()
                ));
            }

            // Copy the DER data into a Vec and free the OpenSSL-allocated memory
            let der_slice = std::slice::from_raw_parts(der_ptr, len as usize);
            let der = der_slice.to_vec();
            ossl::CRYPTO_free(
                der_ptr as *mut std::ffi::c_void,
                concat!(file!(), "\0").as_ptr() as *const i8,
                line!() as i32,
            );

            Ok(der)
        }
    }

    /// Export the private key as DER-encoded traditional format.
    pub fn to_der_private(&self) -> Result<Vec<u8>, String> {
        unsafe {
            let mut der_ptr: *mut u8 = ptr::null_mut();
            let len = ossl::i2d_PrivateKey(self.key, &mut der_ptr);

            if len <= 0 || der_ptr.is_null() {
                return Err(format!(
                    "i2d_PrivateKey returned {}: {}",
                    len,
                    ossl_err_string()
                ));
            }

            let der_slice = std::slice::from_raw_parts(der_ptr, len as usize);
            let der = der_slice.to_vec();
            ossl::CRYPTO_free(
                der_ptr as *mut std::ffi::c_void,
                concat!(file!(), "\0").as_ptr() as *const i8,
                line!() as i32,
            );

            Ok(der)
        }
    }

    /// Create an `EvpKey` from a PEM-encoded public key.
    pub fn from_pem_public(pem: &[u8]) -> Result<Self, String> {
        let pem_len: std::ffi::c_int = pem.len().try_into().map_err(|_| {
            format!("PEM input too large ({} bytes)", pem.len())
        })?;
        let key = unsafe {
            let bio = ossl::BIO_new_mem_buf(
                pem.as_ptr() as *const std::ffi::c_void,
                pem_len,
            );
            if bio.is_null() {
                return Err(format!(
                    "BIO_new_mem_buf failed: {}",
                    ossl_err_string()
                ));
            }
            let key = ossl::PEM_read_bio_PUBKEY(
                bio,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
            );
            ossl::BIO_free_all(bio);
            if key.is_null() {
                return Err(format!(
                    "PEM_read_bio_PUBKEY failed: {}",
                    ossl_err_string()
                ));
            }
            key
        };

        let typ = match Self::detect_key_type_raw(key) {
            Ok(t) => t,
            Err(e) => {
                unsafe { ossl::EVP_PKEY_free(key) };
                return Err(e);
            }
        };

        Ok(EvpKey { key, typ })
    }

    /// Create an `EvpKey` from a PEM-encoded private key.
    pub fn from_pem_private(pem: &[u8]) -> Result<Self, String> {
        let pem_len: std::ffi::c_int = pem.len().try_into().map_err(|_| {
            format!("PEM input too large ({} bytes)", pem.len())
        })?;
        let key = unsafe {
            let bio = ossl::BIO_new_mem_buf(
                pem.as_ptr() as *const std::ffi::c_void,
                pem_len,
            );
            if bio.is_null() {
                return Err(format!(
                    "BIO_new_mem_buf failed: {}",
                    ossl_err_string()
                ));
            }
            let key = ossl::PEM_read_bio_PrivateKey(
                bio,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
            );
            ossl::BIO_free_all(bio);
            if key.is_null() {
                return Err(format!(
                    "PEM_read_bio_PrivateKey failed: {}",
                    ossl_err_string()
                ));
            }
            key
        };

        let typ = match Self::detect_key_type_raw(key) {
            Ok(t) => t,
            Err(e) => {
                unsafe { ossl::EVP_PKEY_free(key) };
                return Err(e);
            }
        };

        Ok(EvpKey { key, typ })
    }

    /// Extract the public key from a PEM-encoded X.509 certificate.
    pub fn from_pem_cert(pem: &[u8]) -> Result<Self, String> {
        let pem_len: std::ffi::c_int = pem.len().try_into().map_err(|_| {
            format!("Certificate too large ({} bytes)", pem.len())
        })?;

        unsafe {
            let bio = ossl::BIO_new_mem_buf(
                pem.as_ptr() as *const std::ffi::c_void,
                pem_len,
            );
            if bio.is_null() {
                return Err(format!(
                    "BIO_new_mem_buf failed: {}",
                    ossl_err_string()
                ));
            }
            let cert = ossl::PEM_read_bio_X509(
                bio,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
            );
            ossl::BIO_free_all(bio);
            if cert.is_null() {
                return Err(format!(
                    "PEM_read_bio_X509 failed: {}",
                    ossl_err_string()
                ));
            }

            Self::pubkey_from_x509(cert)
        }
    }

    /// Extract the public key from a DER-encoded X.509 certificate.
    pub fn from_der_cert(der: &[u8]) -> Result<Self, String> {
        unsafe {
            let mut ptr = der.as_ptr();
            let cert = ossl::d2i_X509(
                ptr::null_mut(),
                &mut ptr,
                der.len() as std::ffi::c_long,
            );
            if cert.is_null() {
                return Err(format!("d2i_X509 failed: {}", ossl_err_string()));
            }

            Self::pubkey_from_x509(cert)
        }
    }

    /// Extract the public key from a parsed X509 and free the cert.
    unsafe fn pubkey_from_x509(cert: *mut ossl::X509) -> Result<Self, String> {
        unsafe {
            let key = ossl::X509_get_pubkey(cert);
            ossl::X509_free(cert);
            if key.is_null() {
                return Err(format!(
                    "X509_get_pubkey failed: {}",
                    ossl_err_string()
                ));
            }

            let typ = match Self::detect_key_type_raw(key) {
                Ok(t) => t,
                Err(e) => {
                    ossl::EVP_PKEY_free(key);
                    return Err(e);
                }
            };

            Ok(EvpKey { key, typ })
        }
    }

    /// Export the public key as PEM.
    pub fn to_pem_public(&self) -> Result<Vec<u8>, String> {
        unsafe {
            let bio = ossl::BIO_new(ossl::BIO_s_mem());
            if bio.is_null() {
                return Err(format!("BIO_new failed: {}", ossl_err_string()));
            }
            if ossl::PEM_write_bio_PUBKEY(bio, self.key) != 1 {
                ossl::BIO_free_all(bio);
                return Err(format!(
                    "PEM_write_bio_PUBKEY failed: {}",
                    ossl_err_string()
                ));
            }
            let mut data_ptr: *mut std::ffi::c_char = ptr::null_mut();
            let len = ossl::BIO_get_mem_data(bio, &mut data_ptr);
            if len <= 0 || data_ptr.is_null() {
                ossl::BIO_free_all(bio);
                return Err(format!(
                    "BIO_get_mem_data returned {}: {}",
                    len,
                    ossl_err_string()
                ));
            }
            let pem =
                std::slice::from_raw_parts(data_ptr as *const u8, len as usize)
                    .to_vec();
            ossl::BIO_free_all(bio);
            Ok(pem)
        }
    }

    /// Export the private key as PEM (unencrypted PKCS#8).
    pub fn to_pem_private(&self) -> Result<Vec<u8>, String> {
        unsafe {
            let bio = ossl::BIO_new(ossl::BIO_s_mem());
            if bio.is_null() {
                return Err(format!("BIO_new failed: {}", ossl_err_string()));
            }
            if ossl::PEM_write_bio_PrivateKey(
                bio,
                self.key,
                ptr::null(),
                ptr::null_mut(),
                0,
                None,
                ptr::null_mut(),
            ) != 1
            {
                ossl::BIO_free_all(bio);
                return Err(format!(
                    "PEM_write_bio_PrivateKey failed: {}",
                    ossl_err_string()
                ));
            }
            let mut data_ptr: *mut std::ffi::c_char = ptr::null_mut();
            let len = ossl::BIO_get_mem_data(bio, &mut data_ptr);
            if len <= 0 || data_ptr.is_null() {
                ossl::BIO_free_all(bio);
                return Err(format!(
                    "BIO_get_mem_data returned {}: {}",
                    len,
                    ossl_err_string()
                ));
            }
            let pem =
                std::slice::from_raw_parts(data_ptr as *const u8, len as usize)
                    .to_vec();
            ossl::BIO_free_all(bio);
            Ok(pem)
        }
    }

    /// Compute the EC field-element byte size from the key's bit size.
    /// Returns an error if the key is not an EC key.
    pub fn ec_field_size(&self) -> Result<usize, String> {
        if !matches!(self.typ, KeyType::EC(_)) {
            return Err("ec_field_size called on a non-EC key".to_string());
        }
        unsafe {
            let bits = ossl::EVP_PKEY_bits(self.key);
            if bits <= 0 {
                return Err(format!(
                    "EVP_PKEY_bits failed: {}",
                    ossl_err_string()
                ));
            }
            Ok(((bits + 7) / 8) as usize)
        }
    }

    /// Return the OpenSSL digest matching the key's COSE algorithm.
    /// Returns null for algorithms that do not use a separate digest
    /// (e.g. ML-DSA).
    pub fn digest(&self) -> *const ossl::EVP_MD {
        unsafe {
            match &self.typ {
                KeyType::EC(WhichEC::P256) => ossl::EVP_sha256(),
                KeyType::EC(WhichEC::P384) => ossl::EVP_sha384(),
                KeyType::EC(WhichEC::P521) => ossl::EVP_sha512(),
                KeyType::RSA(WhichRSA::PS256) => ossl::EVP_sha256(),
                KeyType::RSA(WhichRSA::PS384) => ossl::EVP_sha384(),
                KeyType::RSA(WhichRSA::PS512) => ossl::EVP_sha512(),
                #[cfg(feature = "pqc")]
                KeyType::MLDSA(_) => ptr::null(),
            }
        }
    }
}

impl Drop for EvpKey {
    fn drop(&mut self) {
        unsafe {
            if !self.key.is_null() {
                ossl::EVP_PKEY_free(self.key);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ECDSA signature format conversion (DER <-> IEEE P1363 fixed-size)
// using OpenSSL's ECDSA_SIG API.
//
// OpenSSL produces/consumes DER-encoded ECDSA signatures:
//     SEQUENCE { INTEGER r, INTEGER s }
//
// COSE (RFC 9053) requires the fixed-size (r || s) representation.
// ---------------------------------------------------------------------------

/// Convert a DER-encoded ECDSA signature to fixed-size (r || s).
pub fn ecdsa_der_to_fixed(
    der: &[u8],
    field_size: usize,
) -> Result<Vec<u8>, String> {
    unsafe {
        let mut p = der.as_ptr();
        let sig = ossl::d2i_ECDSA_SIG(
            ptr::null_mut(),
            &mut p,
            der.len() as std::ffi::c_long,
        );
        if sig.is_null() {
            return Err(format!("d2i_ECDSA_SIG failed: {}", ossl_err_string()));
        }

        let mut r: *const ossl::BIGNUM = ptr::null();
        let mut s: *const ossl::BIGNUM = ptr::null();
        ossl::ECDSA_SIG_get0(sig, &mut r, &mut s);

        let mut fixed = vec![0u8; field_size * 2];
        let rc_r = ossl::BN_bn2binpad(
            r,
            fixed.as_mut_ptr(),
            field_size as std::ffi::c_int,
        );
        let rc_s = ossl::BN_bn2binpad(
            s,
            fixed[field_size..].as_mut_ptr(),
            field_size as std::ffi::c_int,
        );
        ossl::ECDSA_SIG_free(sig);

        if rc_r != field_size as std::ffi::c_int
            || rc_s != field_size as std::ffi::c_int
        {
            return Err(format!("BN_bn2binpad failed: {}", ossl_err_string()));
        }

        Ok(fixed)
    }
}

/// Convert a fixed-size (r || s) ECDSA signature to DER.
pub fn ecdsa_fixed_to_der(
    fixed: &[u8],
    field_size: usize,
) -> Result<Vec<u8>, String> {
    if fixed.len() != field_size * 2 {
        return Err(format!(
            "Expected {} byte ECDSA signature, got {}",
            field_size * 2,
            fixed.len()
        ));
    }

    unsafe {
        let r = ossl::BN_bin2bn(
            fixed.as_ptr(),
            field_size as std::ffi::c_int,
            ptr::null_mut(),
        );
        if r.is_null() {
            return Err(format!("BN_bin2bn failed (r): {}", ossl_err_string()));
        }

        let s = ossl::BN_bin2bn(
            fixed[field_size..].as_ptr(),
            field_size as std::ffi::c_int,
            ptr::null_mut(),
        );
        if s.is_null() {
            ossl::BN_free(r);
            return Err(format!("BN_bin2bn failed (s): {}", ossl_err_string()));
        }

        let sig = ossl::ECDSA_SIG_new();
        if sig.is_null() {
            ossl::BN_free(r);
            ossl::BN_free(s);
            return Err(format!("ECDSA_SIG_new failed: {}", ossl_err_string()));
        }

        if ossl::ECDSA_SIG_set0(sig, r, s) != 1 {
            ossl::ECDSA_SIG_free(sig);
            ossl::BN_free(r);
            ossl::BN_free(s);
            return Err(format!(
                "ECDSA_SIG_set0 failed: {}",
                ossl_err_string()
            ));
        }
        // ECDSA_SIG_set0 takes ownership of r and s on success.

        let mut out_ptr: *mut u8 = ptr::null_mut();
        let len = ossl::i2d_ECDSA_SIG(sig, &mut out_ptr);
        ossl::ECDSA_SIG_free(sig);

        if len <= 0 || out_ptr.is_null() {
            return Err(format!("i2d_ECDSA_SIG failed: {}", ossl_err_string()));
        }

        let der = std::slice::from_raw_parts(out_ptr, len as usize).to_vec();
        ossl::CRYPTO_free(
            out_ptr as *mut std::ffi::c_void,
            concat!(file!(), "\0").as_ptr() as *const i8,
            line!() as i32,
        );

        Ok(der)
    }
}

#[derive(Debug)]
pub struct EvpMdContext<T> {
    op: PhantomData<T>,
    pub ctx: *mut ossl::EVP_MD_CTX,
}

pub struct SignOp;
pub struct VerifyOp;

pub trait ContextInit {
    fn init(
        ctx: *mut ossl::EVP_MD_CTX,
        md: *const ossl::EVP_MD,
        key: *mut ossl::EVP_PKEY,
        pctx_out: *mut *mut ossl::EVP_PKEY_CTX,
    ) -> Result<(), i32>;
    fn purpose() -> &'static str;
}

impl ContextInit for SignOp {
    fn init(
        ctx: *mut ossl::EVP_MD_CTX,
        md: *const ossl::EVP_MD,
        key: *mut ossl::EVP_PKEY,
        pctx_out: *mut *mut ossl::EVP_PKEY_CTX,
    ) -> Result<(), i32> {
        unsafe {
            let rc = ossl::EVP_DigestSignInit(
                ctx,
                pctx_out,
                md,
                ptr::null_mut(),
                key,
            );
            match rc {
                1 => Ok(()),
                err => Err(err),
            }
        }
    }
    fn purpose() -> &'static str {
        "Sign"
    }
}

impl ContextInit for VerifyOp {
    fn init(
        ctx: *mut ossl::EVP_MD_CTX,
        md: *const ossl::EVP_MD,
        key: *mut ossl::EVP_PKEY,
        pctx_out: *mut *mut ossl::EVP_PKEY_CTX,
    ) -> Result<(), i32> {
        unsafe {
            let rc = ossl::EVP_DigestVerifyInit(
                ctx,
                pctx_out,
                md,
                ptr::null_mut(),
                key,
            );
            match rc {
                1 => Ok(()),
                err => Err(err),
            }
        }
    }
    fn purpose() -> &'static str {
        "Verify"
    }
}

impl<T: ContextInit> EvpMdContext<T> {
    pub fn new(key: &EvpKey) -> Result<Self, String> {
        Self::new_with_md(key, key.digest())
    }

    /// Create a context with an explicit digest, allowing the caller
    /// to override the digest that `key.digest()` would return.
    pub fn new_with_md(
        key: &EvpKey,
        md: *const ossl::EVP_MD,
    ) -> Result<Self, String> {
        unsafe {
            let ctx = ossl::EVP_MD_CTX_new();
            if ctx.is_null() {
                return Err(format!(
                    "EVP_MD_CTX_new failed: {}",
                    ossl_err_string()
                ));
            }
            let mut pctx: *mut ossl::EVP_PKEY_CTX = ptr::null_mut();
            if let Err(err) = T::init(ctx, md, key.key, &mut pctx) {
                ossl::EVP_MD_CTX_free(ctx);
                return Err(format!(
                    "EVP_Digest{}Init returned {}: {}",
                    T::purpose(),
                    err,
                    ossl_err_string()
                ));
            }
            // For RSA keys, configure PSS padding.
            if matches!(key.typ, KeyType::RSA(_)) && !pctx.is_null() {
                const RSA_PSS_SALTLEN_DIGEST: std::ffi::c_int = -1;
                if ossl::EVP_PKEY_CTX_set_rsa_padding(
                    pctx,
                    ossl::RSA_PKCS1_PSS_PADDING,
                ) != 1
                {
                    ossl::EVP_MD_CTX_free(ctx);
                    return Err(format!(
                        "EVP_PKEY_CTX_set_rsa_padding failed: {}",
                        ossl_err_string()
                    ));
                }
                if ossl::EVP_PKEY_CTX_set_rsa_pss_saltlen(
                    pctx,
                    RSA_PSS_SALTLEN_DIGEST,
                ) != 1
                {
                    ossl::EVP_MD_CTX_free(ctx);
                    return Err(format!(
                        "EVP_PKEY_CTX_set_rsa_pss_saltlen failed: {}",
                        ossl_err_string()
                    ));
                }
            }
            Ok(EvpMdContext {
                op: PhantomData,
                ctx,
            })
        }
    }
}

/// Return the OpenSSL digest for the given COSE RSA-PSS algorithm ID.
pub fn rsa_pss_md_for_cose_alg(
    alg: i64,
) -> Result<*const ossl::EVP_MD, String> {
    unsafe {
        match alg {
            -37 => Ok(ossl::EVP_sha256()),
            -38 => Ok(ossl::EVP_sha384()),
            -39 => Ok(ossl::EVP_sha512()),
            _ => Err(format!("{alg} is not a COSE RSA-PSS algorithm")),
        }
    }
}

impl<T> Drop for EvpMdContext<T> {
    fn drop(&mut self) {
        unsafe {
            if !self.ctx.is_null() {
                ossl::EVP_MD_CTX_free(self.ctx);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg(feature = "pqc")]
    fn create_ml_dsa_keys() {
        assert!(EvpKey::new(KeyType::MLDSA(WhichMLDSA::P44)).is_ok());
        assert!(EvpKey::new(KeyType::MLDSA(WhichMLDSA::P65)).is_ok());
        assert!(EvpKey::new(KeyType::MLDSA(WhichMLDSA::P87)).is_ok());
    }

    #[test]
    fn create_ec_keys() {
        assert!(EvpKey::new(KeyType::EC(WhichEC::P256)).is_ok());
        assert!(EvpKey::new(KeyType::EC(WhichEC::P384)).is_ok());
        assert!(EvpKey::new(KeyType::EC(WhichEC::P521)).is_ok());
    }

    #[test]
    fn create_rsa_keys() {
        assert!(EvpKey::new(KeyType::RSA(WhichRSA::PS256)).is_ok());
        assert!(EvpKey::new(KeyType::RSA(WhichRSA::PS384)).is_ok());
        assert!(EvpKey::new(KeyType::RSA(WhichRSA::PS512)).is_ok());
    }

    #[test]
    fn rsa_key_der_roundtrip() {
        for which in [WhichRSA::PS256, WhichRSA::PS384, WhichRSA::PS512] {
            let key = EvpKey::new(KeyType::RSA(which)).unwrap();
            let der = key.to_der_public().unwrap();
            let imported = EvpKey::from_der_public(&der).unwrap();
            assert!(
                matches!(imported.typ, KeyType::RSA(_)),
                "Expected RSA key type"
            );
            let der2 = imported.to_der_public().unwrap();
            assert_eq!(der, der2);
        }
    }

    #[test]
    fn rsa_key_private_der_roundtrip() {
        for which in [WhichRSA::PS256, WhichRSA::PS384, WhichRSA::PS512] {
            let key = EvpKey::new(KeyType::RSA(which)).unwrap();
            let priv_der = key.to_der_private().unwrap();
            let imported = EvpKey::from_der_private(&priv_der).unwrap();
            assert!(
                matches!(imported.typ, KeyType::RSA(_)),
                "Expected RSA key type"
            );
            let priv_der2 = imported.to_der_private().unwrap();
            assert_eq!(priv_der, priv_der2);

            let pub1 = key.to_der_public().unwrap();
            let pub2 = imported.to_der_public().unwrap();
            assert_eq!(pub1, pub2);
        }
    }

    #[test]
    fn ec_key_from_der_roundtrip() {
        for which in [WhichEC::P256, WhichEC::P384, WhichEC::P521] {
            let key = EvpKey::new(KeyType::EC(which)).unwrap();
            let der = key.to_der_public().unwrap();
            let imported = EvpKey::from_der_public(&der).unwrap();
            assert!(
                matches!(imported.typ, KeyType::EC(_)),
                "Expected EC key type"
            );

            // Verify the reimported key exports the same DER
            let der2 = imported.to_der_public().unwrap();
            assert_eq!(der, der2);
        }
    }

    #[test]
    fn ec_key_from_der_p256() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let der = key.to_der_public().unwrap();
        let imported = EvpKey::from_der_public(&der).unwrap();

        assert!(matches!(imported.typ, KeyType::EC(WhichEC::P256)));
    }

    #[test]
    fn from_der_rejects_garbage() {
        let err =
            EvpKey::from_der_public(&[0xde, 0xad, 0xbe, 0xef]).unwrap_err();
        assert!(
            err.starts_with("d2i_PUBKEY failed: error:"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn from_der_private_rejects_garbage() {
        let err =
            EvpKey::from_der_private(&[0xde, 0xad, 0xbe, 0xef]).unwrap_err();
        assert!(
            err.starts_with("d2i_AutoPrivateKey failed: error:"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn ec_key_private_der_roundtrip() {
        for which in [WhichEC::P256, WhichEC::P384, WhichEC::P521] {
            let key = EvpKey::new(KeyType::EC(which)).unwrap();
            let priv_der = key.to_der_private().unwrap();
            let imported = EvpKey::from_der_private(&priv_der).unwrap();
            assert!(
                matches!(imported.typ, KeyType::EC(_)),
                "Expected EC key type"
            );

            // Private key re-export must be identical.
            let priv_der2 = imported.to_der_private().unwrap();
            assert_eq!(priv_der, priv_der2);

            // Public key extracted from the reimported private key must
            // match the original.
            let pub1 = key.to_der_public().unwrap();
            let pub2 = imported.to_der_public().unwrap();
            assert_eq!(pub1, pub2);
        }
    }

    #[test]
    #[cfg(feature = "pqc")]
    fn ml_dsa_key_from_der_roundtrip() {
        for which in [WhichMLDSA::P44, WhichMLDSA::P65, WhichMLDSA::P87] {
            let key = EvpKey::new(KeyType::MLDSA(which)).unwrap();
            let der = key.to_der_public().unwrap();
            let imported = EvpKey::from_der_public(&der).unwrap();
            assert!(
                matches!(imported.typ, KeyType::MLDSA(_)),
                "Expected ML-DSA key type"
            );
            let der2 = imported.to_der_public().unwrap();
            assert_eq!(der, der2);
        }
    }

    #[test]
    #[cfg(feature = "pqc")]
    fn ml_dsa_key_private_der_roundtrip() {
        for which in [WhichMLDSA::P44, WhichMLDSA::P65, WhichMLDSA::P87] {
            let key = EvpKey::new(KeyType::MLDSA(which)).unwrap();
            let priv_der = key.to_der_private().unwrap();
            let imported = EvpKey::from_der_private(&priv_der).unwrap();
            assert!(
                matches!(imported.typ, KeyType::MLDSA(_)),
                "Expected ML-DSA key type"
            );

            // Private key re-export must be identical.
            let priv_der2 = imported.to_der_private().unwrap();
            assert_eq!(priv_der, priv_der2);

            let pub1 = key.to_der_public().unwrap();
            let pub2 = imported.to_der_public().unwrap();
            assert_eq!(pub1, pub2);
        }
    }

    #[test]
    #[ignore]
    fn intentional_leak_for_sanitizer_validation() {
        // This test intentionally leaks memory to verify sanitizers
        // detect it if not ignored.
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        std::mem::forget(key);
    }

    // ---------------------------------------------------------------
    // Tests verifying exact OpenSSL errors in Err values
    // ---------------------------------------------------------------

    #[test]
    fn from_der_public_error_has_ossl_detail() {
        let err =
            EvpKey::from_der_public(&[0xde, 0xad, 0xbe, 0xef]).unwrap_err();
        assert!(
            err.starts_with("d2i_PUBKEY failed: error:"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn from_der_private_error_has_ossl_detail() {
        let err =
            EvpKey::from_der_private(&[0xde, 0xad, 0xbe, 0xef]).unwrap_err();
        assert!(
            err.starts_with("d2i_AutoPrivateKey failed: error:"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn ecdsa_der_to_fixed_error() {
        assert_eq!(
            ecdsa_der_to_fixed(&[0xff, 0xff], 32).unwrap_err(),
            "d2i_ECDSA_SIG failed: (no OpenSSL error)",
        );
    }

    #[test]
    fn sign_with_public_only_key_error_has_ossl_detail() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let pub_der = key.to_der_public().unwrap();
        let pub_key = EvpKey::from_der_public(&pub_der).unwrap();
        let err = crate::sign::sign(&pub_key, b"test message").unwrap_err();
        assert!(
            err.starts_with("EVP_DigestSign returned 0: error:"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn ec_pem_public_roundtrip() {
        for which in [WhichEC::P256, WhichEC::P384, WhichEC::P521] {
            let key = EvpKey::new(KeyType::EC(which)).unwrap();
            let pem = key.to_pem_public().unwrap();
            let pem_str = std::str::from_utf8(&pem).unwrap();
            assert!(
                pem_str.starts_with("-----BEGIN PUBLIC KEY-----"),
                "{pem_str}"
            );
            let imported = EvpKey::from_pem_public(&pem).unwrap();
            assert!(matches!(imported.typ, KeyType::EC(_)));
            // PEM -> DER -> PEM must be identical.
            let der1 = key.to_der_public().unwrap();
            let der2 = imported.to_der_public().unwrap();
            assert_eq!(der1, der2);
        }
    }

    #[test]
    fn ec_pem_private_roundtrip() {
        for which in [WhichEC::P256, WhichEC::P384, WhichEC::P521] {
            let key = EvpKey::new(KeyType::EC(which)).unwrap();
            let pem = key.to_pem_private().unwrap();
            let pem_str = std::str::from_utf8(&pem).unwrap();
            assert!(
                pem_str.starts_with("-----BEGIN PRIVATE KEY-----"),
                "{pem_str}"
            );
            let imported = EvpKey::from_pem_private(&pem).unwrap();
            assert!(matches!(imported.typ, KeyType::EC(_)));
            let der1 = key.to_der_private().unwrap();
            let der2 = imported.to_der_private().unwrap();
            assert_eq!(der1, der2);
        }
    }

    #[test]
    fn rsa_pem_public_roundtrip() {
        let key = EvpKey::new(KeyType::RSA(WhichRSA::PS256)).unwrap();
        let pem = key.to_pem_public().unwrap();
        let imported = EvpKey::from_pem_public(&pem).unwrap();
        assert!(matches!(imported.typ, KeyType::RSA(_)));
        assert_eq!(
            key.to_der_public().unwrap(),
            imported.to_der_public().unwrap()
        );
    }

    #[test]
    fn rsa_pem_private_roundtrip() {
        let key = EvpKey::new(KeyType::RSA(WhichRSA::PS256)).unwrap();
        let pem = key.to_pem_private().unwrap();
        let imported = EvpKey::from_pem_private(&pem).unwrap();
        assert!(matches!(imported.typ, KeyType::RSA(_)));
        assert_eq!(
            key.to_der_private().unwrap(),
            imported.to_der_private().unwrap()
        );
    }

    #[test]
    fn pem_der_pem_public_roundtrip() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let pem1 = key.to_pem_public().unwrap();
        let der = EvpKey::from_pem_public(&pem1)
            .unwrap()
            .to_der_public()
            .unwrap();
        let pem2 = EvpKey::from_der_public(&der)
            .unwrap()
            .to_pem_public()
            .unwrap();
        assert_eq!(pem1, pem2);
    }

    #[test]
    fn pem_der_pem_private_roundtrip() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P384)).unwrap();
        let pem1 = key.to_pem_private().unwrap();
        let der = EvpKey::from_pem_private(&pem1)
            .unwrap()
            .to_der_private()
            .unwrap();
        let pem2 = EvpKey::from_der_private(&der)
            .unwrap()
            .to_pem_private()
            .unwrap();
        assert_eq!(pem1, pem2);
    }

    #[test]
    fn from_pem_public_rejects_garbage() {
        let err = EvpKey::from_pem_public(b"not a pem").unwrap_err();
        assert!(
            err.starts_with("PEM_read_bio_PUBKEY failed: error:"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn from_pem_private_rejects_garbage() {
        let err = EvpKey::from_pem_private(b"not a pem").unwrap_err();
        assert!(
            err.starts_with("PEM_read_bio_PrivateKey failed: error:"),
            "unexpected error: {err}"
        );
    }

    // ---------------------------------------------------------------
    // Certificate tests
    // ---------------------------------------------------------------

    /// Build a minimal self-signed certificate from the given key.
    /// Returns (DER, PEM) of the certificate.
    fn make_self_signed_cert(key: &EvpKey) -> (Vec<u8>, Vec<u8>) {
        unsafe {
            let cert = ossl::X509_new();
            assert!(!cert.is_null());

            ossl::ASN1_INTEGER_set(ossl::X509_get_serialNumber(cert), 1);
            ossl::X509_gmtime_adj(ossl::X509_getm_notBefore(cert), 0);
            ossl::X509_gmtime_adj(
                ossl::X509_getm_notAfter(cert),
                365 * 24 * 3600,
            );
            ossl::X509_set_pubkey(cert, key.key);
            ossl::X509_set_issuer_name(cert, ossl::X509_get_subject_name(cert));
            let rc = ossl::X509_sign(cert, key.key, key.digest());
            assert!(rc > 0, "X509_sign failed");

            // DER
            let mut der_ptr: *mut u8 = ptr::null_mut();
            let der_len = ossl::i2d_X509(cert, &mut der_ptr);
            assert!(der_len > 0);
            let der =
                std::slice::from_raw_parts(der_ptr, der_len as usize).to_vec();
            ossl::CRYPTO_free(
                der_ptr as *mut std::ffi::c_void,
                concat!(file!(), "\0").as_ptr() as *const i8,
                line!() as i32,
            );

            // PEM
            let bio = ossl::BIO_new(ossl::BIO_s_mem());
            assert!(!bio.is_null());
            assert_eq!(ossl::PEM_write_bio_X509(bio, cert), 1);
            let mut data_ptr: *mut std::ffi::c_char = ptr::null_mut();
            let pem_len = ossl::BIO_get_mem_data(bio, &mut data_ptr);
            assert!(pem_len > 0);
            let pem = std::slice::from_raw_parts(
                data_ptr as *const u8,
                pem_len as usize,
            )
            .to_vec();
            ossl::BIO_free_all(bio);

            ossl::X509_free(cert);
            (der, pem)
        }
    }

    #[test]
    fn from_pem_cert_ec() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let (_, pem) = make_self_signed_cert(&key);
        let imported = EvpKey::from_pem_cert(&pem).unwrap();
        assert!(matches!(imported.typ, KeyType::EC(WhichEC::P256)));
        assert_eq!(
            key.to_der_public().unwrap(),
            imported.to_der_public().unwrap()
        );
    }

    #[test]
    fn from_der_cert_ec() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P384)).unwrap();
        let (der, _) = make_self_signed_cert(&key);
        let imported = EvpKey::from_der_cert(&der).unwrap();
        assert!(matches!(imported.typ, KeyType::EC(WhichEC::P384)));
        assert_eq!(
            key.to_der_public().unwrap(),
            imported.to_der_public().unwrap()
        );
    }

    #[test]
    fn from_cert_rsa() {
        let key = EvpKey::new(KeyType::RSA(WhichRSA::PS256)).unwrap();
        let (der, pem) = make_self_signed_cert(&key);

        let from_der = EvpKey::from_der_cert(&der).unwrap();
        let from_pem = EvpKey::from_pem_cert(&pem).unwrap();
        assert!(matches!(from_der.typ, KeyType::RSA(_)));
        assert!(matches!(from_pem.typ, KeyType::RSA(_)));

        let expected_pub = key.to_der_public().unwrap();
        assert_eq!(from_der.to_der_public().unwrap(), expected_pub);
        assert_eq!(from_pem.to_der_public().unwrap(), expected_pub);
    }

    #[test]
    fn from_pem_cert_rejects_garbage() {
        let err = EvpKey::from_pem_cert(b"not a cert").unwrap_err();
        assert!(
            err.starts_with("PEM_read_bio_X509 failed: error:"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn from_der_cert_rejects_garbage() {
        let err = EvpKey::from_der_cert(&[0xde, 0xad, 0xbe, 0xef]).unwrap_err();
        assert!(
            err.starts_with("d2i_X509 failed: error:"),
            "unexpected error: {err}"
        );
    }
}
