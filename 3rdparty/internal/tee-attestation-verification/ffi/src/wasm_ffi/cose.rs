// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use js_sys::{Array, Promise};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use cose::{signature_key_algorithm_for_cose_alg, CborValue as NativeCborValue};
use crypto::{AsyncCryptoBackend, AsyncKeyBackend};

/// JavaScript wrapper around an owned CBOR value.
#[wasm_bindgen]
#[derive(Clone)]
pub struct CborValue {
    inner: NativeCborValue,
}

impl CborValue {
    pub fn from_native(inner: NativeCborValue) -> Self {
        Self { inner }
    }

    pub fn as_native(&self) -> &NativeCborValue {
        &self.inner
    }

    pub fn into_native(self) -> NativeCborValue {
        self.inner
    }
}

#[wasm_bindgen]
impl CborValue {
    /// Parse a CBOR document from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<CborValue, String> {
        NativeCborValue::from_bytes(bytes).map(CborValue::from_native)
    }

    /// Serialize this value as deterministic CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        self.inner.to_bytes()
    }

    /// Return the CBOR major type represented by this value.
    pub fn kind(&self) -> String {
        match self.inner {
            NativeCborValue::Int(_) => "int",
            NativeCborValue::Simple(_) => "simple",
            NativeCborValue::ByteString(_) => "bytes",
            NativeCborValue::TextString(_) => "text",
            NativeCborValue::Array(_) => "array",
            NativeCborValue::Map(_) => "map",
            NativeCborValue::Tagged { .. } => "tagged",
        }
        .to_string()
    }

    pub fn int(&self) -> Result<i64, String> {
        match &self.inner {
            NativeCborValue::Int(value) => Ok(*value),
            other => Err(format!("Expected Int, got {:?}", other)),
        }
    }

    pub fn simple(&self) -> Result<u8, String> {
        match &self.inner {
            NativeCborValue::Simple(value) => Ok(*value),
            other => Err(format!("Expected Simple, got {:?}", other)),
        }
    }

    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        match &self.inner {
            NativeCborValue::ByteString(value) => Ok(value.clone()),
            other => Err(format!("Expected ByteString, got {:?}", other)),
        }
    }

    pub fn text(&self) -> Result<String, String> {
        match &self.inner {
            NativeCborValue::TextString(value) => Ok(value.clone()),
            other => Err(format!("Expected TextString, got {:?}", other)),
        }
    }

    pub fn tag(&self) -> Result<u64, String> {
        match &self.inner {
            NativeCborValue::Tagged { tag, .. } => Ok(*tag),
            other => Err(format!("Expected Tagged, got {:?}", other)),
        }
    }

    pub fn tagged_payload(&self) -> Result<CborValue, String> {
        match &self.inner {
            NativeCborValue::Tagged { payload, .. } => {
                Ok(CborValue::from_native(payload.as_ref().clone()))
            }
            other => Err(format!("Expected Tagged, got {:?}", other)),
        }
    }

    pub fn len(&self) -> Result<u32, String> {
        self.inner
            .len()?
            .try_into()
            .map_err(|_| "CBOR container length does not fit u32".to_string())
    }

    pub fn array_at(&self, index: u32) -> Result<CborValue, String> {
        self.inner
            .array_at(index as usize)
            .cloned()
            .map(CborValue::from_native)
    }

    pub fn map_at_int(&self, key: i64) -> Result<CborValue, String> {
        self.inner
            .map_at_int(key)
            .cloned()
            .map(CborValue::from_native)
    }

    pub fn map_at_text(&self, key: &str) -> Result<CborValue, String> {
        self.inner
            .map_at_str(key)
            .cloned()
            .map(CborValue::from_native)
    }

    pub fn map_at(&self, key: &CborValue) -> Result<CborValue, String> {
        self.inner
            .map_at(key.as_native())
            .cloned()
            .map(CborValue::from_native)
    }

    pub fn map_entry_at(&self, index: u32) -> Result<Array, String> {
        map_entry_at(&self.inner, index).map(|(key, value)| {
            let entry = Array::new();
            entry.push(&CborValue::from_native(key.clone()).into());
            entry.push(&CborValue::from_native(value.clone()).into());
            entry
        })
    }

    pub fn map_key_at(&self, index: u32) -> Result<CborValue, String> {
        map_entry_at(&self.inner, index).map(|(key, _)| CborValue::from_native(key.clone()))
    }

    pub fn map_value_at(&self, index: u32) -> Result<CborValue, String> {
        map_entry_at(&self.inner, index).map(|(_, value)| CborValue::from_native(value.clone()))
    }

    pub fn map_has_int(&self, key: i64) -> Result<bool, String> {
        self.inner.map_has_int_key(key)
    }

    pub fn map_has_text(&self, key: &str) -> Result<bool, String> {
        self.inner.map_has_str_key(key)
    }

    pub fn map_has(&self, key: &CborValue) -> Result<bool, String> {
        self.inner.map_has_key(key.as_native())
    }

    pub fn as_cose_sign1(&self) -> Result<CoseSign1, String> {
        cose::cose_sign1(&self.inner)
            .cloned()
            .map(CoseSign1::from_native)
    }
}

/// JavaScript wrapper around a COSE_Sign1 array.
#[wasm_bindgen]
#[derive(Clone)]
pub struct CoseSign1 {
    inner: NativeCborValue,
}

impl CoseSign1 {
    pub fn from_native(inner: NativeCborValue) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl CoseSign1 {
    pub fn protected(&self) -> Result<Vec<u8>, String> {
        required_bytes(self.inner.array_at(0)?, "protected")
    }

    pub fn unprotected(&self) -> Result<CborValue, String> {
        self.inner.array_at(1).cloned().map(CborValue::from_native)
    }

    pub fn payload(&self) -> Result<Vec<u8>, String> {
        required_bytes(self.inner.array_at(2)?, "payload")
    }

    pub fn signature(&self) -> Result<Vec<u8>, String> {
        required_bytes(self.inner.array_at(3)?, "signature")
    }

    pub fn protected_header(&self) -> Result<CborValue, String> {
        NativeCborValue::from_bytes(&self.protected()?).map(CborValue::from_native)
    }
}

/// Signed material snapshotted from a COSE_Sign1 at call time.
#[cfg(async_crypto)]
struct SignedMaterial {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

#[cfg(async_crypto)]
impl CoseSign1 {
    /// Copy the protected header, payload, and signature bytes synchronously,
    /// before the async verification borrows `self`. For embedded verification the
    /// payload is read from COSE field 2; for detached verification field 2 must be
    /// nil (CBOR simple value 22) and the caller-supplied `detached_payload` is used.
    fn signed_material(&self, detached_payload: Option<Vec<u8>>) -> Result<SignedMaterial, String> {
        let protected = required_bytes(self.inner.array_at(0)?, "protected")?;
        let signature = required_bytes(self.inner.array_at(3)?, "signature")?;
        let payload = match detached_payload {
            Some(payload) => match self.inner.array_at(2)? {
                NativeCborValue::Simple(22) => payload,
                NativeCborValue::ByteString(_) => return Err(
                    "detached payload verification requires nil COSE payload; use embedded verification for byte string payloads"
                        .into(),
                ),
                _ => return Err("detached payload verification requires nil COSE payload".into()),
            },
            None => required_bytes(self.inner.array_at(2)?, "payload")?,
        };
        Ok(SignedMaterial {
            protected,
            payload,
            signature,
        })
    }
}

#[cfg(async_crypto)]
#[wasm_bindgen]
impl CoseSign1 {
    /// Verify this COSE_Sign1 over its embedded payload against an SPKI DER public key.
    ///
    /// `cose_alg` is the COSE algorithm identifier (for example -7 for ES256). The
    /// returned Promise resolves on a valid signature and rejects with an error
    /// string otherwise. This is the wasm equivalent of the C ABI
    /// `tav_verify_cose_sign1_embedded`.
    #[wasm_bindgen(unchecked_return_type = "Promise<void>")]
    pub fn verify_embedded(&self, spki_der: Vec<u8>, cose_alg: i32) -> Promise {
        verify_sign1(self.signed_material(None), spki_der, cose_alg)
    }

    /// Verify this COSE_Sign1 against an SPKI DER public key with a caller-supplied
    /// detached payload.
    ///
    /// The COSE payload field must be nil (CBOR simple value 22); use
    /// `verify_embedded` for an embedded byte-string payload. This is the wasm
    /// equivalent of the C ABI `tav_verify_cose_sign1_detached`.
    #[wasm_bindgen(unchecked_return_type = "Promise<void>")]
    pub fn verify_detached(&self, payload: Vec<u8>, spki_der: Vec<u8>, cose_alg: i32) -> Promise {
        verify_sign1(self.signed_material(Some(payload)), spki_der, cose_alg)
    }
}

/// Import the SPKI DER key and verify the COSE_Sign1 signature with the async
/// crypto backend. Every input is owned, so nothing is borrowed across the await.
#[cfg(async_crypto)]
fn verify_sign1(
    material: Result<SignedMaterial, String>,
    spki_der: Vec<u8>,
    cose_alg: i32,
) -> Promise {
    future_to_promise(async move {
        let SignedMaterial {
            protected,
            payload,
            signature,
        } = material.map_err(|e| JsValue::from_str(&e))?;
        let algorithm = signature_key_algorithm_for_cose_alg(cose_alg as i64)
            .map_err(|e| JsValue::from_str(&e))?;
        let key = <<crypto::Crypto as AsyncCryptoBackend>::Key as AsyncKeyBackend>::from_spki_der(
            &spki_der, algorithm,
        )
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
        cose::asynchronous::cose_verify1(&key, algorithm, &protected, &payload, &signature)
            .await
            .map_err(|e| JsValue::from_str(&e))?;
        Ok(JsValue::UNDEFINED)
    })
}

pub fn required_bytes(value: &NativeCborValue, name: &str) -> Result<Vec<u8>, String> {
    match value {
        NativeCborValue::ByteString(bytes) => Ok(bytes.clone()),
        _ => Err(format!("{name} must be a byte string")),
    }
}

fn map_entry_at(
    value: &NativeCborValue,
    index: u32,
) -> Result<(&NativeCborValue, &NativeCborValue), String> {
    match value {
        NativeCborValue::Map(entries) => entries
            .get(index as usize)
            .map(|(key, value)| (key, value))
            .ok_or_else(|| format!("Index {index} out of bounds")),
        other => Err(format!("Expected Map, got {:?}", other)),
    }
}
