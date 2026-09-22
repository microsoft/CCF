// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

//! Safe Rust API for native CCF application endpoints.
//!
//! # Defining an application
//!
//! A registration function receives a [`Registry`] and installs handlers with
//! [`Registry::read_only`] or [`Registry::read_write`], choosing an [`Auth`]
//! policy for each endpoint. [`export_app!`] exposes that function to CCF's C++
//! bridge. See `samples/apps/basic_rust/src/lib.rs` in the CCF repository for a
//! complete application and its build configuration.
//!
//! Handlers receive a [`ReadOnlyContext`] or [`WriteContext`] for reading the
//! request, constructing the response, and accessing transactional KV maps.
//! Read-only refers to KV access: both contexts can set response status,
//! headers, and body. A handler returns [`EndpointResult`]; returning an
//! [`EndpointError`] asks the bridge to construct a JSON error response.
//!
//! # Borrowing and raw bytes
//!
//! Each context belongs to one handler invocation. Request bodies and query
//! strings borrow the context, while path parameters, headers, and KV values
//! are copied into owned Rust values. Copy a borrowed body or query before
//! using a method that needs mutable access to the context. [`Map`] and
//! [`ReadOnlyMap`] borrow both their context and map name and cannot outlive
//! that context.
//!
//! Request bodies, header values, and KV keys and values are bytes, not
//! implicitly UTF-8 or JSON. Maps do not serialise application types:
//! [`Codec`] is an optional trait for application-defined conversions, not a
//! codec automatically applied by the map API. An absent path parameter,
//! header, or KV entry is `Ok(None)`, distinct from a bridge failure or a
//! present value containing zero bytes.
//!
//! # Transactions and handler state
//!
//! Handlers may execute concurrently and must be `Send`, `Sync`, and `'static`.
//! CCF may discard a transaction and execute its handler again after a
//! conflict. [`RetrySafeHandler`] documents this requirement but does not
//! enforce the safety of external side effects. Keep persistent application
//! state in the transactional KV; a successful map mutation stages a change,
//! rather than committing it immediately. With the bridge's default response
//! handling, only a 2xx response applies writes. Returning `Ok(())` by itself
//! neither selects a status nor establishes consensus commitment.
//!
//! # Errors and linking
//!
//! [`BridgeResult`] reports failures of individual bridge operations. Using
//! `?` on one in a handler converts every [`BridgeError`] into a 500
//! [`EndpointError`]; it does not infer client errors such as 400 or 404.
//! Select application error responses explicitly, and do not include secrets
//! in their client-visible messages.
//!
//! The application must link against CCF's native bridge and use
//! `panic = "unwind"`. Handler panics are caught at the ABI boundary and
//! reported as internal errors, not used as an application error mechanism.
//! The examples that execute below exercise pure Rust functionality; calling
//! a context or registry method requires the CCF runtime.

#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

#[cfg(panic = "abort")]
compile_error!(
    "ccf-app requires panic = \"unwind\" because its C ABI catches panics at the boundary"
);

use std::ffi::c_void;
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::NonNull;
use std::slice;

#[doc(hidden)]
pub const ABI_VERSION: u32 = 1;

#[doc(hidden)]
#[repr(C)]
pub struct RawRegistry {
    _private: [u8; 0],
}

#[doc(hidden)]
#[repr(C)]
pub struct RawEndpointContext {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawSlice {
    data: *const u8,
    len: usize,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RawResult {
    Ok = 0,
    NotFound = 1,
    InvalidArgument = 2,
    ReadOnly = 3,
    InternalError = 4,
}

#[doc(hidden)]
pub const INTERNAL_ERROR_CODE: i32 = RawResult::InternalError as i32;

#[repr(i32)]
#[derive(Clone, Copy)]
enum RawAuth {
    None = 0,
    UserCert = 1,
}

type RawHandler = unsafe extern "C" fn(*mut c_void, *mut RawEndpointContext) -> i32;
type RawDrop = unsafe extern "C" fn(*mut c_void);

#[cfg(not(test))]
mod ffi {
    use super::*;

    unsafe extern "C" {
        pub fn ccf_rust_get_abi_version() -> u32;
        pub fn ccf_rust_register_endpoint(
            registry: *mut RawRegistry,
            path: RawSlice,
            method: RawSlice,
            auth: RawAuth,
            read_only: i32,
            callback: RawHandler,
            drop: RawDrop,
            user_data: *mut c_void,
        ) -> i32;
        pub fn ccf_rust_request_body(ctx: *mut RawEndpointContext, body: *mut RawSlice) -> i32;
        pub fn ccf_rust_request_query(ctx: *mut RawEndpointContext, query: *mut RawSlice) -> i32;
        pub fn ccf_rust_request_path_param(
            ctx: *mut RawEndpointContext,
            name: RawSlice,
            value: *mut RawSlice,
        ) -> i32;
        pub fn ccf_rust_request_header(
            ctx: *mut RawEndpointContext,
            name: RawSlice,
            value: *mut RawSlice,
        ) -> i32;
        pub fn ccf_rust_response_status(ctx: *mut RawEndpointContext, status: u16) -> i32;
        pub fn ccf_rust_response_header(
            ctx: *mut RawEndpointContext,
            name: RawSlice,
            value: RawSlice,
        ) -> i32;
        pub fn ccf_rust_response_body(ctx: *mut RawEndpointContext, body: RawSlice) -> i32;
        pub fn ccf_rust_response_error(
            ctx: *mut RawEndpointContext,
            status: u16,
            code: RawSlice,
            message: RawSlice,
        ) -> i32;
        pub fn ccf_rust_kv_get(
            ctx: *mut RawEndpointContext,
            map_name: RawSlice,
            key: RawSlice,
            value: *mut RawSlice,
        ) -> i32;
        pub fn ccf_rust_kv_has(
            ctx: *mut RawEndpointContext,
            map_name: RawSlice,
            key: RawSlice,
            present: *mut i32,
        ) -> i32;
        pub fn ccf_rust_kv_put(
            ctx: *mut RawEndpointContext,
            map_name: RawSlice,
            key: RawSlice,
            value: RawSlice,
        ) -> i32;
        pub fn ccf_rust_kv_remove(
            ctx: *mut RawEndpointContext,
            map_name: RawSlice,
            key: RawSlice,
        ) -> i32;
    }
}

#[cfg(test)]
mod ffi {
    use super::*;

    pub unsafe extern "C" fn ccf_rust_get_abi_version() -> u32 {
        ABI_VERSION
    }

    pub unsafe extern "C" fn ccf_rust_register_endpoint(
        _registry: *mut RawRegistry,
        _path: RawSlice,
        _method: RawSlice,
        _auth: RawAuth,
        _read_only: i32,
        _callback: RawHandler,
        _drop: RawDrop,
        _user_data: *mut c_void,
    ) -> i32 {
        RawResult::InternalError as i32
    }

    macro_rules! failing_ffi {
        ($name:ident($($arg:ident: $ty:ty),*)) => {
            pub unsafe extern "C" fn $name($($arg: $ty),*) -> i32 {
                $(let _ = $arg;)*
                RawResult::InternalError as i32
            }
        };
    }

    failing_ffi!(ccf_rust_request_body(ctx: *mut RawEndpointContext, body: *mut RawSlice));
    failing_ffi!(ccf_rust_request_query(ctx: *mut RawEndpointContext, query: *mut RawSlice));
    failing_ffi!(ccf_rust_request_path_param(ctx: *mut RawEndpointContext, name: RawSlice, value: *mut RawSlice));
    failing_ffi!(ccf_rust_request_header(ctx: *mut RawEndpointContext, name: RawSlice, value: *mut RawSlice));
    failing_ffi!(ccf_rust_response_status(ctx: *mut RawEndpointContext, status: u16));
    failing_ffi!(ccf_rust_response_header(ctx: *mut RawEndpointContext, name: RawSlice, value: RawSlice));
    failing_ffi!(ccf_rust_response_body(ctx: *mut RawEndpointContext, body: RawSlice));
    failing_ffi!(ccf_rust_response_error(ctx: *mut RawEndpointContext, status: u16, code: RawSlice, message: RawSlice));
    failing_ffi!(ccf_rust_kv_get(ctx: *mut RawEndpointContext, map_name: RawSlice, key: RawSlice, value: *mut RawSlice));
    failing_ffi!(ccf_rust_kv_has(ctx: *mut RawEndpointContext, map_name: RawSlice, key: RawSlice, present: *mut i32));
    failing_ffi!(ccf_rust_kv_put(ctx: *mut RawEndpointContext, map_name: RawSlice, key: RawSlice, value: RawSlice));
    failing_ffi!(ccf_rust_kv_remove(ctx: *mut RawEndpointContext, map_name: RawSlice, key: RawSlice));
}

fn raw_slice(value: &[u8]) -> RawSlice {
    RawSlice {
        data: value.as_ptr(),
        len: value.len(),
    }
}

fn raw_str(value: &str) -> RawSlice {
    raw_slice(value.as_bytes())
}

fn decode_result(result: i32) -> Result<(), BridgeError> {
    match result {
        value if value == RawResult::Ok as i32 => Ok(()),
        value if value == RawResult::NotFound as i32 => Err(BridgeError::NotFound),
        value if value == RawResult::InvalidArgument as i32 => Err(BridgeError::InvalidArgument),
        value if value == RawResult::ReadOnly as i32 => Err(BridgeError::ReadOnly),
        _ => Err(BridgeError::Internal),
    }
}

unsafe fn borrowed_slice<'a>(value: RawSlice) -> &'a [u8] {
    if value.len == 0 {
        &[]
    } else {
        // SAFETY: The C++ bridge guarantees that successful output slices are
        // valid until the next bridge call on this callback context.
        unsafe { slice::from_raw_parts(value.data, value.len) }
    }
}

/// Failure reported by the native bridge or by validation of its output.
///
/// The optional lookup APIs translate [`NotFound`](Self::NotFound) into
/// `Ok(None)`; absence is normally not an error for application code.
/// Conversion into [`EndpointError`] always produces status 500 with code
/// `"InternalError"`, including for `NotFound` and `InvalidArgument`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeError {
    /// The bridge could not find the requested header, path parameter, or key.
    ///
    /// Context and map lookup methods expose this as `Ok(None)` instead.
    NotFound,
    /// An argument failed bridge validation, such as an empty map name,
    /// unknown response status, or invalid response header.
    InvalidArgument,
    /// A KV mutation was attempted without a writable transaction.
    ///
    /// The safe [`ReadOnlyContext`] and [`ReadOnlyMap`] APIs do not expose
    /// mutation methods.
    ReadOnly,
    /// A bridge operation failed internally, returned an unknown result code,
    /// or supplied invalid UTF-8 where the SDK requires a string.
    ///
    /// C++ exceptions are translated to this error. If a KV operation hit a
    /// compacted-version conflict, the bridge also preserves that conflict for
    /// CCF's retry handling after the Rust callback returns.
    Internal,
    /// The SDK and native bridge ABI versions differ during registration.
    AbiMismatch,
}

/// Result of one SDK operation, distinct from a handler's [`EndpointResult`].
///
/// A successful lookup can still contain `None` or `false` for a missing value.
pub type BridgeResult<T> = Result<T, BridgeError>;

/// Authentication policy selected when registering an endpoint.
///
/// The bridge installs the corresponding CCF policy before the handler runs.
/// Authentication does not provide application-specific resource
/// authorisation, and the contexts do not expose the authenticated identity.
#[derive(Clone, Copy, Debug)]
pub enum Auth {
    /// Install no authentication policies; the endpoint can be called without
    /// a registered user certificate.
    None,
    /// Require CCF user-certificate authentication.
    ///
    /// The caller's certificate must be within its validity period and match
    /// a certificate in CCF's user certificate table. This is not member
    /// authentication and does not check application-specific permissions.
    UserCert,
}

impl Auth {
    fn raw(self) -> RawAuth {
        match self {
            Self::None => RawAuth::None,
            Self::UserCert => RawAuth::UserCert,
        }
    }
}

/// An application error to return from an endpoint handler.
///
/// The bridge writes a CCF JSON OData error response using [`code`](Self::code)
/// and [`message`](Self::message), replacing the response status and body.
/// It uses [`status`](Self::status) only when it is a known CCF HTTP status of
/// at least 400; all other values, including unknown 4xx/5xx codes, become 500.
/// Construction does not perform this normalisation.
///
/// An empty code is rejected by the bridge, resulting in a generic internal
/// error response rather than this error's contents. Both code and message
/// are client-visible; do not put confidential diagnostics in them.
///
/// ```
/// use ccf_app::EndpointError;
///
/// let missing = EndpointError::new(404, "ResourceNotFound", "No such key");
/// assert_eq!(missing.status, 404);
/// assert_eq!(missing.code, "ResourceNotFound");
///
/// // Construction preserves the input; the native bridge normalises it later.
/// let unsupported = EndpointError::new(432, "InvalidStatus", "Unsupported status");
/// assert_eq!(unsupported.status, 432);
/// ```
#[derive(Clone, Debug)]
pub struct EndpointError {
    /// Requested HTTP error status, normalised by the bridge when sent.
    ///
    /// Only known CCF statuses of at least 400 are retained; otherwise the
    /// response uses 500. See the type-level documentation.
    pub status: u16,
    /// Non-empty, application-defined error code in the JSON response.
    pub code: String,
    /// Client-visible description of the error; may be empty.
    pub message: String,
}

impl EndpointError {
    /// Construct an error without validating its status or code.
    ///
    /// The strings are owned by the returned error. See [`EndpointError`] for
    /// the bridge's status normalisation and non-empty code requirement.
    pub fn new(status: u16, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    /// Construct a status 500 error with code `"InternalError"`.
    ///
    /// `message` is still client-visible, not a private log message.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(500, "InternalError", message)
    }
}

/// Convert any bridge failure to status 500 and code `"InternalError"`.
///
/// The message is `"CCF bridge error: "` followed by the variant's `Debug`
/// representation. This conversion supports `?` in endpoint handlers; it
/// deliberately does not map `NotFound` to 404 or `InvalidArgument` to 400.
///
/// ```
/// use ccf_app::{BridgeError, EndpointError};
///
/// let error = EndpointError::from(BridgeError::InvalidArgument);
/// assert_eq!(error.status, 500);
/// assert_eq!(error.code, "InternalError");
/// assert_eq!(error.message, "CCF bridge error: InvalidArgument");
/// ```
impl From<BridgeError> for EndpointError {
    fn from(error: BridgeError) -> Self {
        Self::internal(format!("CCF bridge error: {error:?}"))
    }
}

/// Outcome of one endpoint handler invocation.
///
/// `Ok(())` leaves the response as configured by the handler; it does not
/// override an error status already set on the context. `Err(error)` asks the
/// bridge to write that [`EndpointError`] as the response. Transaction
/// application follows the response status, not the Rust result alone.
pub type EndpointResult = Result<(), EndpointError>;

/// Application-defined conversion between a value and its byte representation.
///
/// Map operations accept and return raw bytes; they do not call this trait.
/// Applications may use a codec explicitly for either keys or values and
/// decide how codec errors become [`EndpointError`]s.
///
/// ```
/// use ccf_app::Codec;
///
/// struct BigEndianU32;
///
/// impl Codec<u32> for BigEndianU32 {
///     type Error = std::array::TryFromSliceError;
///
///     fn encode(value: &u32) -> Result<Vec<u8>, Self::Error> {
///         Ok(value.to_be_bytes().to_vec())
///     }
///
///     fn decode(bytes: &[u8]) -> Result<u32, Self::Error> {
///         Ok(u32::from_be_bytes(bytes.try_into()?))
///     }
/// }
///
/// let bytes = BigEndianU32::encode(&42).unwrap();
/// assert_eq!(bytes, [0, 0, 0, 42]);
/// assert_eq!(BigEndianU32::decode(&bytes).unwrap(), 42);
/// assert!(BigEndianU32::decode(&[42]).is_err());
/// ```
pub trait Codec<T> {
    /// Application-selected error type for encoding and decoding.
    ///
    /// The SDK does not require this to implement any particular error trait.
    type Error;

    /// Encode a borrowed value into owned bytes suitable for KV storage.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the implementation cannot encode the value.
    fn encode(value: &T) -> Result<Vec<u8>, Self::Error>;
    /// Decode a value from borrowed bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the bytes are not a supported representation
    /// according to the implementation's format and validation rules.
    fn decode(value: &[u8]) -> Result<T, Self::Error>;
}

struct Context<'a> {
    raw: NonNull<RawEndpointContext>,
    _lifetime: PhantomData<&'a mut RawEndpointContext>,
}

impl Context<'_> {
    fn body(&self) -> BridgeResult<&[u8]> {
        let mut value = RawSlice {
            data: std::ptr::null(),
            len: 0,
        };
        // SAFETY: raw is valid for the handler callback and value is writable.
        decode_result(unsafe { ffi::ccf_rust_request_body(self.raw.as_ptr(), &mut value) })?;
        // SAFETY: The returned body is owned by the request and outlives self.
        Ok(unsafe { borrowed_slice(value) })
    }

    fn query(&self) -> BridgeResult<&str> {
        let mut value = RawSlice {
            data: std::ptr::null(),
            len: 0,
        };
        // SAFETY: raw is valid for the handler callback and value is writable.
        decode_result(unsafe { ffi::ccf_rust_request_query(self.raw.as_ptr(), &mut value) })?;
        // SAFETY: The returned query is owned by the request and outlives self.
        let bytes = unsafe { borrowed_slice(value) };
        std::str::from_utf8(bytes).map_err(|_| BridgeError::Internal)
    }

    fn copied_optional(
        &mut self,
        name: &str,
        get: unsafe extern "C" fn(*mut RawEndpointContext, RawSlice, *mut RawSlice) -> i32,
    ) -> BridgeResult<Option<Vec<u8>>> {
        let mut value = RawSlice {
            data: std::ptr::null(),
            len: 0,
        };
        // SAFETY: raw is valid for the callback and all pointers remain valid
        // for this call.
        match decode_result(unsafe { get(self.raw.as_ptr(), raw_str(name), &mut value) }) {
            Ok(()) => {
                // SAFETY: The bridge returned a valid scratch slice.
                Ok(Some(unsafe { borrowed_slice(value) }.to_vec()))
            }
            Err(BridgeError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn path_param(&mut self, name: &str) -> BridgeResult<Option<String>> {
        self.copied_optional(name, ffi::ccf_rust_request_path_param)?
            .map(|value| String::from_utf8(value).map_err(|_| BridgeError::Internal))
            .transpose()
    }

    fn header(&mut self, name: &str) -> BridgeResult<Option<Vec<u8>>> {
        self.copied_optional(name, ffi::ccf_rust_request_header)
    }

    fn set_status(&mut self, status: u16) -> BridgeResult<()> {
        // SAFETY: raw is valid for the callback.
        decode_result(unsafe { ffi::ccf_rust_response_status(self.raw.as_ptr(), status) })
    }

    fn set_header(&mut self, name: &str, value: &str) -> BridgeResult<()> {
        // SAFETY: raw and both strings are valid for this call.
        decode_result(unsafe {
            ffi::ccf_rust_response_header(self.raw.as_ptr(), raw_str(name), raw_str(value))
        })
    }

    fn set_body(&mut self, body: &[u8]) -> BridgeResult<()> {
        // SAFETY: raw and body are valid for this call.
        decode_result(unsafe { ffi::ccf_rust_response_body(self.raw.as_ptr(), raw_slice(body)) })
    }

    fn set_error(&mut self, error: &EndpointError) -> BridgeResult<()> {
        // SAFETY: raw and all strings are valid for this call.
        decode_result(unsafe {
            ffi::ccf_rust_response_error(
                self.raw.as_ptr(),
                error.status,
                raw_str(&error.code),
                raw_str(&error.message),
            )
        })
    }

    fn get(&mut self, map_name: &str, key: &[u8]) -> BridgeResult<Option<Vec<u8>>> {
        let mut value = RawSlice {
            data: std::ptr::null(),
            len: 0,
        };
        // SAFETY: raw and input buffers are valid for this call.
        match decode_result(unsafe {
            ffi::ccf_rust_kv_get(
                self.raw.as_ptr(),
                raw_str(map_name),
                raw_slice(key),
                &mut value,
            )
        }) {
            Ok(()) => {
                // SAFETY: The bridge returned a valid scratch slice.
                Ok(Some(unsafe { borrowed_slice(value) }.to_vec()))
            }
            Err(BridgeError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn has(&mut self, map_name: &str, key: &[u8]) -> BridgeResult<bool> {
        let mut present = 0;
        // SAFETY: raw and input buffers are valid for this call.
        decode_result(unsafe {
            ffi::ccf_rust_kv_has(
                self.raw.as_ptr(),
                raw_str(map_name),
                raw_slice(key),
                &mut present,
            )
        })?;
        Ok(present != 0)
    }

    fn put(&mut self, map_name: &str, key: &[u8], value: &[u8]) -> BridgeResult<()> {
        // SAFETY: raw and input buffers are valid for this call.
        decode_result(unsafe {
            ffi::ccf_rust_kv_put(
                self.raw.as_ptr(),
                raw_str(map_name),
                raw_slice(key),
                raw_slice(value),
            )
        })
    }

    fn remove(&mut self, map_name: &str, key: &[u8]) -> BridgeResult<()> {
        // SAFETY: raw and input buffers are valid for this call.
        decode_result(unsafe {
            ffi::ccf_rust_kv_remove(self.raw.as_ptr(), raw_str(map_name), raw_slice(key))
        })
    }
}

/// Request, response, and read-only KV access for one handler invocation.
///
/// CCF creates this context for a handler registered with
/// [`Registry::read_only`]. The lifetime `'a` limits access to the native
/// callback. The context cannot be retained for a later request.
///
/// Response setters are available, but KV maps cannot be mutated:
///
/// ```compile_fail,E0599
/// use ccf_app::{EndpointResult, ReadOnlyContext};
///
/// fn write_in_read_only_handler(context: &mut ReadOnlyContext<'_>) -> EndpointResult {
///     context.map("records").put(b"key", b"value")?;
///     Ok(())
/// }
/// ```
pub struct ReadOnlyContext<'a>(Context<'a>);

impl<'ctx> ReadOnlyContext<'ctx> {
    /// Borrow the request body as uninterpreted bytes, empty if no body exists.
    ///
    /// No UTF-8 validation or deserialisation is performed. The slice borrows
    /// this context: copy it with `to_vec()` before a mutable context operation
    /// if the bytes are needed by or after that operation.
    ///
    /// # Errors
    ///
    /// Returns a [`BridgeError`] if the bridge cannot retrieve the body.
    pub fn body(&self) -> BridgeResult<&[u8]> {
        self.0.body()
    }

    /// Borrow the raw query string, without the leading `?`.
    ///
    /// An absent query is `Ok("")`. The query is still percent-encoded; this
    /// method neither splits parameters nor decodes them. Split components
    /// before decoding escaped separators. The string borrows this context;
    /// copy it if it is needed across a mutable context operation.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::Internal`] for invalid UTF-8, or the bridge error
    /// if retrieving the query fails.
    pub fn query(&self) -> BridgeResult<&str> {
        self.0.query()
    }

    /// Copy a decoded path parameter, using its name without braces.
    ///
    /// For a route such as `/records/{key}`, use `"key"`. A missing parameter
    /// is `Ok(None)`, not an error. A present empty parameter is `Ok(Some(...))`
    /// containing an empty string. The owned string survives later bridge
    /// calls; mutable access is needed because the bridge uses scratch space.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::Internal`] if the decoded value is not UTF-8,
    /// or the bridge error if retrieval fails.
    pub fn path_param(&mut self, name: &str) -> BridgeResult<Option<String>> {
        self.0.path_param(name)
    }

    /// Copy a request header value without UTF-8 validation.
    ///
    /// Use lowercase names such as `"content-type"` for CCF's normalised
    /// request headers; the bridge passes the lookup name through unchanged.
    /// A missing header is `Ok(None)` and a present empty header is
    /// `Ok(Some(Vec::new()))`. The bytes are owned and survive later bridge
    /// calls, which may reuse the bridge's scratch space.
    ///
    /// # Errors
    ///
    /// Returns a [`BridgeError`] if retrieving the header fails.
    pub fn header(&mut self, name: &str) -> BridgeResult<Option<Vec<u8>>> {
        self.0.header(name)
    }

    /// Set the response's HTTP status without changing its body.
    ///
    /// Unlike [`EndpointError`], this method rejects unsupported statuses
    /// rather than normalising them. A known status below 400 is permitted.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidArgument`] if `status` is not in CCF's
    /// HTTP status table, or a bridge error if setting the status fails.
    pub fn set_status(&mut self, status: u16) -> BridgeResult<()> {
        self.0.set_status(status)
    }

    /// Set a response header, copying both strings into the response.
    ///
    /// The name must be a non-empty HTTP token (ASCII letters, digits, and
    /// token punctuation). The value must not contain ASCII control bytes
    /// other than horizontal tab, nor DEL (`0x7f`); CR and LF are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidArgument`] for an invalid name or value,
    /// or a bridge error if setting the header fails.
    pub fn set_header(&mut self, name: &str, value: &str) -> BridgeResult<()> {
        self.0.set_header(name, value)
    }

    /// Replace the response body with a copy of these bytes.
    ///
    /// No serialisation or content-type inference is performed. Use
    /// [`set_header`](Self::set_header) to specify the content type. The input
    /// buffer need not outlive this call, and an empty slice sets an empty body.
    ///
    /// # Errors
    ///
    /// Returns a [`BridgeError`] if setting the body fails.
    pub fn set_body(&mut self, body: &[u8]) -> BridgeResult<()> {
        self.0.set_body(body)
    }

    /// Borrow a read-only raw-byte map in this invocation's transaction.
    ///
    /// The handle exclusively borrows the context and also borrows `name`.
    /// No bridge call or name validation occurs until a map operation is
    /// attempted. In particular, an empty name causes those operations to
    /// return [`BridgeError::InvalidArgument`], rather than failing here.
    pub fn map<'a>(&'a mut self, name: &'a str) -> ReadOnlyMap<'a, 'ctx> {
        ReadOnlyMap {
            context: &mut self.0,
            name,
        }
    }
}

/// Request, response, and read-write KV access for one handler invocation.
///
/// CCF creates this context for a handler registered with
/// [`Registry::read_write`]. The lifetime `'a` limits access to the native
/// callback. Mutations through [`Map`] are staged in that invocation's
/// transaction; they are not independent commits. See [`RetrySafeHandler`]
/// for concurrency and retry requirements.
///
/// A body borrowed from the context cannot be passed straight into a mutable
/// context method. Copy it first, as the basic Rust sample does:
///
/// ```compile_fail,E0502
/// use ccf_app::{EndpointResult, WriteContext};
///
/// fn echo(context: &mut WriteContext<'_>) -> EndpointResult {
///     let body = context.body()?;
///     context.set_body(body)?;
///     Ok(())
/// }
/// ```
///
/// Borrowed request data also cannot escape with an unrestricted lifetime:
///
/// ```compile_fail
/// use ccf_app::WriteContext;
///
/// fn retain_body(context: &WriteContext<'_>) -> &'static [u8] {
///     context.body().unwrap()
/// }
/// ```
pub struct WriteContext<'a>(Context<'a>);

impl<'ctx> WriteContext<'ctx> {
    /// Borrow the request body as raw bytes, empty if there is no body.
    ///
    /// This has the same borrowing and error behaviour as
    /// [`ReadOnlyContext::body`]. Copy the bytes before using a mutable
    /// context method if they are needed by or after that operation.
    ///
    /// # Errors
    ///
    /// Returns a [`BridgeError`] if the bridge cannot retrieve the body.
    pub fn body(&self) -> BridgeResult<&[u8]> {
        self.0.body()
    }

    /// Borrow the raw, still percent-encoded query without the leading `?`.
    ///
    /// An absent query is `Ok("")`. No splitting or decoding is performed.
    /// The string borrows this context; see [`ReadOnlyContext::query`] for
    /// ownership and decoding considerations.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::Internal`] for invalid UTF-8, or the bridge error
    /// if retrieving the query fails.
    pub fn query(&self) -> BridgeResult<&str> {
        self.0.query()
    }

    /// Copy a decoded path parameter into an owned string.
    ///
    /// Use the template name without braces, for example `"key"` for
    /// `/records/{key}`. Missing parameters are `Ok(None)`; a present empty
    /// value remains `Some`. Later bridge calls do not invalidate the string.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::Internal`] for invalid UTF-8 in the decoded
    /// value, or the bridge error if retrieval fails.
    pub fn path_param(&mut self, name: &str) -> BridgeResult<Option<String>> {
        self.0.path_param(name)
    }

    /// Copy a request header into owned bytes without UTF-8 validation.
    ///
    /// Use lowercase names such as `"content-type"`; lookup names are passed
    /// through unchanged. Missing headers are `Ok(None)`, while present empty
    /// values remain `Some`. The result survives subsequent bridge calls.
    ///
    /// # Errors
    ///
    /// Returns a [`BridgeError`] if retrieving the header fails.
    pub fn header(&mut self, name: &str) -> BridgeResult<Option<Vec<u8>>> {
        self.0.header(name)
    }

    /// Set the response's HTTP status without changing its body.
    ///
    /// Known CCF statuses, including successes, are accepted. Unlike the
    /// status in [`EndpointError`], an unsupported value is rejected rather
    /// than normalised. The bridge uses CCF's default write-application policy:
    /// a 2xx response permits applying the transaction's staged writes.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidArgument`] if `status` is not in CCF's
    /// HTTP status table, or a bridge error if setting the status fails.
    pub fn set_status(&mut self, status: u16) -> BridgeResult<()> {
        self.0.set_status(status)
    }

    /// Set a response header, copying its name and value.
    ///
    /// The name must be a non-empty ASCII HTTP token. The value must not
    /// contain ASCII control bytes other than horizontal tab, nor DEL
    /// (`0x7f`). In particular, CR and LF are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidArgument`] for an invalid name or value,
    /// or a bridge error if setting the header fails.
    pub fn set_header(&mut self, name: &str, value: &str) -> BridgeResult<()> {
        self.0.set_header(name, value)
    }

    /// Replace the response body with an owned copy of these raw bytes.
    ///
    /// An empty slice clears the body. This neither serialises application
    /// values nor sets a content type; use [`set_header`](Self::set_header)
    /// when one is needed. The input only needs to live for this call.
    ///
    /// # Errors
    ///
    /// Returns a [`BridgeError`] if setting the body fails.
    pub fn set_body(&mut self, body: &[u8]) -> BridgeResult<()> {
        self.0.set_body(body)
    }

    /// Borrow a read-write raw-byte map in this invocation's transaction.
    ///
    /// The handle exclusively borrows the context and also borrows `name`.
    /// It stages mutations in the existing transaction; it does not open a
    /// new transaction or commit writes. Construction makes no bridge call
    /// and does not validate the name. An empty name is rejected by subsequent
    /// map operations with [`BridgeError::InvalidArgument`].
    pub fn map<'a>(&'a mut self, name: &'a str) -> Map<'a, 'ctx> {
        Map {
            context: &mut self.0,
            name,
        }
    }
}

/// Read-only access to one named raw-byte KV map in a transaction.
///
/// Created by [`ReadOnlyContext::map`]. The lifetime `'a` covers the exclusive
/// borrow of the context and the map name; `'ctx` covers the native callback.
/// Drop this handle or stop using it before reusing its context.
///
/// Keys and values are uninterpreted bytes; empty keys and values are allowed.
/// The map name must be non-empty, but validation is deferred to operations.
/// See [`Map`] for the read-write equivalent and [`Codec`] for optional
/// application-defined byte conversions.
pub struct ReadOnlyMap<'a, 'ctx> {
    context: &'a mut Context<'ctx>,
    name: &'a str,
}

impl ReadOnlyMap<'_, '_> {
    /// Read a key's value into an owned byte vector.
    ///
    /// A missing key is `Ok(None)`; a present empty value is
    /// `Ok(Some(Vec::new()))`. The returned bytes survive later bridge calls
    /// and dropping the handle. The input key is not retained.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidArgument`] for an empty map name, or a
    /// bridge error if reading fails. KV exceptions become
    /// [`BridgeError::Internal`].
    pub fn get(&mut self, key: &[u8]) -> BridgeResult<Option<Vec<u8>>> {
        self.context.get(self.name, key)
    }

    /// Test whether a key is present without returning its value.
    ///
    /// A missing key is `Ok(false)`, not an error. A key whose value is empty
    /// is still present. The input key is not retained.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidArgument`] for an empty map name, or a
    /// bridge error if the lookup fails. KV exceptions become
    /// [`BridgeError::Internal`].
    pub fn has(&mut self, key: &[u8]) -> BridgeResult<bool> {
        self.context.has(self.name, key)
    }
}

/// Read-write access to one named raw-byte KV map in a transaction.
///
/// Created by [`WriteContext::map`]. The lifetime `'a` covers the exclusive
/// borrow of the context and the map name; `'ctx` covers the native callback.
/// Stop using the handle before reusing its context. Returned values are
/// owned copies and are not tied to these lifetimes.
///
/// Empty keys and values are valid; an empty map name fails at operation time.
/// No codec is applied automatically. [`put`](Self::put) and
/// [`remove`](Self::remove) stage writes visible to subsequent reads in the
/// transaction, not independent commits. CCF may discard this transaction
/// and retry the entire handler; see [`RetrySafeHandler`].
pub struct Map<'a, 'ctx> {
    context: &'a mut Context<'ctx>,
    name: &'a str,
}

impl Map<'_, '_> {
    /// Read a key, including changes staged by this transaction.
    ///
    /// Returns owned bytes, `Ok(None)` for a missing or removed key, and
    /// `Ok(Some(Vec::new()))` for a present empty value. The result remains
    /// valid after later map operations or after dropping the handle. The
    /// input key is not retained.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidArgument`] for an empty map name, or a
    /// bridge error if reading fails. KV exceptions become
    /// [`BridgeError::Internal`].
    pub fn get(&mut self, key: &[u8]) -> BridgeResult<Option<Vec<u8>>> {
        self.context.get(self.name, key)
    }

    /// Test whether a key is present, including this transaction's changes.
    ///
    /// Returns `Ok(false)` for a missing or removed key. A present empty value
    /// still returns `Ok(true)`. The input key is not retained.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidArgument`] for an empty map name, or a
    /// bridge error if the lookup fails. KV exceptions become
    /// [`BridgeError::Internal`].
    pub fn has(&mut self, key: &[u8]) -> BridgeResult<bool> {
        self.context.has(self.name, key)
    }

    /// Stage insertion or replacement of a key's raw-byte value.
    ///
    /// Copies the key and value; neither input needs to outlive this call.
    /// Empty keys and values are accepted. Success stages a change in the
    /// current transaction, not a commit; see [`Map`].
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidArgument`] for an empty map name, or
    /// [`BridgeError::ReadOnly`] if the bridge has no writable transaction
    /// (not expected for a safe [`WriteContext`]). KV exceptions become
    /// [`BridgeError::Internal`].
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> BridgeResult<()> {
        self.context.put(self.name, key, value)
    }

    /// Stage removal of a key from this transaction's map.
    ///
    /// Removing a missing key succeeds; this does not return `NotFound` or
    /// report whether a value existed. The input is copied as needed, not
    /// retained. Success stages a removal, not a commit.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidArgument`] for an empty map name, or
    /// [`BridgeError::ReadOnly`] if the bridge has no writable transaction
    /// (not expected for a safe [`WriteContext`]). KV exceptions become
    /// [`BridgeError::Internal`].
    pub fn remove(&mut self, key: &[u8]) -> BridgeResult<()> {
        self.context.remove(self.name, key)
    }
}

/// Marker trait for endpoint handlers that may be invoked repeatedly.
///
/// CCF may discard a transaction and invoke the handler again when transaction
/// execution conflicts. Handlers must not perform non-transactional side
/// effects that are unsafe to repeat. Changes made through [`Map`] belong to
/// the transaction; mutations of captured state, external I/O, and other side
/// effects do not get rolled back with it.
///
/// This trait is implemented for every `Send + Sync` type. It documents the
/// caller's semantic obligation; the blanket implementation does not prove
/// that a handler is actually safe to retry. The same handler may execute
/// concurrently, and registration additionally requires it to be `'static`.
pub trait RetrySafeHandler: Send + Sync {}

impl<T> RetrySafeHandler for T where T: Send + Sync {}

trait ReadHandler:
    for<'a> Fn(&mut ReadOnlyContext<'a>) -> EndpointResult + RetrySafeHandler + 'static
{
}

impl<T> ReadHandler for T where
    T: for<'a> Fn(&mut ReadOnlyContext<'a>) -> EndpointResult + RetrySafeHandler + 'static
{
}

trait WriteHandler:
    for<'a> Fn(&mut WriteContext<'a>) -> EndpointResult + RetrySafeHandler + 'static
{
}

impl<T> WriteHandler for T where
    T: for<'a> Fn(&mut WriteContext<'a>) -> EndpointResult + RetrySafeHandler + 'static
{
}

enum Handler {
    Read(Box<dyn ReadHandler>),
    Write(Box<dyn WriteHandler>),
}

unsafe extern "C" fn invoke_handler(
    user_data: *mut c_void,
    raw_context: *mut RawEndpointContext,
) -> i32 {
    if user_data.is_null() || raw_context.is_null() {
        return RawResult::InvalidArgument as i32;
    }

    // SAFETY: The registry owns this Handler until it invokes drop_handler.
    let handler = unsafe { &*(user_data.cast::<Handler>()) };
    // SAFETY: The null guard above validated raw_context.
    let raw = unsafe { NonNull::new_unchecked(raw_context) };

    let result = catch_unwind(AssertUnwindSafe(|| match handler {
        Handler::Read(handler) => handler(&mut ReadOnlyContext(Context {
            raw,
            _lifetime: PhantomData,
        })),
        Handler::Write(handler) => handler(&mut WriteContext(Context {
            raw,
            _lifetime: PhantomData,
        })),
    }));

    let endpoint_error = match result {
        Ok(Ok(())) => return RawResult::Ok as i32,
        Ok(Err(error)) => error,
        Err(_) => EndpointError::internal("Rust endpoint panicked"),
    };

    let mut context = Context {
        raw,
        _lifetime: PhantomData,
    };
    match context.set_error(&endpoint_error) {
        Ok(()) => RawResult::Ok as i32,
        Err(_) => RawResult::InternalError as i32,
    }
}

unsafe extern "C" fn drop_handler(user_data: *mut c_void) {
    if !user_data.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: The pointer was created by Box::into_raw during endpoint
            // registration and is dropped exactly once by the C++ registry.
            drop(unsafe { Box::from_raw(user_data.cast::<Handler>()) });
        }));
    }
}

/// Endpoint registration interface provided to the application's initializer.
///
/// Receive this through the function passed to [`export_app!`], rather than
/// constructing it directly. Use [`read_only`](Self::read_only) or
/// [`read_write`](Self::read_write) to choose the transaction access allowed
/// for each handler, independently of its HTTP method and [`Auth`] policy.
///
/// Successful registration transfers ownership of a boxed handler to the
/// native registry. Captured state must be `'static`, `Send`, and `Sync`.
/// Registration borrows the path and method only for the call; those strings
/// are copied by the bridge. Propagate registration failures from the
/// initializer so CCF does not start with missing application endpoints.
pub struct Registry {
    raw: NonNull<RawRegistry>,
}

impl Registry {
    #[doc(hidden)]
    /// # Safety
    ///
    /// `raw` must point to the live C++ registry passed to
    /// `ccf_rust_app_register` and may not outlive that call.
    pub unsafe fn from_raw(raw: *mut RawRegistry) -> BridgeResult<Self> {
        if unsafe { ffi::ccf_rust_get_abi_version() } != ABI_VERSION {
            return Err(BridgeError::AbiMismatch);
        }
        NonNull::new(raw)
            .map(|raw| Self { raw })
            .ok_or(BridgeError::InvalidArgument)
    }

    /// Register an endpoint with read-only KV access and a mutable response.
    ///
    /// `path` is a CCF route, optionally containing named parameters such as
    /// `/records/{key}`. `method` is a supported uppercase HTTP method such as
    /// `"GET"`; choosing a method does not itself choose transaction access.
    /// `auth` selects the CCF authentication policy.
    ///
    /// The handler receives a fresh [`ReadOnlyContext`] per invocation and
    /// returns [`EndpointResult`]. It can run concurrently or be retried; see
    /// [`RetrySafeHandler`]. On success the native registry owns the handler;
    /// on registration failure the SDK drops it.
    ///
    /// # Errors
    ///
    /// Empty `path` or `method` returns [`BridgeError::InvalidArgument`].
    /// A non-empty unrecognised method, or another exception while installing
    /// the endpoint, returns [`BridgeError::Internal`]. Registration does not
    /// translate these errors into HTTP responses; return them from the
    /// application's initializer.
    pub fn read_only<F>(
        &mut self,
        path: &str,
        method: &str,
        auth: Auth,
        handler: F,
    ) -> BridgeResult<()>
    where
        F: for<'a> Fn(&mut ReadOnlyContext<'a>) -> EndpointResult + RetrySafeHandler + 'static,
    {
        self.register(path, method, auth, Handler::Read(Box::new(handler)))
    }

    /// Register an endpoint with read-write KV access and a mutable response.
    ///
    /// `path` is a CCF route, optionally containing parameters such as
    /// `/records/{key}`. `method` is a supported uppercase HTTP method such as
    /// `"PUT"`. Any supported method can be registered here; it is this method,
    /// rather than the HTTP verb, that selects a writable transaction.
    /// `auth` selects the CCF authentication policy.
    ///
    /// The handler receives a fresh [`WriteContext`] per invocation and
    /// returns [`EndpointResult`]. Writes are staged in the transaction, not
    /// immediately committed. Handlers can run concurrently or be retried;
    /// see [`RetrySafeHandler`]. Successful registration transfers ownership
    /// of the handler to CCF; the SDK drops it if registration fails.
    ///
    /// # Errors
    ///
    /// Empty `path` or `method` returns [`BridgeError::InvalidArgument`].
    /// A non-empty unrecognised method, or another exception while installing
    /// the endpoint, returns [`BridgeError::Internal`]. Propagate failures from
    /// the initializer rather than continuing with an incomplete registry.
    pub fn read_write<F>(
        &mut self,
        path: &str,
        method: &str,
        auth: Auth,
        handler: F,
    ) -> BridgeResult<()>
    where
        F: for<'a> Fn(&mut WriteContext<'a>) -> EndpointResult + RetrySafeHandler + 'static,
    {
        self.register(path, method, auth, Handler::Write(Box::new(handler)))
    }

    fn register(
        &mut self,
        path: &str,
        method: &str,
        auth: Auth,
        handler: Handler,
    ) -> BridgeResult<()> {
        let read_only = matches!(handler, Handler::Read(_)) as i32;
        let user_data = Box::into_raw(Box::new(handler)).cast::<c_void>();
        // SAFETY: All inputs are valid for this call. Ownership of user_data is
        // transferred only when registration succeeds.
        let result = unsafe {
            ffi::ccf_rust_register_endpoint(
                self.raw.as_ptr(),
                raw_str(path),
                raw_str(method),
                auth.raw(),
                read_only,
                invoke_handler,
                drop_handler,
                user_data,
            )
        };
        if let Err(error) = decode_result(result) {
            // SAFETY: Registration failed, so C++ did not retain user_data.
            unsafe { drop_handler(user_data) };
            return Err(error);
        }
        Ok(())
    }
}

/// Export a native CCF application's ABI entry points.
///
/// Invoke once at the application crate root as
/// `ccf_app::export_app!(register);`, with a function path whose registration
/// function has the signature `fn(&mut Registry) -> BridgeResult<()>`.
/// The function installs endpoints with [`Registry::read_only`] and
/// [`Registry::read_write`]. See `samples/apps/basic_rust/src/lib.rs` for a
/// complete, linkable application.
///
/// The macro exports the ABI version and registration functions that the C++
/// bridge calls during initialization. It checks bridge compatibility before
/// calling the registration function. An initialization error or panic becomes
/// an internal-error return code, causing CCF application registration to fail;
/// it is not an HTTP response. Successful handlers are owned by the native
/// registry rather than the temporary Rust [`Registry`] wrapper.
///
/// The application must link CCF's native bridge and use `panic = "unwind"`.
/// The generated entry points and the raw ABI types they refer to are
/// implementation details, not APIs for application handlers to call.
#[macro_export]
macro_rules! export_app {
    ($register:path) => {
        #[doc(hidden)]
        #[unsafe(no_mangle)]
        pub extern "C" fn ccf_rust_app_abi_version() -> u32 {
            $crate::ABI_VERSION
        }

        #[doc(hidden)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn ccf_rust_app_register(
            raw_registry: *mut $crate::RawRegistry,
        ) -> i32 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // SAFETY: The C++ bridge passes a live registry for this call.
                let mut registry = unsafe { $crate::Registry::from_raw(raw_registry) }?;
                $register(&mut registry)
            }));
            match result {
                Ok(Ok(())) => 0,
                _ => $crate::INTERNAL_ERROR_CODE,
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_raw_result_codes() {
        assert_eq!(decode_result(0), Ok(()));
        assert_eq!(decode_result(1), Err(BridgeError::NotFound));
        assert_eq!(decode_result(2), Err(BridgeError::InvalidArgument));
        assert_eq!(decode_result(3), Err(BridgeError::ReadOnly));
        assert_eq!(decode_result(99), Err(BridgeError::Internal));
    }

    #[test]
    fn rejects_null_registry() {
        // SAFETY: This intentionally exercises null validation.
        assert!(matches!(
            unsafe { Registry::from_raw(std::ptr::null_mut()) },
            Err(BridgeError::InvalidArgument)
        ));
    }

    #[test]
    fn preserves_error_status_for_bridge_validation() {
        assert_eq!(EndpointError::new(432, "Error", "message").status, 432);
    }

    #[test]
    fn panicking_handler_returns_internal_error() {
        let handler = Box::new(Handler::Write(Box::new(|_| panic!("test panic"))));
        let user_data = Box::into_raw(handler).cast::<c_void>();
        let raw_context = NonNull::<RawEndpointContext>::dangling().as_ptr();
        // SAFETY: In the test-only FFI stubs, the context pointer is never
        // dereferenced. This exercises the panic trampoline without invoking
        // any real C++ bridge logic.
        let result = unsafe { invoke_handler(user_data, raw_context) };
        assert_eq!(result, RawResult::InternalError as i32);
        // SAFETY: The test retains ownership of the handler.
        unsafe { drop_handler(user_data) };
    }
}
