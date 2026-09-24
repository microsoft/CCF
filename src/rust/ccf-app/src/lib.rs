// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

//! Minimal Rust API for native CCF applications.
//!
//! Endpoint handlers may execute concurrently and must therefore be `Send` and
//! `Sync`. Request, response, transaction, and map objects are borrowed for one
//! callback invocation and cannot be retained.

#[cfg(not(panic = "unwind"))]
compile_error!(
    "ccf-app requires panic = \"unwind\" because its C ABI catches panics at the boundary"
);

use std::cell::Cell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::NonNull;
use std::slice;
use std::sync::Once;

pub const ABI_VERSION: u32 = 1;

#[repr(C)]
pub struct RawRegistry {
    _private: [u8; 0],
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeError {
    NotFound,
    InvalidArgument,
    ReadOnly,
    Internal,
    AbiMismatch,
}

pub type BridgeResult<T> = Result<T, BridgeError>;

#[derive(Clone, Copy, Debug)]
pub enum Auth {
    None,
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

#[derive(Clone, Debug)]
pub struct EndpointError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl EndpointError {
    pub fn new(status: u16, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(500, "InternalError", message)
    }
}

impl From<BridgeError> for EndpointError {
    fn from(error: BridgeError) -> Self {
        Self::internal(format!("CCF bridge error: {error:?}"))
    }
}

pub type EndpointResult = Result<(), EndpointError>;

pub trait Codec<T> {
    type Error;

    fn encode(value: &T) -> Result<Vec<u8>, Self::Error>;
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

pub struct ReadOnlyContext<'a>(Context<'a>);

impl<'ctx> ReadOnlyContext<'ctx> {
    pub fn body(&self) -> BridgeResult<&[u8]> {
        self.0.body()
    }

    pub fn query(&self) -> BridgeResult<&str> {
        self.0.query()
    }

    pub fn path_param(&mut self, name: &str) -> BridgeResult<Option<String>> {
        self.0.path_param(name)
    }

    pub fn header(&mut self, name: &str) -> BridgeResult<Option<Vec<u8>>> {
        self.0.header(name)
    }

    pub fn set_status(&mut self, status: u16) -> BridgeResult<()> {
        self.0.set_status(status)
    }

    pub fn set_header(&mut self, name: &str, value: &str) -> BridgeResult<()> {
        self.0.set_header(name, value)
    }

    pub fn set_body(&mut self, body: &[u8]) -> BridgeResult<()> {
        self.0.set_body(body)
    }

    pub fn map<'a>(&'a mut self, name: &'a str) -> ReadOnlyMap<'a, 'ctx> {
        ReadOnlyMap {
            context: &mut self.0,
            name,
        }
    }
}

pub struct WriteContext<'a>(Context<'a>);

impl<'ctx> WriteContext<'ctx> {
    pub fn body(&self) -> BridgeResult<&[u8]> {
        self.0.body()
    }

    pub fn query(&self) -> BridgeResult<&str> {
        self.0.query()
    }

    pub fn path_param(&mut self, name: &str) -> BridgeResult<Option<String>> {
        self.0.path_param(name)
    }

    pub fn header(&mut self, name: &str) -> BridgeResult<Option<Vec<u8>>> {
        self.0.header(name)
    }

    pub fn set_status(&mut self, status: u16) -> BridgeResult<()> {
        self.0.set_status(status)
    }

    pub fn set_header(&mut self, name: &str, value: &str) -> BridgeResult<()> {
        self.0.set_header(name, value)
    }

    pub fn set_body(&mut self, body: &[u8]) -> BridgeResult<()> {
        self.0.set_body(body)
    }

    pub fn map<'a>(&'a mut self, name: &'a str) -> Map<'a, 'ctx> {
        Map {
            context: &mut self.0,
            name,
        }
    }
}

pub struct ReadOnlyMap<'a, 'ctx> {
    context: &'a mut Context<'ctx>,
    name: &'a str,
}

impl ReadOnlyMap<'_, '_> {
    pub fn get(&mut self, key: &[u8]) -> BridgeResult<Option<Vec<u8>>> {
        self.context.get(self.name, key)
    }

    pub fn has(&mut self, key: &[u8]) -> BridgeResult<bool> {
        self.context.has(self.name, key)
    }
}

pub struct Map<'a, 'ctx> {
    context: &'a mut Context<'ctx>,
    name: &'a str,
}

impl Map<'_, '_> {
    pub fn get(&mut self, key: &[u8]) -> BridgeResult<Option<Vec<u8>>> {
        self.context.get(self.name, key)
    }

    pub fn has(&mut self, key: &[u8]) -> BridgeResult<bool> {
        self.context.has(self.name, key)
    }

    pub fn put(&mut self, key: &[u8], value: &[u8]) -> BridgeResult<()> {
        self.context.put(self.name, key, value)
    }

    pub fn remove(&mut self, key: &[u8]) -> BridgeResult<()> {
        self.context.remove(self.name, key)
    }
}

/// Marker trait for endpoint handlers that may be invoked repeatedly.
///
/// CCF may discard a transaction and invoke the handler again when transaction
/// execution conflicts. Handlers must not perform non-transactional side
/// effects that are unsafe to repeat.
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

thread_local! {
    static IN_APP_CALLBACK: Cell<bool> = const { Cell::new(false) };
}

fn in_app_callback() -> bool {
    // The hook may run while this thread's locals are being destroyed.
    IN_APP_CALLBACK.try_with(Cell::get).unwrap_or(false)
}

/// Runs application code, catching any panic at the ABI boundary.
fn catch_app_panic<R>(f: impl FnOnce() -> R) -> std::thread::Result<R> {
    struct Restore(bool);

    impl Drop for Restore {
        fn drop(&mut self) {
            IN_APP_CALLBACK.set(self.0);
        }
    }

    let _restore = Restore(IN_APP_CALLBACK.replace(true));
    catch_unwind(AssertUnwindSafe(f))
}

/// Stops panics raised by application callbacks from being reported.
///
/// Rust's default hook writes panic messages, which may contain request or KV
/// data, to the node's stderr, which is visible to the host. These panics are
/// contained by `catch_app_panic`, and handler panics are reported to the
/// caller as HTTP 500 errors. Other panics, including those raised by CCF's own
/// Rust code, which may share this process-wide hook, are passed to the
/// previously installed hook.
fn install_panic_hook() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !in_app_callback() {
                previous(info);
            }
        }));
    });
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

    let result = catch_app_panic(|| match handler {
        Handler::Read(handler) => handler(&mut ReadOnlyContext(Context {
            raw,
            _lifetime: PhantomData,
        })),
        Handler::Write(handler) => handler(&mut WriteContext(Context {
            raw,
            _lifetime: PhantomData,
        })),
    });

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
        let _ = catch_app_panic(|| {
            // SAFETY: The pointer was created by Box::into_raw during endpoint
            // registration and is dropped exactly once by the C++ registry.
            drop(unsafe { Box::from_raw(user_data.cast::<Handler>()) });
        });
    }
}

pub struct Registry {
    raw: NonNull<RawRegistry>,
}

impl Registry {
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

/// Implements the `ccf_rust_app_register` function exported by `export_app!`.
///
/// # Safety
///
/// `raw_registry` must be the registry passed by CCF to
/// `ccf_rust_app_register`.
#[doc(hidden)]
pub unsafe fn register_app<F>(raw_registry: *mut RawRegistry, register: F) -> i32
where
    F: FnOnce(&mut Registry) -> BridgeResult<()>,
{
    install_panic_hook();
    let result = catch_app_panic(|| {
        // SAFETY: The caller passes the live registry for this call.
        let mut registry = unsafe { Registry::from_raw(raw_registry) }?;
        register(&mut registry)
    });
    match result {
        Ok(Ok(())) => RawResult::Ok as i32,
        _ => RawResult::InternalError as i32,
    }
}

#[macro_export]
macro_rules! export_app {
    ($register:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn ccf_rust_app_abi_version() -> u32 {
            $crate::ABI_VERSION
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn ccf_rust_app_register(
            raw_registry: *mut $crate::RawRegistry,
        ) -> i32 {
            // SAFETY: The C++ bridge passes a live registry for this call.
            unsafe { $crate::register_app(raw_registry, $register) }
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

    #[test]
    fn restores_app_callback_marker() {
        assert!(!in_app_callback());
        let nested = catch_app_panic(|| {
            assert!(catch_app_panic(|| ()).is_ok());
            in_app_callback()
        });
        assert_eq!(nested.ok(), Some(true));
        assert!(catch_app_panic::<()>(|| panic!("test panic")).is_err());
        assert!(!in_app_callback());
    }

    #[test]
    fn panic_hook_forwards_only_panics_outside_app_callbacks() {
        thread_local! {
            static REPORTS: Cell<usize> = const { Cell::new(0) };
        }
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            REPORTS.set(REPORTS.get() + 1);
            default_hook(info);
        }));
        install_panic_hook();

        assert!(catch_app_panic::<()>(|| panic!("test panic")).is_err());
        assert_eq!(REPORTS.get(), 0);
        assert!(catch_unwind(|| panic!("test panic")).is_err());
        assert_eq!(REPORTS.get(), 1);
    }
}
