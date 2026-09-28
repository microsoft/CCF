// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use ccf_app::{Auth, BridgeError, EndpointError, EndpointResult, Registry};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const COMPACTION_DELAY_MS: u64 = 2_000;
const COMPACTION_MARKER: &str = "compaction_marker";
const COMPACTION_RECORDS: &str = "compaction_records";
const RECORDS: &str = "records";
static COMPACTION_READY: AtomicBool = AtomicBool::new(false);

fn required_key(value: Result<Option<String>, BridgeError>) -> Result<String, EndpointError> {
    value?.ok_or_else(|| EndpointError::new(400, "InvalidResourceName", "Missing key"))
}

fn register(registry: &mut Registry) -> Result<(), BridgeError> {
    registry.read_write(
        "/records/{key}",
        "PUT",
        Auth::UserCert,
        |context| -> EndpointResult {
            let body = context.body()?.to_vec();
            let key = required_key(context.path_param("key"))?;
            context.map(RECORDS).put(key.as_bytes(), &body)?;
            context.set_status(204)?;
            Ok(())
        },
    )?;

    registry.read_only(
        "/records/{key}",
        "GET",
        Auth::UserCert,
        |context| -> EndpointResult {
            let key = required_key(context.path_param("key"))?;
            match context.map(RECORDS).get(key.as_bytes())? {
                Some(value) => {
                    context.set_status(200)?;
                    context.set_header("content-type", "application/octet-stream")?;
                    context.set_body(&value)?;
                    Ok(())
                }
                None => Err(EndpointError::new(404, "ResourceNotFound", "No such key")),
            }
        },
    )?;

    registry.read_write("/compaction/marker", "POST", Auth::None, |context| {
        COMPACTION_READY.store(false, Ordering::Release);
        context.map(COMPACTION_MARKER).put(b"init", b"init")?;
        context.set_status(204)?;
        Ok(())
    })?;

    registry.read_only("/compaction/ready", "GET", Auth::None, |context| {
        context.set_status(if COMPACTION_READY.load(Ordering::Acquire) {
            200
        } else {
            404
        })?;
        Ok(())
    })?;

    registry.read_write(
        "/compaction/fast/{key}",
        "POST",
        Auth::None,
        |context| -> EndpointResult {
            let key = required_key(context.path_param("key"))?;
            context
                .map(COMPACTION_RECORDS)
                .put(key.as_bytes(), b"fast")?;
            context.set_status(204)?;
            Ok(())
        },
    )?;

    registry.read_write(
        "/compaction/slow",
        "POST",
        Auth::None,
        |context| -> EndpointResult {
            if !context.map(COMPACTION_MARKER).has(b"init")? {
                return Err(EndpointError::internal("Compaction marker is missing"));
            }

            // This idempotent signal lets the e2e test advance the other map
            // only after this transaction's read version is fixed.
            COMPACTION_READY.store(true, Ordering::Release);
            thread::sleep(Duration::from_millis(COMPACTION_DELAY_MS));

            let retried = context.map(COMPACTION_RECORDS).has(b"retry")?;
            context.map(COMPACTION_RECORDS).put(b"slow", b"slow")?;
            context.set_status(200)?;
            context.set_body(if retried { b"retried" } else { b"first" })?;
            Ok(())
        },
    )?;

    registry.read_only("/panic", "GET", Auth::None, |_| -> EndpointResult {
        panic!("test panic")
    })?;

    registry.read_only(
        "/invalid-error-status",
        "GET",
        Auth::None,
        |_| -> EndpointResult {
            Err(EndpointError::new(
                432,
                "InvalidStatus",
                "Unsupported status",
            ))
        },
    )?;

    registry.read_only(
        "/empty-error-code",
        "GET",
        Auth::None,
        |_| -> EndpointResult { Err(EndpointError::new(400, "", "Empty error code")) },
    )?;

    registry.read_only("/health", "GET", Auth::None, |context| {
        context.set_status(200)?;
        context.set_body(b"OK")?;
        Ok(())
    })?;

    registry.read_only("/header-validation", "GET", Auth::None, |context| {
        for (name, value) in [
            ("bad name", "value"),
            ("bad\r\nname", "value"),
            ("x-test", "bad\r\nx-injected: true"),
            ("x-test", "bad\u{7f}"),
        ] {
            if context.set_header(name, value) != Err(BridgeError::InvalidArgument) {
                return Err(EndpointError::internal(
                    "Invalid response header was accepted",
                ));
            }
        }
        context.set_header("x-valid", "safe\tvalue")?;
        context.set_status(204)?;
        Ok(())
    })?;

    Ok(())
}

ccf_app::export_app!(register);
