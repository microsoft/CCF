// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

use ccf_app::{Auth, BridgeError, EndpointError, EndpointResult, Registry};

const RECORDS: &str = "records";

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

    registry.read_only("/panic", "GET", Auth::None, |_| -> EndpointResult {
        panic!("test panic")
    })?;

    registry.read_only("/health", "GET", Auth::None, |context| {
        context.set_status(200)?;
        context.set_body(b"OK")?;
        Ok(())
    })?;

    Ok(())
}

ccf_app::export_app!(register);
