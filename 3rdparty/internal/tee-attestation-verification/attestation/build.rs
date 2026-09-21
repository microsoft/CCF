// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(sync_crypto)");
    println!("cargo::rustc-check-cfg=cfg(async_crypto)");

    if crypto_capability("SYNC_CRYPTO") {
        println!("cargo::rustc-cfg=sync_crypto");
    }
    if crypto_capability("ASYNC_CRYPTO") {
        println!("cargo::rustc-cfg=async_crypto");
    }
}

fn crypto_capability(name: &str) -> bool {
    let var_name = format!("DEP_TAV_CRYPTO_{name}");
    std::env::var(&var_name).as_deref() == Ok("true")
}
