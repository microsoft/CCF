// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(sync_crypto)");
    println!("cargo::rustc-check-cfg=cfg(async_crypto)");
    println!(
        "cargo::rustc-check-cfg=cfg(crypto_backend, values(\"crypto_openssl\", \"crypto_webcrypto\", \"crypto_windows\"))"
    );

    let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let is_wasm = target_family == "wasm";
    let is_windows = target_os == "windows";
    let has_openssl = std::env::var_os("CARGO_FEATURE_CRYPTO_OPENSSL").is_some();
    let has_webcrypto = std::env::var_os("CARGO_FEATURE_CRYPTO_WEBCRYPTO").is_some();
    let has_windows = std::env::var_os("CARGO_FEATURE_CRYPTO_WINDOWS").is_some();

    let crypto_backend = if !is_wasm {
        if is_windows {
            if has_windows {
                "crypto_windows"
            } else {
                panic!("On Windows targets, `crypto_windows` must be enabled.");
            }
        } else if has_openssl {
            "crypto_openssl"
        } else {
            panic!("On native targets, `crypto_openssl` must be enabled.");
        }
    } else {
        if has_webcrypto {
            "crypto_webcrypto"
        } else {
            panic!("On WASM targets, `crypto_webcrypto` must be enabled.");
        }
    };

    let backend_map = std::collections::BTreeMap::from([
        ("crypto_openssl", (true, true)),
        ("crypto_webcrypto", (false, true)),
        ("crypto_windows", (true, true)),
    ]);

    let (sync_crypto, async_crypto) = backend_map.get(crypto_backend).unwrap();

    if *sync_crypto {
        println!("cargo::rustc-cfg=sync_crypto");
    }
    if *async_crypto {
        println!("cargo::rustc-cfg=async_crypto");
    }

    println!("cargo::metadata=sync_crypto={sync_crypto}");
    println!("cargo::metadata=async_crypto={async_crypto}");
    println!("cargo::rustc-cfg=crypto_backend=\"{crypto_backend}\"");
}
