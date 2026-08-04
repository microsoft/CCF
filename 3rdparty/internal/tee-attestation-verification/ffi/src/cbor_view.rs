// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared immutable CBOR document views for the native and WebAssembly FFIs.
//!
//! A view keeps an [`Arc`] to the parsed document and a pointer to either its
//! root or one of its nodes. The document is never exposed mutably, so moving
//! or reallocating descendants after a view is created is impossible.

use std::sync::Arc;

use cose::CborValue as NativeCborValue;

#[derive(Clone)]
pub struct CborView {
    document: Arc<NativeCborValue>,
    node: *const NativeCborValue,
}

impl CborView {
    pub(crate) fn new(value: NativeCborValue) -> Self {
        let document = Arc::new(value);
        let node = Arc::as_ptr(&document);
        Self { document, node }
    }

    pub(crate) fn as_native(&self) -> &NativeCborValue {
        // SAFETY: `node` is initialized from `document` or by `project` from
        // a reference whose lifetime is tied to the current node. CBOR values
        // reachable through an immutable `NativeCborValue` cannot move because
        // this type never exposes mutable access. `document` keeps the complete
        // allocation graph alive for at least as long as this view.
        unsafe { &*self.node }
    }

    pub(crate) fn project<const N: usize, E>(
        &self,
        project: impl for<'a> FnOnce(&'a NativeCborValue) -> Result<[&'a NativeCborValue; N], E>,
    ) -> Result<[Self; N], E> {
        let nodes = project(self.as_native())?;
        Ok(nodes.map(|node| Self {
            document: Arc::clone(&self.document),
            node,
        }))
    }
}
