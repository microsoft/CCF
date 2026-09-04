// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared immutable CBOR document views for the native and WebAssembly FFIs.
//!
//! A view keeps an [`Arc`] to the parsed document and a pointer to either its
//! root or one of its nodes. The document is never exposed mutably, so moving
//! or reallocating descendants after a view is created is impossible.

use std::sync::Arc;

use cose::CborValue;

/// A CBOR value stored behind a native FFI handle.
pub(crate) type NativeCborValue = CborValue<'static>;

#[derive(Clone)]
pub struct CborView {
    document: Arc<NativeCborValue>,
    node: *const NativeCborValue,
}

impl CborView {
    /// Detaches `value` from any input buffer, which a view outlives.
    pub(crate) fn new(value: CborValue<'_>) -> Self {
        Self::from_native(value.into_owned())
    }

    /// Takes ownership of a value whose borrowed payloads already satisfy the
    /// native FFI's lifetime contract.
    pub(crate) fn from_native(value: NativeCborValue) -> Self {
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

    /// Materializes this view for insertion into a new document.
    ///
    /// An unshared root moves without cloning. Shared roots and projections
    /// clone the selected subtree while preserving borrowed payloads.
    pub(crate) fn into_native(self) -> NativeCborValue {
        let Self { document, node } = self;
        if node == Arc::as_ptr(&document) {
            Arc::try_unwrap(document).unwrap_or_else(|document| (*document).clone())
        } else {
            // SAFETY: `node` points into `document`, which remains alive until
            // after the selected subtree has been cloned.
            unsafe { (&*node).clone() }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    fn owned_bytes(bytes: Vec<u8>) -> NativeCborValue {
        NativeCborValue::ByteString(Cow::Owned(bytes))
    }

    fn payload_ptr(value: &NativeCborValue) -> *const u8 {
        match value {
            NativeCborValue::ByteString(bytes) => bytes.as_ptr(),
            _ => panic!("expected byte string"),
        }
    }

    #[test]
    fn a_unique_root_moves_its_owned_payload() {
        let view = CborView::from_native(owned_bytes(vec![1, 2, 3]));
        let before = payload_ptr(view.as_native());

        let value = view.into_native();

        assert_eq!(payload_ptr(&value), before);
    }

    #[test]
    fn a_shared_root_clones_its_owned_payload() {
        let view = CborView::from_native(owned_bytes(vec![1, 2, 3]));
        let shared = view.clone();
        let before = payload_ptr(view.as_native());

        let value = shared.into_native();

        assert_ne!(payload_ptr(&value), before);
        assert_eq!(value, *view.as_native());
    }

    #[test]
    fn a_projection_clones_only_its_selected_subtree() {
        let root = CborView::from_native(NativeCborValue::Array(vec![owned_bytes(vec![1, 2, 3])]));
        let [projection] = root
            .project(|value| value.array_at(0).map(|child| [child]))
            .unwrap();
        let before = payload_ptr(projection.as_native());

        let value = projection.into_native();

        assert_ne!(payload_ptr(&value), before);
        assert_eq!(value, *root.as_native().array_at(0).unwrap());
    }
}
