# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Unit tests for ccf.receipt using freshly signed receipts and malformed variants."""

from hashlib import sha256
from typing import Any

import cbor2
import ccf.cose
import ccf.receipt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CLAIM = sha256(b"test claim").digest()
LEAF: list[Any] = [sha256(b"write set").digest(), "ce:2.42", CLAIM]
SIBLING = sha256(b"sibling").digest()
LEAF_ROOT = sha256(LEAF[0] + sha256(LEAF[1].encode()).digest() + CLAIM).digest()
PROOF = {1: LEAF, 2: []}
UNSET = object()


@pytest.fixture(scope="module")
def identity():
    return ec.generate_private_key(ec.SECP384R1())


def _verify(encoded, key, digest=CLAIM):
    return ccf.receipt.verify_cose(encoded, key, digest)


def _headers(identity):
    pem = identity.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    return {
        1: -35,
        4: ccf.cose.key_fingerprint_from_key(pem.decode("ascii")).encode("ascii"),
        395: 2,
    }


def _map_bytes(pairs, indefinite=False):
    encoded = b"".join(k + v for k, v in pairs)
    if indefinite:
        return b"\xbf" + encoded + b"\xff"
    return bytes([0xA0 + len(pairs)]) + encoded


def _signed(
    identity,
    *,
    root=LEAF_ROOT,
    protected=UNSET,
    protected_bytes=None,
    unprotected=UNSET,
    unprotected_bytes=None,
    proof=PROOF,
    payload=None,
):
    if protected_bytes is None:
        protected_bytes = cbor2.dumps(
            _headers(identity) if protected is UNSET else protected
        )
    if unprotected_bytes is None:
        unprotected_bytes = cbor2.dumps(
            {396: {-1: [cbor2.dumps(proof)]}} if unprotected is UNSET else unprotected
        )
    to_sign = cbor2.dumps(
        ["Signature1", protected_bytes, b"", root if payload is None else payload]
    )
    r, s = utils.decode_dss_signature(identity.sign(to_sign, ec.ECDSA(hashes.SHA384())))
    signature = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    return (
        b"\xd2\x84"
        + cbor2.dumps(protected_bytes)
        + unprotected_bytes
        + cbor2.dumps(payload)
        + cbor2.dumps(signature)
    )


def _proof_receipt(identity, proof_bytes):
    return _signed(identity, unprotected={396: {-1: [proof_bytes]}})


def test_empty_inclusion_path_is_valid(identity):
    assert _verify(_signed(identity), identity.public_key()) == _headers(identity)


@pytest.mark.parametrize(
    "extension",
    [
        b"\xa1\xa0\x00",
        b"\xa1\xa1\x01\x82\x02\x03\x00",
        b"\xa1\x82\xa0\x81\x00\x00",
        b"\xa1\xd9\x03\xe8\xa0\x00",
        b"\xa1\xd9\x03\xe8\x81\xa0\x00",
        b"\xa1\xa1\xd9\x03\xe8\xa0\x81\xa0\x00",
        b"\xbf\xbf\xff\x00\xff",
        b"\xa1\x9f\xbf\xff\xff\x00",
    ],
)
@pytest.mark.parametrize("location", ["protected", "unprotected"])
def test_extension_container_keys_are_valid(identity, extension, location):
    protected_pairs = [
        (cbor2.dumps(label), cbor2.dumps(value))
        for label, value in _headers(identity).items()
    ]
    unprotected_pairs = [(cbor2.dumps(396), cbor2.dumps({-1: [cbor2.dumps(PROOF)]}))]
    pairs = protected_pairs if location == "protected" else unprotected_pairs
    pairs.insert(0, (cbor2.dumps("extension"), extension))
    encoded = _signed(
        identity,
        protected_bytes=_map_bytes(protected_pairs),
        unprotected_bytes=_map_bytes(unprotected_pairs),
    )
    headers = _verify(encoded, identity.public_key())
    assert headers[1] == -35
    assert headers[395] == 2
    if location == "protected":
        assert headers["extension"] == cbor2.loads(extension)


@pytest.mark.parametrize(
    "first,second",
    [
        (b"\xa1\x01\x80", b"\xa1\x18\x01\x80"),
        (b"\x81\xa1\x01\x80", b"\x81\xa1\x18\x01\x80"),
        (b"\xd9\x03\xe8\xa1\x01\x80", b"\xd9\x03\xe8\xa1\x18\x01\x80"),
    ],
)
def test_rejects_duplicate_extension_container_keys(identity, first, second):
    extension = _map_bytes([(first, b"\x00"), (second, b"\x00")])
    encoded = _signed(
        identity,
        unprotected_bytes=_map_bytes(
            [
                (cbor2.dumps("extension"), extension),
                (cbor2.dumps(396), cbor2.dumps({-1: [cbor2.dumps(PROOF)]})),
            ]
        ),
    )
    with pytest.raises(ValueError, match="Duplicate CBOR map key"):
        _verify(encoded, identity.public_key())


@pytest.mark.parametrize(
    "first,second,duplicate",
    [
        ("f97e00", "f97e00", True),
        ("f97e01", "f97e01", True),
        ("fa7fc00001", "fa7fc00001", True),
        ("fb7ff8000000000001", "fb7ff8000000000001", True),
        ("f97e01", "fa7fc02000", True),
        ("f97e01", "fb7ff8040000000000", True),
        ("f97e01", "f9fe01", True),
        ("f97e01", "f97e02", False),
        ("fa7fc00001", "fa7fc00002", False),
        ("fb7ff8000000000001", "fb7ff8000000000002", False),
    ],
)
@pytest.mark.parametrize(
    "prefix,suffix",
    [
        pytest.param("", "", id="scalar"),
        pytest.param("81", "", id="array"),
        pytest.param("a1", "00", id="map-key"),
        pytest.param("a100", "", id="map-value"),
        pytest.param("d903e8", "", id="tag"),
    ],
)
@pytest.mark.parametrize("location", ["protected", "unprotected"])
def test_nan_extension_key_equivalence(
    identity, first, second, duplicate, prefix, suffix, location
):
    extension = _map_bytes(
        [
            (bytes.fromhex(prefix + first + suffix), b"\x00"),
            (bytes.fromhex(prefix + second + suffix), b"\x01"),
        ]
    )
    protected_pairs = [
        (cbor2.dumps(label), cbor2.dumps(value))
        for label, value in _headers(identity).items()
    ]
    unprotected_pairs = [(cbor2.dumps(396), cbor2.dumps({-1: [cbor2.dumps(PROOF)]}))]
    pairs = protected_pairs if location == "protected" else unprotected_pairs
    pairs.insert(0, (cbor2.dumps("extension"), extension))
    encoded = _signed(
        identity,
        protected_bytes=_map_bytes(protected_pairs),
        unprotected_bytes=_map_bytes(unprotected_pairs),
    )

    if duplicate:
        with pytest.raises(ValueError, match="Duplicate CBOR map key"):
            _verify(encoded, identity.public_key())
    else:
        _verify(encoded, identity.public_key())


@pytest.mark.parametrize("evidence", ["a", "a" * 1024, "\u00e9" * 512])
def test_commit_evidence_utf8_boundaries(identity, evidence):
    leaf = [LEAF[0], evidence, CLAIM]
    root = sha256(leaf[0] + sha256(evidence.encode()).digest() + CLAIM).digest()
    _verify(_signed(identity, proof={1: leaf, 2: []}, root=root), identity.public_key())


def test_multiple_inclusions_and_consistency_proofs(identity):
    root = sha256(LEAF_ROOT + LEAF_ROOT).digest()
    inclusions = [
        cbor2.dumps({1: LEAF, 2: [[False, LEAF_ROOT]]}),
        cbor2.dumps({1: LEAF, 2: [[True, LEAF_ROOT]]}),
    ]
    consistency = cbor2.dumps({1: LEAF_ROOT, 2: [[False, LEAF_ROOT]]})
    _verify(
        _signed(
            identity,
            root=root,
            unprotected={396: {-1: inclusions, -2: [consistency, consistency]}},
        ),
        identity.public_key(),
    )


def test_multiple_inclusions_must_all_match_claim(identity):
    other_leaf = [LEAF[0], LEAF[1], sha256(b"other claim").digest()]
    other_root = sha256(
        other_leaf[0] + sha256(other_leaf[1].encode()).digest() + other_leaf[2]
    ).digest()
    root = sha256(LEAF_ROOT + other_root).digest()
    proofs = [
        cbor2.dumps({1: LEAF, 2: [[False, other_root]]}),
        cbor2.dumps({1: other_leaf, 2: [[True, LEAF_ROOT]]}),
    ]
    with pytest.raises(ValueError, match="Claim digest mismatch"):
        _verify(
            _signed(identity, root=root, unprotected={396: {-1: proofs}}),
            identity.public_key(),
        )


def test_multiple_inclusions_must_reconstruct_same_root(identity):
    proofs = [
        cbor2.dumps(PROOF),
        cbor2.dumps({1: LEAF, 2: [[False, SIBLING]]}),
    ]
    with pytest.raises(ValueError, match="different roots"):
        _verify(
            _signed(identity, unprotected={396: {-1: proofs}}),
            identity.public_key(),
        )


@pytest.mark.parametrize(
    "proof",
    [
        None,
        [],
        {1: LEAF},
        {2: []},
        {1: LEAF, 2: [], 3: b""},
        {True: LEAF, 2: []},
        {1.0: LEAF, 2: []},
        {"1": LEAF, 2: []},
        {1: [], 2: []},
        {1: LEAF[:2], 2: []},
        {1: LEAF + [b""], 2: []},
        {1: {0: LEAF[0], 1: LEAF[1], 2: LEAF[2]}, 2: []},
        {1: [b"", LEAF[1], CLAIM], 2: []},
        {1: [b"x" * 31, LEAF[1], CLAIM], 2: []},
        {1: [b"x" * 33, LEAF[1], CLAIM], 2: []},
        {1: ["x" * 32, LEAF[1], CLAIM], 2: []},
        {1: [LEAF[0], b"evidence", CLAIM], 2: []},
        {1: [LEAF[0], "", CLAIM], 2: []},
        {1: [LEAF[0], "x" * 1025, CLAIM], 2: []},
        {1: [LEAF[0], "\u00e9" * 513, CLAIM], 2: []},
        {1: [LEAF[0], None, CLAIM], 2: []},
        {1: [LEAF[0], LEAF[1], b"x" * 31], 2: []},
        {1: [LEAF[0], LEAF[1], "x" * 32], 2: []},
        {1: LEAF, 2: None},
        {1: LEAF, 2: {}},
        {1: LEAF, 2: b""},
        {1: LEAF, 2: [[0, SIBLING]]},
        {1: LEAF, 2: [[1, SIBLING]]},
        {1: LEAF, 2: [["false", SIBLING]]},
        {1: LEAF, 2: [[False]]},
        {1: LEAF, 2: [[False, SIBLING, b"extra"]]},
        {1: LEAF, 2: [{0: False, 1: SIBLING}]},
        {1: LEAF, 2: [[False, b"x" * 31]]},
        {1: LEAF, 2: [[False, b"x" * 33]]},
        {1: LEAF, 2: [[False, "x" * 32]]},
        {1: cbor2.CBORTag(55799, LEAF), 2: []},
        {1: LEAF, 2: cbor2.CBORTag(55799, [])},
        {1: [LEAF[0], LEAF[1], cbor2.CBORTag(55799, CLAIM)], 2: []},
    ],
)
def test_rejects_malformed_inclusions(identity, proof):
    with pytest.raises(ValueError):
        _verify(_signed(identity, proof=proof), identity.public_key())


@pytest.mark.parametrize(
    "unprotected",
    [
        None,
        [],
        {},
        {396: None},
        {396: []},
        {396: {}},
        {396: {-3: [b""]}},
        {396: {-1: [cbor2.dumps(PROOF)], 0: []}},
        {396: {-1: []}},
        {396: {-1: b"proof"}},
        {396: {-1: [PROOF]}},
        {396: {-1: [None]}},
        {396: {-1: [cbor2.dumps(PROOF)], -2: []}},
        {396: {-1: [cbor2.dumps(PROOF)], -2: b""}},
        {396: {-1: [cbor2.dumps(PROOF)], -2: [None]}},
        {396: {-1.0: [cbor2.dumps(PROOF)]}},
        {396.0: {-1: [cbor2.dumps(PROOF)]}},
        {396: {-2: [cbor2.dumps({1: LEAF_ROOT, 2: [[False, SIBLING]]})]}},
    ],
)
def test_rejects_malformed_proof_headers(identity, unprotected):
    with pytest.raises(ValueError):
        _verify(_signed(identity, unprotected=unprotected), identity.public_key())


@pytest.mark.parametrize(
    "label,value",
    [
        (1, UNSET),
        (1, True),
        (1, -35.0),
        (1, "-35"),
        (1, cbor2.CBORTag(3, b"\x22")),
        (395, UNSET),
        (395, True),
        (395, 2.0),
        (395, 1),
        (395, "2"),
        (4, UNSET),
        (4, "kid"),
        (4, b"wrong key"),
    ],
)
def test_rejects_invalid_protected_fields(identity, label, value):
    protected = _headers(identity)
    if value is UNSET:
        del protected[label]
    else:
        protected[label] = value
    with pytest.raises((ValueError, ccf.signatures.InvalidRootCoseSignatureException)):
        _verify(_signed(identity, protected=protected), identity.public_key())


@pytest.mark.parametrize("protected", [None, [], b"", cbor2.CBORTag(55799, {})])
def test_rejects_non_map_protected_headers(identity, protected):
    with pytest.raises(ValueError):
        _verify(_signed(identity, protected=protected), identity.public_key())


@pytest.mark.parametrize("label", [True, 1.0])
def test_rejects_non_integer_protected_label(identity, label):
    protected = _headers(identity)
    del protected[1]
    protected[label] = -35
    with pytest.raises(ValueError):
        _verify(_signed(identity, protected=protected), identity.public_key())


@pytest.mark.parametrize("location", ["outer", "protected", "inclusion", "consistency"])
def test_rejects_trailing_cbor(identity, location):
    if location == "outer":
        encoded = _signed(identity) + b"\x00"
    elif location == "protected":
        encoded = _signed(
            identity, protected_bytes=cbor2.dumps(_headers(identity)) + b"\x00"
        )
    elif location == "inclusion":
        encoded = _proof_receipt(identity, cbor2.dumps(PROOF) + b"\x00")
    else:
        root = sha256(LEAF_ROOT + SIBLING).digest()
        encoded = _signed(
            identity,
            root=root,
            proof={1: LEAF, 2: [[False, SIBLING]]},
            unprotected={
                396: {
                    -1: [cbor2.dumps({1: LEAF, 2: [[False, SIBLING]]})],
                    -2: [cbor2.dumps({1: LEAF_ROOT, 2: [[False, SIBLING]]}) + b"\x00"],
                }
            },
        )
    with pytest.raises(ValueError, match="Trailing data"):
        _verify(encoded, identity.public_key())


@pytest.mark.parametrize("indefinite", [False, True])
@pytest.mark.parametrize("alternate_encoding", [False, True])
@pytest.mark.parametrize(
    "location",
    ["protected", "unprotected", "vdp", "leaf", "path", "consistency", "extension"],
)
def test_rejects_duplicate_map_keys(identity, indefinite, alternate_encoding, location):
    def duplicate(label, value):
        canonical = cbor2.dumps(label)
        if label == 396:
            alternate = b"\x1a\x00\x00\x01\x8c"
        elif label == -1:
            alternate = b"\x38\x00"
        else:
            alternate = bytes([0x18, label])
        return _map_bytes(
            [
                (canonical, value),
                (alternate if alternate_encoding else canonical, value),
            ],
            indefinite=indefinite,
        )

    if location == "protected":
        headers = _headers(identity)
        pairs = [(cbor2.dumps(k), cbor2.dumps(v)) for k, v in headers.items()]
        pairs.append((b"\x18\x01" if alternate_encoding else b"\x01", cbor2.dumps(-35)))
        encoded = _signed(
            identity, protected_bytes=_map_bytes(pairs, indefinite=indefinite)
        )
    elif location == "unprotected":
        encoded = _signed(
            identity,
            unprotected_bytes=duplicate(396, cbor2.dumps({-1: [cbor2.dumps(PROOF)]})),
        )
    elif location == "vdp":
        encoded = _signed(
            identity,
            unprotected_bytes=_map_bytes(
                [(cbor2.dumps(396), duplicate(-1, cbor2.dumps([cbor2.dumps(PROOF)])))]
            ),
        )
    elif location in ("leaf", "path"):
        label = 1 if location == "leaf" else 2
        pairs = [(cbor2.dumps(k), cbor2.dumps(v)) for k, v in PROOF.items()]
        pairs.append(
            (
                bytes([0x18, label]) if alternate_encoding else cbor2.dumps(label),
                cbor2.dumps(PROOF[label]),
            )
        )
        encoded = _proof_receipt(identity, _map_bytes(pairs, indefinite=indefinite))
    elif location == "consistency":
        encoded = _signed(
            identity,
            unprotected={
                396: {
                    -1: [cbor2.dumps(PROOF)],
                    -2: [duplicate(1, cbor2.dumps(LEAF_ROOT))],
                }
            },
        )
    else:
        encoded = _signed(
            identity,
            unprotected_bytes=_map_bytes(
                [
                    (cbor2.dumps(396), cbor2.dumps({-1: [cbor2.dumps(PROOF)]})),
                    (cbor2.dumps("extension"), duplicate(1, b"\x00")),
                ]
            ),
        )
    with pytest.raises(ValueError, match="Duplicate CBOR map key"):
        _verify(encoded, identity.public_key())


@pytest.mark.parametrize(
    "consistency",
    [
        None,
        [],
        {1: LEAF_ROOT},
        {2: [[False, SIBLING]]},
        {1: LEAF_ROOT, 2: [[False, SIBLING]], 3: b""},
        {True: LEAF_ROOT, 2: [[False, SIBLING]]},
        {1: LEAF, 2: [[False, SIBLING]]},
        {1: b"x" * 31, 2: [[False, SIBLING]]},
        {1: "x" * 32, 2: [[False, SIBLING]]},
        {1: LEAF_ROOT, 2: []},
        {1: LEAF_ROOT, 2: None},
        {1: LEAF_ROOT, 2: [[True, SIBLING]]},
        {1: LEAF_ROOT, 2: [[0, SIBLING]]},
        {1: LEAF_ROOT, 2: [[False, b"x" * 31]]},
        {1: LEAF_ROOT, 2: [[False, SIBLING, b""]]},
        {1: LEAF_ROOT, 2: [[False, LEAF_ROOT]]},
    ],
)
def test_rejects_malformed_consistency(identity, consistency):
    root = sha256(LEAF_ROOT + SIBLING).digest()
    with pytest.raises(ValueError):
        _verify(
            _signed(
                identity,
                root=root,
                unprotected={
                    396: {
                        -1: [cbor2.dumps({1: LEAF, 2: [[False, SIBLING]]})],
                        -2: [cbor2.dumps(consistency)],
                    }
                },
            ),
            identity.public_key(),
        )


def test_all_consistency_proofs_must_match_root(identity):
    root = sha256(LEAF_ROOT + SIBLING).digest()
    with pytest.raises(ValueError, match="Consistency proof"):
        _verify(
            _signed(
                identity,
                root=root,
                unprotected={
                    396: {
                        -1: [cbor2.dumps({1: LEAF, 2: [[False, SIBLING]]})],
                        -2: [
                            cbor2.dumps({1: LEAF_ROOT, 2: [[False, SIBLING]]}),
                            cbor2.dumps({1: LEAF_ROOT, 2: [[False, LEAF_ROOT]]}),
                        ],
                    }
                },
            ),
            identity.public_key(),
        )


def test_first_consistency_sibling_must_be_right_even_if_root_matches(identity):
    root = sha256(LEAF_ROOT + LEAF_ROOT).digest()
    with pytest.raises(ValueError, match="First consistency proof sibling"):
        _verify(
            _signed(
                identity,
                root=root,
                unprotected={
                    396: {
                        -1: [cbor2.dumps({1: LEAF, 2: [[False, LEAF_ROOT]]})],
                        -2: [cbor2.dumps({1: LEAF_ROOT, 2: [[True, LEAF_ROOT]]})],
                    }
                },
            ),
            identity.public_key(),
        )


def test_consistency_can_have_left_siblings_after_first(identity):
    path = [[False, SIBLING], [True, SIBLING]]
    root = sha256(SIBLING + sha256(LEAF_ROOT + SIBLING).digest()).digest()
    _verify(
        _signed(
            identity,
            root=root,
            unprotected={
                396: {
                    -1: [cbor2.dumps({1: LEAF, 2: path})],
                    -2: [cbor2.dumps({1: LEAF_ROOT, 2: path})],
                }
            },
        ),
        identity.public_key(),
    )


@pytest.mark.parametrize("payload", [b"", LEAF_ROOT, b"unrelated", 0])
def test_rejects_embedded_payload_even_if_signed(identity, payload):
    with pytest.raises(ValueError, match="detached"):
        _verify(_signed(identity, payload=payload), identity.public_key())


def test_rejects_wrong_key_digest_and_signature(identity):
    encoded = _signed(identity)
    other_key = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(ValueError, match="expected key"):
        _verify(encoded, other_key.public_key())
    with pytest.raises(ValueError, match="Claim digest mismatch"):
        _verify(encoded, identity.public_key(), b"x" * 32)
    with pytest.raises(ccf.signatures.InvalidRootCoseSignatureException):
        _verify(encoded[:-1] + bytes([encoded[-1] ^ 1]), identity.public_key())
    with pytest.raises(ccf.signatures.InvalidRootCoseSignatureException):
        _verify(_signed(identity, root=SIBLING), identity.public_key())
    with pytest.raises(ccf.signatures.InvalidRootCoseSignatureException):
        protected = _headers(other_key)
        forged = _signed(identity, protected=protected)
        _verify(forged, other_key.public_key())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.value,
        lambda value: cbor2.CBORTag(17, value.value),
        lambda value: cbor2.CBORTag(18, value.value[:3]),
        lambda value: cbor2.CBORTag(18, value.value + [b""]),
        lambda value: cbor2.CBORTag(18, None),
        lambda value: cbor2.CBORTag(18, {i: x for i, x in enumerate(value.value)}),
        lambda value: cbor2.CBORTag(18, [{}, *value.value[1:]]),
        lambda value: cbor2.CBORTag(18, [*value.value[:3], "signature"]),
        lambda value: cbor2.CBORTag(55799, value),
    ],
)
def test_rejects_invalid_cose_envelope(identity, mutate):
    with pytest.raises(ValueError):
        _verify(
            cbor2.dumps(mutate(cbor2.loads(_signed(identity)))),
            identity.public_key(),
        )


@pytest.mark.parametrize("digest", [b"", b"x" * 31, b"x" * 33, "x" * 32, None])
def test_rejects_invalid_caller_digest(identity, digest):
    with pytest.raises(ValueError):
        _verify(_signed(identity), identity.public_key(), digest)


@pytest.mark.parametrize(
    "encoded",
    [
        b"",
        b"\xd2\x84",
        b"\xff",
        b"\x1c",
        b"\xa1\x01",
        b"\x5f\x5f\xff\xff",
        b"\x61\xff",
    ],
)
def test_rejects_invalid_outer_cbor(identity, encoded):
    with pytest.raises(ValueError):
        _verify(encoded, identity.public_key())


@pytest.mark.parametrize(
    "invalid",
    [
        b"\xff",
        b"\x81\xff",
        b"\xa1\x01\xff",
        b"\xbf\x01\xff",
        b"\xc0\xff",
        b"\xf8\x00",
        b"\xf8\x14",
        b"\xf8\x18",
        b"\x61\xff",
        b"\x7f\x61\xc3\x61\xa9\xff",
    ],
)
def test_rejects_invalid_cbor_in_unprotected_extensions(identity, invalid):
    unprotected = _map_bytes(
        [
            (cbor2.dumps(396), cbor2.dumps({-1: [cbor2.dumps(PROOF)]})),
            (cbor2.dumps("extension"), invalid),
        ]
    )
    with pytest.raises(ValueError):
        _verify(_signed(identity, unprotected_bytes=unprotected), identity.public_key())


def test_rejects_invalid_utf8_commit_evidence(identity):
    leaf_bytes = b"\x83" + cbor2.dumps(LEAF[0]) + b"\x61\xff" + cbor2.dumps(CLAIM)
    proof_bytes = _map_bytes(
        [(cbor2.dumps(1), leaf_bytes), (cbor2.dumps(2), cbor2.dumps([]))]
    )
    with pytest.raises(ValueError):
        _verify(_proof_receipt(identity, proof_bytes), identity.public_key())


@pytest.mark.parametrize("collision", [b"\xf5", cbor2.dumps(1.0), b"\xe1"])
def test_rejects_integer_key_collisions(identity, collision):
    proof = _map_bytes(
        [
            (b"\x01", cbor2.dumps(LEAF)),
            (collision, cbor2.dumps(LEAF)),
            (b"\x02", b"\x80"),
        ]
    )
    with pytest.raises(ValueError, match="Duplicate CBOR map key"):
        _verify(_proof_receipt(identity, proof), identity.public_key())


def test_duplicate_is_rejected_before_decoding_its_value(identity):
    proof = b"\xa2\x01" + cbor2.dumps(LEAF) + b"\x18\x01"
    with pytest.raises(ValueError, match="Duplicate CBOR map key"):
        _verify(_proof_receipt(identity, proof), identity.public_key())


def test_valid_indefinite_maps_and_arrays(identity):
    leaf_bytes = b"\x9f" + b"".join(cbor2.dumps(x) for x in LEAF) + b"\xff"
    proof = _map_bytes([(b"\x01", leaf_bytes), (b"\x02", b"\x9f\xff")], indefinite=True)
    unprotected = _map_bytes(
        [(cbor2.dumps(396), cbor2.dumps({-1: [proof]}))], indefinite=True
    )
    _verify(_signed(identity, unprotected_bytes=unprotected), identity.public_key())
