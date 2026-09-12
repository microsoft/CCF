# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.github


def test_get_version_from_install_prefers_full_version(tmp_path):
    share = tmp_path / "share"
    share.mkdir()
    (share / "VERSION").write_text("7.0.14", encoding="utf-8")
    (share / "VERSION_LONG").write_text("ccf-7.0.14-40-gb14367b91", encoding="utf-8")

    assert infra.github.get_version_from_install(tmp_path) == "ccf-7.0.14-40-gb14367b91"


def test_get_version_from_install_supports_legacy_install(tmp_path):
    share = tmp_path / "share"
    share.mkdir()
    (share / "VERSION").write_text("6.0.28", encoding="utf-8")

    assert infra.github.get_version_from_install(tmp_path) == "ccf-6.0.28"
