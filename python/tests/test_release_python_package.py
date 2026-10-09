# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parents[2]
RELEASE_INSTALL = "uv pip install -q --upgrade --reinstall-package ccf ccf"


@pytest.fixture
def shell_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    log = tmp_path / "commands.log"
    monkeypatch.setenv("COMMAND_LOG", str(log))
    monkeypatch.setenv("STUB_BIN", str(stubs))
    monkeypatch.setenv("PATH", f"{stubs}:{os.environ['PATH']}")
    for name in (
        "CCF_USE_RELEASED_PYTHON_PACKAGE",
        "CCF_TEST_SYNC_AFTER_SETUP",
        "PYTHON_PACKAGE_PATH",
        "VENV_DIR",
        "PIP_INDEX_URL",
        "UV_INDEX_URL",
        "UV_FAIL_CODE",
    ):
        monkeypatch.delenv(name, raising=False)
    scripts = {
        "uv": """
printf 'uv %s\\n' "$*" >> "$COMMAND_LOG"
exit "${UV_FAIL_CODE:-0}"
""",
        "python3": """
printf 'python3 %s\\n' "$*" >> "$COMMAND_LOG"
[[ "$1" == "-m" && "$2" == "venv" ]]
venv="${@: -1}"
mkdir -p "$venv/bin"
printf ':\\n' > "$venv/bin/activate"
""",
        "python": """printf 'python %s\\n' "$*" >> "$COMMAND_LOG"\n""",
        "ctest": """
[[ -f "$VENV_DIR/bin/activate" ]]
printf 'ctest %s\\n' "$*" >> "$COMMAND_LOG"
""",
        "curl": """
count_file="$COMMAND_LOG.curl-count"
count=0
if [[ -f "$count_file" ]]; then
    count=$(<"$count_file")
fi
count=$((count + 1))
printf '%s\\n' "$count" > "$count_file"
if ((count <= 2)); then
    printf '200'
else
    printf '500'
fi
""",
    }
    for name, content in scripts.items():
        path = stubs / name
        path.write_text("#!/bin/bash\nset -euo pipefail\n" + content)
        path.chmod(0o755)
    installer = tmp_path / "scripts" / "install_uv.sh"
    installer.parent.mkdir()
    installer.write_text("#!/bin/bash\nexit 0\n")
    return log


@pytest.mark.parametrize("released", [False, True])
def test_test_wrapper_selects_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shell_environment: Path,
    released: bool,
) -> None:
    build = tmp_path / "build"
    build.mkdir()
    if released:
        monkeypatch.setenv("CCF_USE_RELEASED_PYTHON_PACKAGE", "1")
    subprocess.run(
        ["bash", str(REPO_ROOT / "tests" / "tests.sh"), "-N"],
        cwd=build,
        check=True,
        capture_output=True,
        timeout=10,
    )
    commands = shell_environment.read_text().splitlines()
    expected = RELEASE_INSTALL if released else "uv pip install -q -e ../python/"
    assert expected in commands
    assert "ctest -N" in commands
    if released:
        assert not any("-e " in command for command in commands)


def test_test_wrapper_stops_if_package_installation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shell_environment: Path
) -> None:
    build = tmp_path / "build"
    build.mkdir()
    monkeypatch.setenv("CCF_USE_RELEASED_PYTHON_PACKAGE", "1")
    monkeypatch.setenv("UV_FAIL_CODE", "9")
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "tests" / "tests.sh"), "-N"],
        cwd=build,
        check=False,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 9
    assert "ctest -N" not in shell_environment.read_text()


@pytest.mark.parametrize(
    "installed, released, local_override, reused",
    [
        (False, False, False, False),
        (False, True, False, False),
        (True, False, False, False),
        (True, True, False, False),
        (True, False, True, False),
        (True, True, True, False),
        (False, False, False, True),
        (False, True, False, True),
        (True, True, False, True),
    ],
)
def test_sandbox_selects_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shell_environment: Path,
    installed: bool,
    released: bool,
    local_override: bool,
    reused: bool,
) -> None:
    sandbox_dir = (
        tmp_path / "install" / "bin" if installed else tmp_path / "tests" / "sandbox"
    )
    sandbox_dir.mkdir(parents=True)
    sandbox = sandbox_dir / "sandbox.sh"
    shutil.copyfile(REPO_ROOT / "tests" / "sandbox" / "sandbox.sh", sandbox)
    if installed:
        share = sandbox_dir.parent / "share"
        share.mkdir()
        (share / "VERSION_LONG").write_text("ccf-7.0.19+unsafe\n")
        shutil.copyfile(
            tmp_path / "scripts" / "install_uv.sh", sandbox_dir / "install_uv.sh"
        )
    if released:
        monkeypatch.setenv("CCF_USE_RELEASED_PYTHON_PACKAGE", "1")
    if local_override:
        monkeypatch.setenv("PYTHON_PACKAGE_PATH", "/local-sdk")
    if reused:
        venv = tmp_path / ".venv_ccf_sandbox" / "bin"
        venv.mkdir(parents=True)
        (venv / "activate").write_text(":\n")
    subprocess.run(
        ["bash", str(sandbox), "--help"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        timeout=10,
    )
    commands = shell_environment.read_text().splitlines()
    package_installs = [
        command
        for command in commands
        if command.startswith("uv pip install ") and " -r " not in command
    ]
    if released:
        expected = [RELEASE_INSTALL]
    elif reused:
        expected = []
    elif local_override:
        expected = ["uv pip install -q -e /local-sdk"]
    elif installed:
        expected = ["uv pip install -q ccf==7.0.19"]
    else:
        expected = [f"uv pip install -q -e {sandbox_dir}/../../python/"]
    assert package_installs == expected
    assert any(command.startswith("python ") for command in commands)


@pytest.mark.parametrize("released", [False, True])
def test_installed_package_test_selects_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shell_environment: Path,
    released: bool,
) -> None:
    install_bin = tmp_path / "install" / "bin"
    install_bin.mkdir(parents=True)
    shutil.copyfile(
        tmp_path / "scripts" / "install_uv.sh", install_bin / "install_uv.sh"
    )
    sandbox = install_bin / "sandbox.sh"
    sandbox.write_text(
        "#!/bin/bash\nset -euo pipefail\n"
        "mkdir -p workspace/sandbox_0/0.ledger workspace/sandbox_common\n"
    )
    sandbox.chmod(0o755)
    build = tmp_path / "build"
    build.mkdir()
    if released:
        monkeypatch.setenv("CCF_USE_RELEASED_PYTHON_PACKAGE", "1")
    subprocess.run(
        ["bash", str(REPO_ROOT / "tests" / "test_install.sh"), str(install_bin.parent)],
        cwd=build,
        check=True,
        capture_output=True,
        timeout=10,
    )
    commands = shell_environment.read_text().splitlines()
    expected = (
        "uv pip install --upgrade --reinstall-package ccf ccf"
        if released
        else "uv pip install -e ../../../python"
    )
    assert expected in commands
