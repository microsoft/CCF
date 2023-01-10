# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import os
import shutil
import stat
import subprocess
import tarfile

TLA_DIR = os.path.dirname(os.path.realpath(__file__))
HOME_DIR = os.path.expanduser('~')


def append_bashrc(line: str):

    bashrc_path = f"{HOME_DIR}/.bashrc"
    with open(bashrc_path, "r+", encoding="utf-8") as bashrc_file:
        bashrc_lines = bashrc_file.readlines()
        if line not in bashrc_lines:
            if not bashrc_lines[-1].endswith("\n"):
                bashrc_file.write("\n")
            bashrc_file.writelines(line)


def set_alias(key: str, value: str):

    append_bashrc(f"alias {key}='{value}'\n")


def fetch_latest(url: str, dest: str = "."):

    subprocess.Popen(f"wget -N {url} -P /tmp".split()).wait()
    file_name = url.split("/")[-1]
    file_path = f"/tmp/{file_name}"
    assert os.path.exists(file_path)
    bin_path = None

    if file_name.endswith(".bin"):
        os.chmod(file_path, os.stat(file_path).st_mode | stat.S_IEXEC)
        subprocess.Popen(f"{file_path} -d {dest}".split()).wait()
        bin_path = f"{dest}/bin"

    elif file_name.endswith(".tgz"):
        with tarfile.open(f"/tmp/{file_name}") as tar:
            tar.extractall(dest)
            rel_bin_path = next(
                member.name for member in tar.getmembers() if "bin" in member.name)
            bin_path = os.path.join(dest, rel_bin_path)

    elif file_name.endswith(".jar"):
        shutil.copyfile(file_path, os.path.join(dest, file_name))

    if bin_path is not None:
        append_bashrc(f"export PATH:$PATH:{bin_path}")


def _parse_args() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        description="Install CCF TLA+ dependencies",
    )

    parser.add_argument(
        "--tlaps",
        action="store_true",
        default=False,
    )

    parser.add_argument(
        "--apalache",
        action="store_true",
        default=False,
    )

    parser.add_argument(
        "--skip-apt-packages",
        action="store_false",
        default=True,
        dest="apt_packages"
    )

    return parser.parse_args()


def install_tlc():

    java = "java -XX:+UseParallelGC"
    tlaplus_path = "~/.vscode-remote/extensions/alygin.vscode-tlaplus-nightly-*/tools/tla2tools.jar"
    tlcmax_args = "-Dtlc2.tool.fp.FPSet.impl=tlc2.tool.fp.OffHeapDiskFPSet -Dtlc2.tool.ModelChecker.BAQueue=true"
    copy_tlaplus = f"-cp {tlaplus_path} tlc2.TLC"

    def get_run_tlc_max(size: int) -> str:
        return f"{java} -XX:MaxDirectMemorySize={size}g {tlcmax_args} {copy_tlaplus}"

    set_alias("tlcrepl", f"{java} -cp {tlaplus_path} tlc2.REPL")
    set_alias("tlc", f"{java} {copy_tlaplus}")
    set_alias("tlcmax4", get_run_tlc_max(4))
    set_alias("tlcmax8", get_run_tlc_max(8))
    set_alias("tlcmax16", get_run_tlc_max(16))
    set_alias("tlcmax32", get_run_tlc_max(32))


def install_deps(args: argparse.Namespace):

    # Setup tools directory
    tools_dir = os.path.join(TLA_DIR, "tools")
    def create_tools_dir():
        if not os.path.exists(tools_dir):
            os.mkdir(tools_dir)

    install_tlc()

    if args.tlaps:
        create_tools_dir()
        fetch_latest(
            url="https://github.com/tlaplus/tlapm/releases/download/v1.4.5/tlaps-1.4.5-x86_64-linux-gnu-inst.bin",
            dest=os.path.join(tools_dir, "tlaps"),
        )

    if args.apalache:
        create_tools_dir()
        fetch_latest(
            url="https://github.com/informalsystems/apalache/releases/latest/download/apalache.tgz",
            dest=tools_dir,
        )

    if args.apt_packages:
        subprocess.Popen(
            "sudo apt-get install -y --no-install-recommends".split() + [
                "wget",
                "graphviz",
                "htop",
                "texlive-latex-recommended",
            ]
        ).wait()

    fetch_latest(
        url="https://nightly.tlapl.us/dist/tla2tools.jar",
        dest=TLA_DIR,
    )

    fetch_latest(
        url="https://github.com/tlaplus/CommunityModules/releases/latest/download/CommunityModules-deps.jar",
        dest=TLA_DIR,
    )


if __name__ == "__main__":
    install_deps(_parse_args())
