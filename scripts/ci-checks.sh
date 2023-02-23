#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

if [ "$1" == "-f" ]; then
  FIX=1
else
  FIX=0
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

ROOT_DIR=$( dirname "$SCRIPT_DIR" )
pushd "$ROOT_DIR" > /dev/null

# GitHub actions workflow commands: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
function group(){
    # Only do this in GitHub actions, where CI is defined according to
    # https://docs.github.com/en/actions/learn-github-actions/environment-variables#default-environment-variables
    if [[ ${CI} ]]; then
      echo "::group::$1"
    fi
}
function endgroup() {
    if [[ ${CI} ]]; then
      echo "::endgroup::"
    fi
}


group "Shell scripts"
git ls-files | grep -e '\.sh$' | grep -E -v "^3rdparty" | xargs shellcheck -s bash -e SC2044,SC2002,SC1091,SC2181
endgroup

group "TODOs"
"$SCRIPT_DIR"/check-todo.sh include src
endgroup

group "Public includes"
# Enforce that no private headers are included from public header files
violations=$(find "$ROOT_DIR/include/ccf" -type f -print0 | xargs --null grep -e "#include \"" | grep -v "#include \"ccf" | sort)
if [[ -n "$violations" ]]; then
  echo "Public headers include private implementation files:"
  echo "$violations"
  exit 1
else
  echo "No public header violations"
fi
endgroup

group "Release notes"
if [ $FIX -ne 0 ]; then
  python3 "$SCRIPT_DIR"/extract-release-notes.py -f
else
  python3 "$SCRIPT_DIR"/extract-release-notes.py
fi
endgroup

group "C/C++/Proto format"
if [ $FIX -ne 0 ]; then
  "$SCRIPT_DIR"/check-format.sh -f include src samples
else
  "$SCRIPT_DIR"/check-format.sh include src samples
fi
endgroup

group "TypeScript, JavaScript, Markdown, YAML and JSON format"
npm install --loglevel=error --no-save prettier 1>/dev/null
if [ $FIX -ne 0 ]; then
  git ls-files | grep -e '\.ts$' -e '\.js$' -e '\.md$' -e '\.yaml$' -e '\.yml$' -e '\.json$' | xargs npx prettier --write
else
  git ls-files | grep -e '\.ts$' -e '\.js$' -e '\.md$' -e '\.yaml$' -e '\.yml$' -e '\.json$' | xargs npx prettier --check
fi
endgroup

group "OpenAPI"
npm install --loglevel=error --no-save @apidevtools/swagger-cli 1>/dev/null
find doc/schemas/*.json -exec npx swagger-cli validate {} \;
endgroup

group "Copyright notice headers"
python3.8 "$SCRIPT_DIR"/notice-check.py
endgroup

group "CMake format"
if [ $FIX -ne 0 ]; then
  "$SCRIPT_DIR"/check-cmake-format.sh -f cmake samples src tests CMakeLists.txt
else
  "$SCRIPT_DIR"/check-cmake-format.sh cmake samples src tests CMakeLists.txt
fi
endgroup

group "Python dependencies"
# Virtual Environment w/ dependencies for Python steps
if [ ! -f "scripts/env/bin/activate" ]
    then
        python3.8 -m venv scripts/env
fi

source scripts/env/bin/activate
pip install -U pip
pip install -U wheel black pylint mypy 1>/dev/null
endgroup

group "Python format"
if [ $FIX -ne 0 ]; then
  git ls-files tests/ python/ scripts/ .cmake-format.py | grep -e '\.py$' | xargs black
else
  git ls-files tests/ python/ scripts/ .cmake-format.py | grep -e '\.py$' | xargs black --check
fi
endgroup

group "Python lint dependencies"
# Install test dependencies before linting
pip install -U -r tests/requirements.txt 1>/dev/null
pip install -U -r python/requirements.txt 1>/dev/null
endgroup

group "Python lint"
PYTHONPATH=./tests git ls-files tests/ python/ | grep -e '\.py$' | xargs python -m pylint --ignored-modules "*_pb2"
endgroup

group "Python types"
git ls-files python/ | grep -e '\.py$' | xargs mypy
endgroup

group "Go dependencies"
GO_VERSION="1.20"
if command -v go &> /dev/null
then
  # go is found
  if ! go version | grep go$GO_VERSION &> /dev/null
  then
    echo "Wrong version of go is installed. Please make sure version $GO_VERSION.x is installed."
    echo -n "Current install version: "
    go version
    exit 1
  fi
else
	# go is not found
  # Install the latest bugfix version of GO_VERSION
  # https://github.com/golang/go/issues/36898 
  install_version=$(curl -sL 'https://go.dev/dl/?mode=json&include=all' | jq -r '.[].version' | grep -m 1 go$GO_VERSION) 
  tar_filename=$install_version.linux-amd64.tar.gz
  curl -sLO "https://go.dev/dl/$tar_filename"
  function clean_up_tar {
      rm "$tar_filename"
  }
  trap clean_up_tar EXIT
  tar -C /usr/local -xzf "$tar_filename"
  # shellcheck disable=SC2016,SC1090
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
fi

group "Go format"
if [ $FIX -ne 0 ]; then
  git ls-files attestation-container/ | grep -e '\.go$' | xargs gofmt -w
else
  GOFMT_RES=$(git ls-files attestation-container/ | grep -e '\.go$' | xargs gofmt -d)
  if [ "$GOFMT_RES" != "" ];
  then
      echo "Format of go codes is broken"
      echo "$GOFMT_RES"
  fi
fi
