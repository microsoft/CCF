#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

git_tag=$(git describe --tags --abbrev=0)
git_tag=${git_tag#v}

# Check if git tag looks like a semver value - ignore if not
if [[ ${git_tag} =~ ^([[:digit:]])+(\.([[:digit:]])+)*(-.*)?$ ]]; then
  mkdir -p build
  pushd build
  cmake_version=$(cmake .. -L | grep "CCF version=")
  cmake_version=${cmake_version#*=}
  echo "Comparing git tag ($git_tag) with CMake version ($cmake_version)"
  if [[ "${git_tag}" == "${cmake_version}" ]]; then
    echo "Git tag ($git_tag) matches CMake version ($cmake_version)"
    exit 0
  else
    echo "Git tag ($git_tag) does not match CMake version ($cmake_version) - please update CMake version"
    exit 1
  fi
else
  echo "Skipping check - ${git_tag} doesn't look like semver"
  exit 0
fi