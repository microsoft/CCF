#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

git_tag=$(git describe --tags --abbrev=0)
git_tag=${git_tag#v}
cmake_version=$(grep CCF_VERSION CMakeLists.txt | grep -Po "(\d)+(\.(\d)+)*")
# Check git tag is <= CMake version. Use sort --version-sort to handle semver (0.9 < 0.10)
if echo "$git_tag $cmake_version" | tr " " "\n" | sort --version-sort -c ; then
  echo "Git tag ($git_tag) is safely <= CMake version ($cmake_version)"
else
  echo "Git tag ($git_tag) is later than CMake version ($cmake_version) - please update CMake version!"
  exit 1
fi