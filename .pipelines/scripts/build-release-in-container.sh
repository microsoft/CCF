#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail
set -x

case "${BUILD_SOURCEBRANCH:-}" in
    refs/tags/ccf-*)
        release_tag=${BUILD_SOURCEBRANCH#refs/tags/}
        ;;
    *)
        echo "Release artifacts must be built from a ccf-* tag" >&2
        exit 1
        ;;
esac

output_dir=${BUILD_SOURCESDIRECTORY:-$PWD}/out
mkdir -p "$output_dir"/{rpm,wheel,npm,sbom,reports,samples}

gpg --import /etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY
tdnf --snapshottime="$SOURCE_DATE_EPOCH" -y update
./scripts/setup-ci.sh

# rpmbuild only clamps file times that are later than SOURCE_DATE_EPOCH.
find . -type f -exec touch {} +

cmake -S . -B build -GNinja \
    -DCLIENT_PROTOCOLS_TEST=ON \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build --verbose

(
    cd build
    ./tests.sh --output-on-failure -L unit -j"$(nproc --all)"
    ./tests.sh --timeout 600 --output-on-failure -L suite
    ./tests.sh --timeout 360 --output-on-failure -LE "suite|benchmark|unit"
)

rm -f build/CMakeCache.txt
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release
(
    cd build
    cmake -L .. 2>/dev/null |
        awk -F= '/^CMAKE_INSTALL_PREFIX:/{print $2}' > /tmp/install_prefix
)
(
    cd build
    cpack -V -G RPM
)

initial_package=$(find build -maxdepth 1 -type f -name '*devel*.rpm' -print -quit)
if [[ -z "$initial_package" ]]; then
    echo "No CCF development RPM was produced" >&2
    exit 1
fi
package_name=$(basename "$initial_package")
github_package_name=${package_name//\~/_}
cp "$initial_package" "$output_dir/rpm/$github_package_name"

tdnf -y install "$initial_package"
install_prefix=$(</tmp/install_prefix)
(
    cd build
    PYTHON_PACKAGE_PATH=../python ./test_install.sh "$install_prefix"
    PYTHON_PACKAGE_PATH=../python ./recovery_benchmark.sh "$install_prefix"
)
./tests/test_install_build.sh
(
    cmake -S tests/ccfapp -B tests/ccfapp/build -GNinja \
        -DCMAKE_BUILD_TYPE=Release
    cmake --build tests/ccfapp/build
    tests/ccfapp/build/ccfapp > /tmp/ccfapp.out
    grep "I'm a CCF test app" /tmp/ccfapp.out
    grep "Exported headers are usable" /tmp/ccfapp.out
    /opt/ccf/bin/ensure-snmalloc.sh tests/ccfapp/build/ccfapp
)

(
    cd python
    uv build --wheel
)
mapfile -t wheels < <(
    find python/dist -maxdepth 1 -type f -name 'ccf-*.whl' -print
)
if [[ ${#wheels[@]} -ne 1 ]]; then
    echo "Expected exactly one CCF wheel" >&2
    exit 1
fi
cp "${wheels[0]}" "$output_dir/wheel/"

(
    cd js/ccf-app
    ccf_version=${release_tag#ccf-}
    npm version "$ccf_version"
    npm pack
)
mapfile -t npm_packages < <(
    find js/ccf-app -maxdepth 1 -type f -name '*.tgz' -print
)
if [[ ${#npm_packages[@]} -ne 1 ]]; then
    echo "Expected exactly one CCF NPM package" >&2
    exit 1
fi
cp "${npm_packages[0]}" "$output_dir/npm/"

./scripts/extract-release-notes.py --target-git-version \
    --describe-path-changes "./samples/constitution" > "$output_dir/release-notes.md"

curl -fsSL -o /tmp/sbom-tool \
    https://github.com/microsoft/sbom-tool/releases/latest/download/sbom-tool-linux-x64
chmod +x /tmp/sbom-tool
/tmp/sbom-tool generate \
    -b . \
    -bc . \
    -pn CCF \
    -ps Microsoft \
    -nsb https://sbom.microsoft \
    -pv "${release_tag#ccf-}" \
    -V Error
cp -a _manifest/spdx_2.2/. "$output_dir/sbom/"

for report in build/compatibility_report.json build/tls_report.html; do
    if [[ ! -f "$report" ]]; then
        echo "Missing release report $report" >&2
        exit 1
    fi
    cp "$report" "$output_dir/reports/"
done

for sample in \
    build_against_install/logging \
    build/verify_uvm_attestation_and_endorsements; do
    if [[ ! -e "$sample" ]]; then
        echo "Missing release sample $sample" >&2
        exit 1
    fi
    cp -a "$sample" "$output_dir/samples/"
done
