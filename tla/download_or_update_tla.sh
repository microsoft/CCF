#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# Original License below
# Adapted from: https://github.com/pmer/tla-bin
#
# Downloads the TLA+ binary image (tla2tools.jar).
# If the file already exists locally, checks for an update & prints a
# message if one was found.
# Also downloads the TLA+ community modules (CommunityModules-deps.jar).
#

download() {
	if type curl > /dev/null 2>&1; then
		download_curl "$1"
	else
		echo "Couldn't find curl" >&2
	fi
}

download_curl() {
	local if_modified

	IFS='/' read -ra PATHPARTS <<< $"1"
	JARNAME=${PATHPARTS[-1]}

	if [ -e $"JARNAME" ]; then
		if_modified=(-z $"JARNAME")
	fi

	curl -f -Ss -L -R -O "${if_modified[@]}" "$1"

	if [ $? -ne 0 ]; then
		echo "Couldn't download $JARNAME"
		exit 1
	fi
}

print_version() {
	"$1" tlc2.TLC | grep Version | cut -d' ' -f3
}

main() {
	echo "Downloading tla2tools.jar (nightly release)..."
	before=$(date -r tla2tools.jar 2>/dev/null)
	download https://nightly.tlapl.us/dist/tla2tools.jar
	after=$(date -r tla2tools.jar 2>/dev/null)

	if [ ! -e tla2tools.jar ]; then
		echo "Couldn't download tla2tools.jar" >&2
		exit 1
	fi

	if [ "$before" != "$after" ]; then
		if [ -n "$before" ]; then
			echo "Updated tla2tools.jar"
			printf "New version: "
			print_version tla2tools.jar
		else
			echo "Created tla2tools.jar"
		fi
	else
		echo "No updates"
	fi

	echo "Downloading CommunityModules-deps.jar..."
	download https://github.com/tlaplus/CommunityModules/releases/latest/download/CommunityModules-deps.jar
}

main


# Original License
# Copyright 2017 Paul Merrill

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.