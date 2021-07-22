#!/bin/bash
# Original creator: https://github.com/pmer/tla-bin
#
# Downloads the TLA+ binary image (tla2tools.jar) from the Microsoft Research
# servers. If the file already exists locally, checks for an update & prints a
# message if one was found.
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

	if [ -e tla2tools.jar ]; then 
		if_modified=(-z tla2tools.jar)
	fi

	curl -f -Ss -R -O "${if_modified[@]}" "$1"

	if [ $? -ne 0 ]; then
		echo "Couldn't download tla2tools.jar"
		exit 1
	fi
}

print_version() {
	"$1" tlc2.TLC | grep Version | cut -d' ' -f3
}

main() {
	echo "Downloading tla2tools.jar..."
	before=$(date -r tla2tools.jar 2>/dev/null)
	download https://tla.msr-inria.inria.fr/tlatoolbox/dist/tla2tools.jar
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
}

main