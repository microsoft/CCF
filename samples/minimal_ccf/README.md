# Minimal CCF Runtime Image

This repository provides scripts and Dockerfiles to build a minimal CCF runtime image and a sample application image based on it.

## Structure

- **ccf_runtime/**: Contains a Dockerfile to build a minimal CCF runtime image with only the required dependencies.
- **myapp/**: Contains a Dockerfile to build a sample application image using the `ccf_runtime` image as its base.
- **use_minimal_ccf.sh**: Script to build sample application image in a container.
- **run_app.sh**: Script to run the sample application in a container.

## Usage

Run `use_minimal_ccf.sh` to build the images and start the sample application.
