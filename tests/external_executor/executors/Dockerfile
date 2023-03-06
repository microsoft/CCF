# Dockerfile used to generate images for Python-based CCF external executors

# Build
FROM mcr.microsoft.com/cbl-mariner/base/python:3 as builder

ARG ccf_dir="ccf"
ARG attestation_container_dir="attestation_container"
COPY "$ccf_dir"/protobuf/ protobuf/
COPY "$attestation_container_dir"/proto/ proto/

RUN pip install "grpcio-tools==1.44.0" \
    && mkdir -p generated \
    && python3 -m grpc_tools.protoc \
        -I protobuf/ \
        --python_out generated/ \
        --grpc_python_out generated/ \
        $(find protobuf/ -iname "*.proto")

# Run
FROM mcr.microsoft.com/cbl-mariner/base/python:3

ARG ccf_dir="ccf"
ARG app_dir="wiki_cacher"

WORKDIR /app

COPY --from=builder /generated .
COPY app.py .
COPY "$app_dir" "$app_dir"
COPY "$ccf_dir"/executors/ "$ccf_dir"/executors/

RUN pip install --upgrade pip && pip3 install -r "$app_dir"/requirements.txt

CMD ["python3", "app.py"] 