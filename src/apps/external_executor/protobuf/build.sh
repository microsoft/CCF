THIS_DIR=$( dirname "${BASH_SOURCE[0]}" )

if [ ! -f "env/bin/activate" ]
    then
        python3.8 -m venv env
fi

source env/bin/activate
pip install -U -r "${THIS_DIR}/requirements.txt"

GENERATED_DIR="${THIS_DIR}/generated"
mkdir -p "${GENERATED_DIR}"

build_proto() {
    echo " -- Building $1"

    python -m grpc_tools.protoc \
        -I "${THIS_DIR}" \
        --python_out "${GENERATED_DIR}" \
        --grpc_python_out "${GENERATED_DIR}" \
        "$1"
}

build_proto "${THIS_DIR}/executor_registration.proto"
build_proto "${THIS_DIR}/kv.proto"
