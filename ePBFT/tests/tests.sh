#!/bin/bash

if [ ! -f "env/bin/activate" ]
    then
        python3.7 -m venv env
fi

source env/bin/activate
pip install -q -U -r ../tests/requirements.txt

"$@"
