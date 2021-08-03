#!/bin/sh

python -m grpc_tools.protoc -I ./src/proto/ --python_out=./src/proto/ --grpc_python_out=./src/proto/ ./src/proto/*.proto