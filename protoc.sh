#! /usr/bin/env bash

# this path has to contain protobuf's well-known types 
WELL_KNOWN_TYPES="thirdparty"
# this is the stenosis project's root path 
STENOSIS_PATH=stenosis

find ${STENOSIS_PATH} -name "*.pb.go" -delete

protoc \
    --proto_path="${WELL_KNOWN_TYPES}" \
    --proto_path="${STENOSIS_PATH}" \
    --proto_path="${GOPATH}/src" \
    --go_out=:${GOPATH}/src \
        ${STENOSIS_PATH}/task/*.proto \
        ${STENOSIS_PATH}/api/hateoas.proto

protoc \
    --proto_path="${WELL_KNOWN_TYPES}" \
    --proto_path="${STENOSIS_PATH}" \
    --proto_path="${GOPATH}/src" \
    --go_out=plugins=grpc:${GOPATH}/src \
        ${STENOSIS_PATH}/api/stenosisservicequery.proto