#! /usr/bin/env bash

# this path has to contain protobuf's well-known types 
WELL_KNOWN_TYPES="thirdparty"
# this is the mgmt project's root path 
MGMT_PATH=mgmt

find ${MGMT_PATH} -name "*.pb.go" -delete

protoc \
    --proto_path="${WELL_KNOWN_TYPES}" \
    --proto_path="${MGMT_PATH}" \
	--go_out=plugins=grpc:${GOPATH}/src \
        ${MGMT_PATH}/mgmt.proto
