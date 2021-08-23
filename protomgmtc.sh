#! /usr/bin/env bash

# this is the mgmt project's root path 
MGMT_PATH=mgmt

find ${MGMT_PATH} -name "*.pb.go" -delete

protoc \
    --proto_path="${MGMT_PATH}" \
	--go_out=plugins=grpc:${GOPATH}/src \
        ${MGMT_PATH}/mgmt.proto
