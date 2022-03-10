#!/bin/bash

# Copyright 2016 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

DEFAULT_VERSION=$(git describe --match 'v[0-9]*' --dirty='.m' --always)
DEFAULT_REVISION=$(git rev-parse HEAD)$(if ! git diff --no-ext-diff --quiet --exit-code; then echo .m; fi)
DEFAULT_ARCH=amd64
DEFAULT_PROTODIR=proto
DEFAULT_APPNAME=diffie-hellman-service

: "${OS:=linux}"
: "${ARCH:=${DEFAULT_ARCH}}"
: "${VERSION:=${DEFAULT_VERSION}}"
: "${REVISION:=${DEFAULT_REVISION}}"
: "${PROTODIR:=${DEFAULT_PROTODIR}}"
: "${APPNAME:=${DEFAULT_APPNAME}}"

export CGO_ENABLED=0
export GOARCH="${ARCH}"
export GOOS="${OS}"
export GO111MODULE=on
export GOFLAGS="-mod=vendor"

# Append the location of the Go protocol compiler plugins to the PATH so that protoc can find them
PATH=$PATH:/goprotogen/bin

# Generate the Go code from protocol buffer definitions
protoc --go_out=. ${PROTODIR}/${APPNAME}.proto
protoc --go-grpc_out=. ${PROTODIR}/${APPNAME}.proto

# Install the application
go install \
    -installsuffix "static" \
    -ldflags "-X $(go list -m)/pkg/version.Version=${VERSION} -X $(go list -m)/pkg/version.Revision=${REVISION}"  \
    ./...

# Copy the binary to the current directory (accounting for cross compilation)
APPSOURCE=${GOPATH}/bin
APPDESTINATION=$(pwd)/bin
if [ "$ARCH" != "$DEFAULT_ARCH" ]; then
  APPSOURCE=${GOPATH}/bin/${OS}_${ARCH}
  APPDESTINATION=${APPDESTINATION}/${OS}_${ARCH}
fi
cp ${APPSOURCE}/${APPNAME} ${APPDESTINATION}
