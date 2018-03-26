#!/bin/sh

CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "-s" -a -installsuffix cgo -o build/jwt-secrets-plugin
shasum -a 256 -p build/jwt-secrets-plugin | cut -d ' ' -f 1 > "build/jwt-secrets-plugin.sha"