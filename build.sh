#!/bin/sh

CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "-s" -a -installsuffix cgo -o build/jose-plugin
shasum -a 256 build/jose-plugin | cut -d ' ' -f 1 > "build/jose-plugin.sha"