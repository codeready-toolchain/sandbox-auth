#! /bin/sh
$GOPATH/bin/goa gen github.com/codeready-toolchain/sandbox-auth/design
podman build -t sandbox-auth .