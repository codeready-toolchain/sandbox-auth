#! /bin/sh
podman build --volume $(pwd)/gen:/gen:z,U -t sandbox-auth .