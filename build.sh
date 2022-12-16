#! /bin/sh
buildah bud --volume $(pwd)/gen:/gen:z,U -t sandbox-auth .