#!/bin/bash

docker build \
    -t samp-crypto/build:ubuntu-18.04 ./ \
|| exit 1

docker run \
    --rm \
    -t \
    -w /code \
    -v $PWD/..:/code \
    samp-crypto/build:ubuntu-18.04