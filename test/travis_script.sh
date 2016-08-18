#!/bin/bash

if [ $# -eq 0 ]; then
    echo "execute unit test"
    go version
    go build
    exit $?
fi

echo "execute scenario test:" $1

echo "build docker image"

docker build -t osrg/goplane .

echo "install python dependencies"

sudo -H pip --quiet install -r test/pip-requires.txt

sudo python $1
exit $?
