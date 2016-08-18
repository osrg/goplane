#!/bin/bash

echo "execute scenario test:" $TEST

echo "build docker image"

docker build -t osrg/goplane .

echo "install python dependencies"

sudo -H pip --quiet install -r test/pip-requires.txt

sudo python $TEST

exit $?
