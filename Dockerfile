# goplane (part of Ryu SDN Framework)
#

FROM osrg/gobgp

MAINTAINER ISHIDA Wataru <ishida.wataru@lab.ntt.co.jp>

ENV GO15VENDOREXPERIMENT 1
RUN curl https://glide.sh/get | sh
ADD . $GOPATH/src/github.com/osrg/goplane/
RUN cd $GOPATH/src/github.com/osrg/goplane && glide install
RUn go install github.com/osrg/goplane
