# goplane (part of Ryu SDN Framework)
#

FROM osrg/gobgp

MAINTAINER ISHIDA Wataru <ishida.wataru@lab.ntt.co.jp>

ADD . /go/src/github.com/osrg/goplane/
RUN go install -a github.com/osrg/gobgp/gobgp
RUN go get -v github.com/osrg/goplane
RUN go install github.com/osrg/goplane
