# goplane (part of Ryu SDN Framework)
#

FROM osrg/gobgp

MAINTAINER ISHIDA Wataru <ishida.wataru@lab.ntt.co.jp>

RUN cd /go/src/github.com/osrg/gobgp; git pull origin evpn:evpn; git checkout evpn
COPY goplane /go/src/github.com/hogecamp/goplane/
RUN go get -v github.com/hogecamp/goplane/goplaned
RUN go install github.com/hogecamp/goplane/goplaned
RUN go install github.com/osrg/gobgp/gobgp
