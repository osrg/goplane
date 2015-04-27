package main

import (
	"fmt"
	"os"
	"github.com/jessevdk/go-flags"
	"github.com/osrg/gobgp/api"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"time"
)

var globalOpts struct {
	Host     string `short:"u" long:"url" description:"specifying an url" default:"127.0.0.1"`
	Port     int    `short:"p" long:"port" description:"specifying a port" default:"8080"`
	Mac      string `short:"m" long:"mac" description:"specifying a mac address to advertise"`
	IP      string `short:"i" long:"ip" description:"specifying an IP address to advertise"`
}

var client api.GrpcClient

func main(){
	parser := flags.NewParser(&globalOpts, flags.Default)
	parser.Parse()


	if globalOpts.Mac == "" {
		fmt.Println("specify a mac address to advertise with -m or --mac")
		os.Exit(1)
	}

	if globalOpts.IP == "" {
		fmt.Println("specify an IP address to advertise with -i or --ip")
		os.Exit(1)
	}

	timeout := grpc.WithTimeout(time.Second)
	conn, _ := grpc.Dial(fmt.Sprintf("%s:%d", globalOpts.Host, globalOpts.Port), timeout)
	client = api.NewGrpcClient(conn)

	// advertise the mac and IP given with from the command line
	addedMac := os.Args[1]
	addedIp := os.Args[2]
	
	var rt *api.AddressFamily
	rt = api.AF_EVPN
	
	path := &api.Path{}
	path.Nlri = &api.Nlri{
		Af: rt,
		EvpnNlri: &api.EVPNNlri{
			Type: api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT,
			MacIpAdv: &api.EvpnMacIpAdvertisement{
				MacAddr: addedMac,
				IpAddr:  addedIp,
			},
		},
	}

	path.IsWithdraw = false

	arg := &api.ModPathArguments{
		Resource: api.Resource_GLOBAL,
		Path:     path,
	}

	stream, _ := client.ModPath(context.Background())
	_ = stream.Send(arg)
	stream.CloseSend()

	_, _ = stream.Recv()
}
