package main

import (
	"fmt"
	"github.com/jessevdk/go-flags"
	api "github.com/osrg/gobgp/api"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"os"
	"strconv"
	"time"
)

var globalOpts struct {
	Host string `short:"u" long:"url" description:"specifying an url" default:"127.0.0.1"`
	Port int    `short:"p" long:"port" description:"specifying a port" default:"8080"`
	Mac  string `short:"m" long:"mac" description:"specifying a mac address to advertise"`
	IP   string `short:"i" long:"ip" description:"specifying an IP address to advertise"`
	VNI  string `short:"v" long:"vni" description:"specifying a VNI (or VLAN ID) to that the MAC belongs"`
}

var client api.GobgpApiClient

func main() {
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

	if globalOpts.VNI == "" {
		fmt.Println("specify a VNI that the MAC belongs with -v or --vni")
		os.Exit(1)
	}

	timeout := grpc.WithTimeout(time.Second)
	conn, _ := grpc.Dial(fmt.Sprintf("%s:%d", globalOpts.Host, globalOpts.Port), timeout)
	client = api.NewGobgpApiClient(conn)

	// advertise the mac and IP given with from the command line
	addedMac := globalOpts.Mac
	addedIp := globalOpts.IP
	vni, _ := strconv.Atoi(globalOpts.VNI)

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
				Labels:  []uint32{uint32(vni)},
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
