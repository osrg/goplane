package main

// READ BEFORE MAKING THIS FILE OPEN-SOURCED
//
// This file is created by picking up and modifying
// methods we need from socketplane/daemon/{bridge,utils,ovs_driver}.go.
//
// License(s) of the original files must be carefully considered
// before we make this file open-sourced.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
	"strings"
	
	log "github.com/Sirupsen/logrus"
	"github.com/socketplane/libovsdb"
	"github.com/vishvananda/netns"
	"github.com/vishvananda/netlink"
	"github.com/jessevdk/go-flags"
)

// Setting a mtu value to 1440 temporarily to resolve #71
const mtu = 1440
const defaultBridgeName = "docker0-ovs"

type Bridge struct {
	Name string
	//	IP     net.IP
	//	Subnet *net.IPNet
}

var OvsBridge Bridge = Bridge{Name: defaultBridgeName}

var ovs *libovsdb.OvsdbClient
var ContextCache map[string]string

type OvsConnection struct {
	Name    string `json:"name"`
	Ip      string `json:"ip"`
	Subnet  string `json:"subnet"`
	Mac     string `json:"mac"`
	Gateway string `json:"gateway"`
}

type Notifier struct {
}

func ovs_connect() (*libovsdb.OvsdbClient, error) {
	// By default libovsdb connects to 127.0.0.0:6400.
	var ovs *libovsdb.OvsdbClient
	var err error
	for {
		ovs, err = libovsdb.Connect("", 0)
		if err != nil {
			log.Errorf("Error(%s) connecting to OVS. Retrying...", err.Error())
			time.Sleep(time.Second * 2)
			continue
		}
		break
	}

	time.Sleep(time.Second * 1)
	
	return ovs, nil
}

func OvsInit() {
	var err error
	ovs, err = ovs_connect()
	if err != nil {
		log.Error("Error connecting OVS ", err)
	} else {
//		ovs.Register(notifier{})
	}
}

func SetInterfaceMac(name string, macaddr string) error {
	iface, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	hwaddr, err := net.ParseMAC(macaddr)
	if err != nil {
		return err
	}
	return netlink.LinkSetHardwareAddr(iface, hwaddr)
}

func SetInterfaceIp(name string, rawIp string) error {
	iface, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	ipNet, err := netlink.ParseIPNet(rawIp)
	if err != nil {
		return err
	}
	addr := &netlink.Addr{ipNet, ""}
	return netlink.AddrAdd(iface, addr)
}

func SetMtu(name string, mtu int) error {
	iface, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(iface, mtu)
}

func InterfaceUp(name string) error {
	iface, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(iface)
}

func InterfaceDown(name string) error {
	iface, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetDown(iface)
}

func ChangeInterfaceName(old, newName string) error {
	iface, err := netlink.LinkByName(old)
	if err != nil {
		return err
	}
	return netlink.LinkSetName(iface, newName)
}

func SetInterfaceInNamespaceFd(name string, fd uintptr) error {
	iface, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetNsFd(iface, int(fd))
}

func AddInternalPort(ovs *libovsdb.OvsdbClient, bridgeName string, portName string, tag uint) error {
	namedPortUuid := "port"
	namedIntfUuid := "intf"

	// intf row to insert
	intf := make(map[string]interface{})
	intf["name"] = portName
	intf["type"] = `internal`

	insertIntfOp := libovsdb.Operation{
		Op:       "insert",
		Table:    "Interface",
		Row:      intf,
		UUIDName: namedIntfUuid,
	}

	// port row to insert
	port := make(map[string]interface{})
	port["name"] = portName
	port["interfaces"] = libovsdb.UUID{namedIntfUuid}

	if tag != 0 {
		port["tag"] = tag
	}

	insertPortOp := libovsdb.Operation{
		Op:       "insert",
		Table:    "Port",
		Row:      port,
		UUIDName: namedPortUuid,
	}

	// Inserting a row in Port table requires mutating the bridge table.
	mutateUuid := []libovsdb.UUID{libovsdb.UUID{namedPortUuid}}
	mutateSet, _ := libovsdb.NewOvsSet(mutateUuid)
	mutation := libovsdb.NewMutation("ports", "insert", mutateSet)
	condition := libovsdb.NewCondition("name", "==", bridgeName)

	// simple mutate operation
	mutateOp := libovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []interface{}{mutation},
		Where:     []interface{}{condition},
	}

	operations := []libovsdb.Operation{insertIntfOp, insertPortOp, mutateOp}
	reply, _ := ovs.Transact("Open_vSwitch", operations...)
	if len(reply) < len(operations) {
		log.Error("Number of Replies should be atleast equal to number of Operations")
		return errors.New("Number of Replies should be atleast equal to number of Operations")
	}
	for i, o := range reply {
		if o.Error != "" && i < len(operations) {
			msg := fmt.Sprintf("Transaction Failed due to an error : %v details: %v in %v", o.Error, o.Details, operations[i])
			return errors.New(msg)
		} else if o.Error != "" {
			msg := fmt.Sprintf("Transaction Failed due to an error : %v", o.Error)
			return errors.New(msg)
		}
	}
	return nil
}

func AddConnection(nspid int, ip net.IP, subnetPrefix string, vlan uint) (err error) {
	var (
		bridge = OvsBridge.Name
		prefix = "ovs"
	)
	err = nil

	if bridge == "" {
		err = fmt.Errorf("bridge is not available")
		return
	}

	portName, err := createOvsInternalPort(prefix, bridge, vlan)
	if err != nil {
		return
	}
	// Add a dummy sleep to make sure the interface is seen by the subsequent calls.
	time.Sleep(time.Second * 1)

	if err = SetMtu(portName, mtu); err != nil {
		return
	}
	if err = InterfaceUp(portName); err != nil {
		return
	}

//	if err = os.Symlink(filepath.Join(os.Getenv("PROCFS"), strconv.Itoa(nspid), "ns/net"),
	if err = os.Symlink(filepath.Join("/proc", strconv.Itoa(nspid), "ns/net"),
		filepath.Join("/var/run/netns", strconv.Itoa(nspid))); err != nil {
		return
	}

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, err := netns.Get()
	if err != nil {
		return
	}
	defer origns.Close()

	targetns, err := netns.GetFromName(strconv.Itoa(nspid))
	if err != nil {
		return
	}
	defer targetns.Close()

	if err = SetInterfaceInNamespaceFd(portName, uintptr(int(targetns))); err != nil {
		return
	}

	if err = netns.Set(targetns); err != nil {
		return
	}
	defer netns.Set(origns)

	if err = InterfaceDown(portName); err != nil {
		return
	}

	/* TODO : Find a way to change the interface name to defaultDevice (eth0).
	   Currently using the Randomly created OVS port as is.
	   refer to veth.go where one end of the veth pair is renamed to eth0
	*/
	if err = ChangeInterfaceName(portName, portName); err != nil {
		return
	}

	if err = SetInterfaceIp(portName, ip.String()+subnetPrefix); err != nil {
		return
	}

	if err = SetInterfaceMac(portName, generateMacAddr(ip).String()); err != nil {
		return
	}

	if err = InterfaceUp(portName); err != nil {
		return
	}

	return nil
}

// createOvsInternalPort will generate a random name for the
// the port and ensure that it has been created
func createOvsInternalPort(prefix string, bridge string, tag uint) (port string, err error) {
	if port, err = GenerateRandomName(prefix, 7); err != nil {
		return
	}

	if ovs == nil {
		err = errors.New("OVS not connected")
		return
	}

	AddInternalPort(ovs, bridge, port, tag)
	return
}

// GenerateRandomName returns a new name joined with a prefix.  This size
// specified is used to truncate the randomly generated value
func GenerateRandomName(prefix string, size int) (string, error) {
	id := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(id)[:size], nil
}

func generateMacAddr(ip net.IP) net.HardwareAddr {
	hw := make(net.HardwareAddr, 6)

	// The first byte of the MAC address has to comply with these rules:
	// 1. Unicast: Set the least-significant bit to 0.
	// 2. Address is locally administered: Set the second-least-significant bit (U/L) to 1.
	// 3. As "small" as possible: The veth address has to be "smaller" than the bridge address.
	hw[0] = 0x02

	// The first 24 bits of the MAC represent the Organizationally Unique Identifier (OUI).
	// Since this address is locally administered, we can do whatever we want as long as
	// it doesn't conflict with other addresses.
	hw[1] = 0x42

	// Insert the IP address into the last 32 bits of the MAC address.
	// This is a simple way to guarantee the address will be consistent and unique.
	copy(hw[2:], ip.To4())

	return hw
}

var globalOpts struct {
	Cid     string `short:"c" long:"container" description:"Container ID"`
	IP      string `short:"i" long:"ip" description:"IP address to assign"`
	Mask    string `short:"m" long:"mask" description:"Net mask"`
	VNI     uint   `short:"v" long:"vni" description:"VNI (VLAN ID) to assign"`
}

func main() {
	parser := flags.NewParser(&globalOpts, flags.Default)
	parser.Parse()

	var (
		cid  string
		ip   string
		mask string
		vni  uint
		pid  int
	)
	
	if globalOpts.Cid == "" {
		fmt.Println("specify the ID of the target container with -c or --container")
		os.Exit(1)
	} else {
		cid = globalOpts.Cid
	}

	if globalOpts.IP == "" {
		fmt.Println("specify the IP address to assign with -i or --ip")
		os.Exit(1)
	} else {
		ip = globalOpts.IP
	}

	if globalOpts.VNI == 0 {
		fmt.Println("VNI to assign (-v, --vni) not specified, set to default value 1")
		vni = 1
	} else {
		vni = globalOpts.VNI
	}
	
	if globalOpts.Mask == "" {
		fmt.Println("Net mask to use (-m, --mask) not specified, set to default value \"/24\"")
		mask = "/24"
	} else {
		mask = globalOpts.Mask
	}

	command := fmt.Sprintf("docker inspect --format {{.State.Pid}} %s", cid)
	fmt.Println(command)

	out, err := exec.Command("sh", "-c", command).Output()
	fmt.Println(string(out))
	pid, err = strconv.Atoi(strings.Trim(string(out), "\n"))

	fmt.Printf("pid: %d\n", pid)
	
	OvsInit()
	
	err = AddConnection(pid, net.ParseIP(ip), mask, vni)

	if err != nil {
		fmt.Println(err)
	}
}
