package main

import (
	"flag"
	"fmt"
	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/orandin/lumberjackrus"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	//"strings"
	"time"
)
var (
	device      string
	logfile		string
	promiscuous bool
	debug		bool
	tlvid		int
	err         error
	timeout    	int
	cachealive int

	handle      *pcap.Handle
)

const (
	cachepathformat string = "/tmp/%slldp.pcap"
)

func exit_timeout(sub int){
	t := time.NewTimer(time.Duration(sub) * time.Second)
	<-t.C
	fmt.Println("time out")
	os.Exit(1)
}

func getIfLinkstate(ifi *net.Interface) bool {
	if ifi.Flags & net.FlagUp == 0 {
		return false
	}
	if runtime.GOOS == "linux" {
		out, err := exec.Command("cat", fmt.Sprintf("/sys/class/net/%s/operstate", ifi.Name)).CombinedOutput()
		if err != nil {
			log.Debugf("poen operstate err. %v", err)
			return false
		}
		strOut := strings.Trim(string(out),"\r\n")
		log.Debugf("/sys/class/net/%s/operstate is %v.", ifi.Name,  strOut)
		if strOut == "down" {
			log.Debugf("interface %s down", ifi.Name)
			return false
		}
	} else {
		log.Debug("get if link status failed. unsupported os")
		return false
	}

	return true
}

func main() {
	flag.BoolVar(&debug, "d", false, "debug")
	flag.StringVar(&device, "i", "", "network interface	")
	flag.BoolVar(&promiscuous, "p", false, "interface into promiscuous mode")
	flag.IntVar(&tlvid, "V", 0, "TLV identifier")
	flag.IntVar(&timeout, "W", 60, "wait for  time out (s)")
	flag.IntVar(&cachealive, "a", 120, "cache alive time (s)")

	flag.Parse()
	if debug{
		log.SetLevel(log.DebugLevel)
	}
	if runtime.GOOS == "linux" {
		logfile = "/var/log/golldp.log"
	}

	initlog(logfile, debug)

	go exit_timeout(timeout)
	ifi, err := net.InterfaceByName(device)
	if err != nil {
		fmt.Printf("%v open interface failed\n", device)
		os.Exit(1)
	}
	log.Debugf("device info %v", *ifi)
	//log.Debugf("flag:%x\nIFF_LOWER_UP:%x\n", ifi.Flags , unix.IFF_LOWER_UP)
	//
	//log.Debugf("%x\n", ifi.Flags & unix.IFF_LOWER_UP)
	if getIfLinkstate(ifi) == false {
		fmt.Printf("%s is down\n", device)
		os.Exit(1)
	}

	if printPacketInfoFromCache(ifi, tlvid) {
		return
	}

	//start := time.Now()
	// Open device
	handle, err = pcap.OpenLive(device, int32(ifi.MTU), promiscuous, 5 * time.Second)
	if err != nil {
		log.Debugf("OpenLive oerr: %v", err)
		fmt.Printf("open live %v interface failed", device)
		os.Exit(1)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if res := printPacketInfo(ifi, packet, tlvid); res {
			return
		}

		//if time.Now().After(start.Add(time.Duration(timeout)* time.Second)) {
		//	fmt.Println("get lldp package timeout")
		//	os.Exit(1)
		//}
	}
}


func initlog(logFile string, debug bool) {
	log.SetFormatter(&nested.Formatter{
		HideKeys:    true,
		FieldsOrder: []string{"component", "category"},
		TimestampFormat: "2006-01-02 15:04:05",
	})

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	log.SetReportCaller(true)
	if logFile == ""{
		return
	}

	hook, err := lumberjackrus.NewHook(
		&lumberjackrus.LogFile{
			Filename:   logFile,
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     10,
			Compress:   true,
			LocalTime:  true,
		},
		log.DebugLevel,
		&nested.Formatter{
			NoColors: true,
			HideKeys:    true,
			FieldsOrder: []string{"component", "category"},
			TimestampFormat: "2006-01-02 15:04:05",
		},
		&lumberjackrus.LogFileOpts{
			//log.InfoLevel: &lumberjackrus.LogFile{
			//	Filename: "/tmp/info.log",
			//},
			//log.ErrorLevel: &lumberjackrus.LogFile{
			//	Filename:   "/tmp/error.log",
			//	MaxSize:    100,   // optional
			//	MaxBackups: 1,     // optional
			//	MaxAge:     1,     // optional
			//	Compress:   false, // optional
			//	LocalTime:  false, // optional
			//},
		},
	)

	if err != nil {
		panic(err)
	}

	log.AddHook(hook)
	log.SetOutput(os.Stdout)
}


func readLinkLayerDiscoverypacket(ifi *net.Interface, packet gopacket.Packet, tlvid int) bool {
	discoveryLayer := packet.Layer(layers.LayerTypeLinkLayerDiscovery)
	discoveryPacket, _ := discoveryLayer.(*layers.LinkLayerDiscovery)
	log.Debug(discoveryPacket)
	discoveryInfoLayer := packet.Layer(layers.LayerTypeLinkLayerDiscoveryInfo)
	discoveryInfoPacket, _ := discoveryInfoLayer.(*layers.LinkLayerDiscoveryInfo)
	log.Debug(discoveryInfoPacket)

	if ifi.HardwareAddr.String() == net.HardwareAddr(discoveryPacket.ChassisID.ID).String(){
		log.Debug("local lldp packet")
		return false
	}

	if tlvid == 0 {
		for i := int(layers.LLDPTLVChassisID); i <= int(layers.LLDPTLVMgmtAddress); i++{
			printTLV(discoveryPacket, discoveryInfoPacket, i)
		}
		fmt.Println("End of LLDPDU TLV")
	} else {
		printTLV(discoveryPacket, discoveryInfoPacket, tlvid)
	}

	return true
}

func printTLV(discoveryPacket *layers.LinkLayerDiscovery, discoveryInfoPacket *layers.LinkLayerDiscoveryInfo, tlvid int) {
	switch layers.LLDPTLVType(tlvid) {
	case layers.LLDPTLVChassisID:
		fmt.Printf("Chassis ID TLV\n")
		fmt.Printf("\tMAC: %v\n", net.HardwareAddr(discoveryPacket.ChassisID.ID))
	case layers.LLDPTLVPortID:
		fmt.Printf("Port ID TLV\n")
		fmt.Printf("\tIfname: %v\n", string(discoveryPacket.PortID.ID))
	case layers.LLDPTLVTTL:
		fmt.Printf("Time to Live TLV\n")
		fmt.Printf("\t%v\n", discoveryPacket.TTL)
	case layers.LLDPTLVSysName:
		fmt.Printf("System Name TLV\n")
		fmt.Printf("\t%s\n", discoveryInfoPacket.SysName)
	case layers.LLDPTLVSysDescription:
		fmt.Printf("System Description TLV\n")
		fmt.Printf("\t%s\n",  discoveryInfoPacket.SysDescription)
	case layers.LLDPTLVSysCapabilities:
		fmt.Printf("System Capabilities TLV\n")
		//fmt.Printf("\tSystem capabilities:  %v\n", discoveryInfoPacket.SysCapabilities.SystemCap)
		//fmt.Printf("\tEnabled capabilities:  %v\n", discoveryInfoPacket.SysCapabilities.EnabledCap)
	case layers.LLDPTLVMgmtAddress:
		fmt.Printf("Management Address TLV\n")
		//fmt.Printf("\t%s: %s\n",  discoveryInfoPacket.MgmtAddress.Subtype, net.IP(discoveryInfoPacket.MgmtAddress.Address))
		//fmt.Printf("\t%s: %d\n",  discoveryInfoPacket.MgmtAddress.InterfaceSubtype, discoveryInfoPacket.MgmtAddress.InterfaceNumber)
		//oid := asn1.ObjectIdentifier{}
		//reset, err :=asn1.Unmarshal([]byte(discoveryInfoPacket.MgmtAddress.OID), &oid)
		//log.Debug(oid.String(), reset, err)
		//fmt.Printf("\tOID: %v\n",  oid.String())

	default:
		log.Debugf("invalid lldp type %v", tlvid)
	}
}

func printPacketInfo(ifi *net.Interface, packet gopacket.Packet, tlvid int) bool {
	res := false
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		if ethernetPacket.EthernetType == layers.EthernetTypeLinkLayerDiscovery{
			if err := saveCache(device, packet); err !=nil {
				log.Warningf("save package file failed. err: %v", err)
			}
			log.Debug("Ethernet layer detected.")
			log.Debug("Source MAC: ", ethernetPacket.SrcMAC)
			log.Debug("Destination MAC: ", ethernetPacket.DstMAC)
			// Ethernet type is typically IPv4 but could be ARP or other
			log.Debug("Ethernet type: ", ethernetPacket.EthernetType)
			return readLinkLayerDiscoverypacket(ifi, packet, tlvid)
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		log.Debugf("Error decoding some part of the packet: %v", err)
	}

	return res
}
func getFileModTime(path string) (t time.Time, err error) {
	f, err := os.Open(path)
	if err != nil {
		log.Debugf("open catch file err: %v", err)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		log.Debugf("stat fileinfo error: %v", err)
		return
	}

	t =  fi.ModTime()
	return
}

func printPacketInfoFromCache(ifi *net.Interface, tlvid int) bool {
	// check packet file alive
	cachepath := fmt.Sprintf(cachepathformat, ifi.Name)
	modtime, err := getFileModTime(cachepath)
	if err != nil || modtime.Add(time.Duration(cachealive) * time.Second).Before(time.Now()){
		log.Debugf("cache file is out date or err: %v", err)
		return false
	}

	// Open file instead of device
	handle, err = pcap.OpenOffline(cachepath)
	if err != nil {
		log.Debugf("open packet file failed. err: %v", err)
		return false
	}
	defer handle.Close()


	//start := time.Now()
	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		if res := readLinkLayerDiscoverypacket(ifi, packet, tlvid); res {
			return true
		}

		//if time.Now().After(start.Add(time.Duration(timeout)* time.Second)) {
		//	fmt.Println("get lldp package from cache timeout")
		//	return  false
		//}
	}

	return false
}

func saveCache(device string, packet gopacket.Packet) error {
	cachepath := fmt.Sprintf(cachepathformat, device)
	f, err := os.Create(cachepath)
	if err != nil {
		log.Debugf("os create err: %v", err)
		return  err
	}
	defer f.Close()
	r := pcapgo.NewWriter(f)
	if err != nil {
		log.Debugf("NewNgWriter err: %v", err)
		return err
	}

	if err := r.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		log.Debugf("WriteFileHeader: %v", err)
		return err
	}


	return r.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
}
