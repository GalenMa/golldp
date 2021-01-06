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
	"regexp"
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
	bService		bool
	handle      *pcap.Handle
)

const (
	cachepathformat string = "/tmp/%slldp.pcap"
)

func exit_timeout(sub int,  handle *pcap.Handle ){
	t := time.NewTimer(time.Duration(sub) * time.Second)
	<-t.C
	log.Debug("time out, close handle")
	handle.Close()
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
	flag.BoolVar(&bService, "s", false, "run as service")

	flag.Parse()
	if debug{
		log.SetLevel(log.DebugLevel)
	}
	if runtime.GOOS == "linux" {
		logfile = "/var/log/golldp.log"
	}

	initlog(logfile, debug)


	if bService {
		waitForNetwork()

		StartService()
	} else {
		ifi, err := net.InterfaceByName(device)
		if err != nil {
			fmt.Printf("%v open interface failed\n", device)
			os.Exit(1)
		}
		log.Debugf("device info %v", *ifi)
		if err := getLLDPInfo(ifi); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	}
}

func getAllInterfacesLLDPInfo(){

	for {
		log.Debug("start get lldp info")
		inters, err := net.Interfaces()
		if err != nil {
			log.Errorf("get interfaces failed. err.:%v", err)
			return
		}

		for _, in := range inters {
			if in.Flags&net.FlagUp != 1 || in.Flags&net.FlagLoopback == 1 {
				continue
			}

			if r, _ := regexp.Compile("^em|^eth|^ens|^eno|^p"); r.MatchString(in.Name) == false {
				continue
			}
			if err := getLLDPInfo(&in); err != nil {
				log.Errorf("get lldp info failed. err:%v", err)
			}
		}

		ticker := time.Tick(time.Minute)
		<- ticker
	}
}

func getLLDPInfo(ifi *net.Interface) error {
	if getIfLinkstate(ifi) == false {
		return fmt.Errorf("%s is down\n", ifi.Name)
	}

	if printPacketInfoFromCache(ifi, tlvid) {
		return nil
	}

	//start := time.Now()
	// Open device
	log.Debugf("OpenLive device:%v snaplen:%v promisc:%v", ifi.Name, int32(ifi.MTU), promiscuous)
	handle, err = pcap.OpenLive(ifi.Name, int32(ifi.MTU), promiscuous, 50 * time.Millisecond)
	if err != nil {
		log.Debugf("OpenLive oerr: %v", err)
		return fmt.Errorf("open live %v interface failed", ifi.Name)
	}
	defer handle.Close()

	go exit_timeout(timeout, handle)

	if err := handle.SetBPFFilter("ether proto 0x88cc"); err != nil {
		return err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if res := printPacketInfo(ifi, packet, tlvid); res {
			return nil
		}
	}

	return fmt.Errorf("%s time out", ifi.Name)
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
	log.Debugf("discoveryPacket: %v", discoveryPacket)
	discoveryInfoLayer := packet.Layer(layers.LayerTypeLinkLayerDiscoveryInfo)
	discoveryInfoPacket, _ := discoveryInfoLayer.(*layers.LinkLayerDiscoveryInfo)
	//log.Debugf("discoveryInfoPacket: %v", discoveryInfoPacket)

	if discoveryPacket.ChassisID.Subtype != layers.LLDPChassisIDSubtypeIfaceName ||
		ifi.HardwareAddr.String() == net.HardwareAddr(discoveryPacket.ChassisID.ID).String(){
		log.Debug("invalid network lldp packet")
		return false
	}

	if tlvid == 0 {
		for i := int(layers.LLDPTLVChassisID); i <= int(layers.LLDPTLVMgmtAddress); i++{
			printTLV(discoveryPacket, discoveryInfoPacket, i)
		}
		fmt.Printf("End of LLDPDU TLV\n")
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
	case layers.LLDPTLVPortDescription:
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
		if ethernetPacket.EthernetType == layers.EthernetTypeLinkLayerDiscovery &&
			ethernetPacket.SrcMAC.String() != ifi.HardwareAddr.String(){

			log.Debug("Ethernet layer detected.")
			log.Debug("Source MAC: ", ethernetPacket.SrcMAC)
			log.Debug("Destination MAC: ", ethernetPacket.DstMAC)
			// Ethernet type is typically IPv4 but could be ARP or other
			log.Debug("Ethernet type: ", ethernetPacket.EthernetType)
			if readLinkLayerDiscoverypacket(ifi, packet, tlvid) {
				if err := saveCache(ifi.Name, packet); err !=nil {
					log.Warningf("save package file failed. err: %v", err)
				}
			}

		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		log.Debugf("Error decoding some part of the packet: %v", err)

		saveCachePacket(fmt.Sprintf("%vErr.pcap", ifi.Name), packet)
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

func saveCachePacket(name string, packet gopacket.Packet) error {
	f, err := os.Create(name)
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



func waitForNetwork() {
	for true {
		// wait one second
		t := time.NewTimer(time.Second)
		<-t.C

		cmd := exec.Command("ping", "127.0.0.1", "-c", "1", "-W", "5")
		err := cmd.Run()
		if err != nil {
			//log.Error(err.Error())
			continue
		} else {
			log.Debug("Net Status , OK")
			break
		}
	}
}



