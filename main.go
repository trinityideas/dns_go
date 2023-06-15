package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"encoding/json"
	"log"
	"strconv"

	"github.com/kardianos/service"
	"github.com/miekg/dns"
)

// Created by Leo Chan (2023)
// ESPMDM + ESPDNS
// get-DNSClient
// Set-DNSClientServerAddress –interfaceIndex $adapterIndex –ServerAddresses (“127.0.0.1”,”1.1.1.2”);
// Set-DnsClientServerAddress -InterfaceIndex 8 -ServerAddresses ("127.0.0.1", "8.8.8.8")

type Services struct {
	Log service.Logger
	Srv *dns.Server
}

func ExecPath() string {
	file, e := os.Executable()
	if e != nil {
		log.Printf("Executable file path error : %s\n", e.Error())
	}
	path := filepath.Dir(file)
	return path
}

// service START
var logger service.Logger

type program struct{}

func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}
func (p *program) run() {
	// Do work here
	go dnsGoroutine()
}

func dnsGoroutine() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from", r)
			go dnsGoroutine() // restart goroutine
		}
	}()
	// startDNS Server
	startDNS_Server()
}

func (p *program) Stop(s service.Service) error {
	// Stop should not block. Return with a few seconds.
	server.Shutdown()
	return nil
}

// service END

type dns_device struct {
	wifi_mac     string
	device_id    []byte
	ip           string
	nid          int
	primaryDNS   string
	secondaryDNS string
}

type DnsConfig struct {
	PrimaryDNS   string
	SecondaryDNS string
	Nid          int
}

const CiscoUmbrella_Resover = "208.67.222.222:53" // Cisco Umbrella DNS
const Google_Resolver = "8.8.8.8:53"              // Google DNS
const ESPDNS_Resolver = "34.80.254.200:53"        // ESP DNS
var MDMDomain string
var dnsc *dns.Client
var device dns_device
var server *dns.Server

var records = map[string]string{
	"test.service.": "192.168.0.2",
}

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("Query for %s\n", q.Name)
			ip := records[q.Name]
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}
}

// GetLocalIP returns the non loopback local IP of the host
func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func handleDnsRequest(w dns.ResponseWriter, reqDNS *dns.Msg) {
	//clientIp := w.RemoteAddr().String()

	if device.device_id != nil {
		clientIp := device.ip
		// append EDNS0
		//reqDNS.RecursionDesired = true
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.SetUDPSize(4096)
		o.Option = append(o.Option, &dns.EDNS0_LOCAL{
			Code: 20292,
			Data: option20292Data(uint32(device.nid), device.device_id, net.ParseIP(clientIp)),
		})

		// replace addtional
		if len(reqDNS.Extra) > 0 {
			reqDNS.Extra[0] = o
		} else {
			reqDNS.Extra = append(reqDNS.Extra, o)
		}
	}

	// use ESP DNS (bydefault)
	r, _, err := dnsc.Exchange(reqDNS, device.primaryDNS+":53")
	if err != nil {
		// if error, then use Google DNS (bydefault)
		r, _, err = dnsc.Exchange(reqDNS, device.secondaryDNS+":53")
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	w.WriteMsg(r)
}

func test_dns() {

	// // Create a new DNS client
	// c := new(dns.Client)

	// // sample query for example.com
	// m, err := queryMsg(
	// 	"www.nike.com.",
	// 	dns.TypeA,
	// 	8122203,                      // orgID
	// 	8122203,                      // assetID (id of the forwarder)      //"f3387b90e67f7831"
	// 	"PunchingBag1",               // computer
	// 	"bonjovij",                   // user
	// 	net.ParseIP("192.168.11.12"), // clientIP
	// )

	// if err != nil {
	// 	panic(err)
	// }

	// // send the query to the DNS server
	// r, _, err := c.Exchange(m, Resolver3)
	// if err != nil {
	// 	panic(err)
	// }

	// // print the response
	// if r.Rcode != dns.RcodeSuccess {
	// 	//panic("DNS query failed")
	// }

	// println(r.Answer)

	// for _, a := range r.Answer {
	// 	//println(a.(*dns.A));
	// 	if t, ok := a.(*dns.A); ok {
	// 		println(t.A.String())
	// 		println(t.A)
	// 	}
	// }
}

func md5_encode(input string) string {
	// Convert the input string to a byte slice
	inputBytes := []byte(input)
	// Calculate the MD5 hash
	hash := md5.Sum(inputBytes)
	hashString := hex.EncodeToString(hash[:])
	return hashString
}

func md5_encode_bytes(input string) []byte {
	// Convert the input string to a byte slice
	inputBytes := []byte(input)
	// Calculate the MD5 hash
	hash := md5.Sum(inputBytes)
	hashBytes := hash[:]
	return hashBytes
}

func getDeviceInfo() dns_device {

	deviceInfo := dns_device{
		wifi_mac:     "",
		device_id:    nil,
		ip:           "",
		nid:          0,
		primaryDNS:   "34.80.254.200",
		secondaryDNS: "8.8.8.8",
	}

	// Get the list of network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		//panic(err)
	}

	// Find the Wi-Fi interface
	var wifiInterface net.Interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagBroadcast != 0 {
			if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagPointToPoint == 0 {
				wifiInterface = iface
				break
			}
		}
	}

	if wifiInterface.Name != "" {
		// Get the MAC address of the Wi-Fi interface

		macAddr := strings.ToUpper(wifiInterface.HardwareAddr.String())

		// Get the IP addresses of the Wi-Fi interface
		addrs, err := wifiInterface.Addrs()
		if err != nil {
			panic(err)
		}

		fmt.Printf("Wi-Fi interface: %s\n", wifiInterface.Name)
		for _, address := range addrs {
			// check the address type and if it is not a loopback the display it
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					log.Printf("ip:" + ipnet.IP.String() + "\n")
					log.Printf("wifi_mac:" + macAddr + "\n")
					log.Printf("device_id:" + md5_encode(macAddr) + "\n")
					deviceInfo.ip = ipnet.IP.String()
					deviceInfo.wifi_mac = macAddr
					deviceInfo.device_id = md5_encode_bytes(macAddr)
				}
			}
		}
	}
	return deviceInfo
}

func loadMDMConfig() {
	config, err3 := os.ReadFile("C:\\ESPAgent\\config.txt")
	if err3 != nil {
	}

	fmt.Print(string(config))
	var mdmConfig interface{}
	json.Unmarshal([]byte(string(config)), &mdmConfig)
	if m, ok := mdmConfig.(map[string]interface{}); ok {
		MDMDomain = m["MDMDomain"].(string)
		fmt.Println("MDMDomain:", MDMDomain)
	} else {
		//fmt.Println("Decoded data is not a JSON object")
	}

	if MDMDomain != "" {
		// ESPAPIConfig := fmt.Sprintf("https://%s/api/3.0/s2/index.php", MDMDomain)
		// ESPAPIConfig = "https://admin.mastermdm.com/api/3.0/s2/index.php"
		// fmt.Println("ESPAPIConfig:", ESPAPIConfig)
		// payloadString := `{"requestType":"deviceConfig", "UDID": "RFCT50JX33W"}`
		// payload := []byte(payloadString)
		// encoded := base64.StdEncoding.EncodeToString(payload)
		// req, err := http.NewRequest("POST", ESPAPIConfig, bytes.NewBuffer([]byte(encoded)))
		// if err != nil {
		// 	fmt.Println("Error creating request:", err)
		// 	//	return
		// }

		// // Make the HTTP POST request
		// client := http.Client{}
		// resp, err := client.Do(req)
		// if err != nil {
		// 	fmt.Println("Error making request:", err)
		// 	//return
		// }
		// defer resp.Body.Close()
		// responseBody, err := ioutil.ReadAll(resp.Body)
		// if err != nil {
		// 	fmt.Println("Error reading response body:", err)
		// 	//return
		// }
		// // Print the response body
		// fmt.Println(string(responseBody))
	}
}

func loadDNSConfig() {
	config, err3 := os.ReadFile("C:\\ESPAgent\\dnsproxy.json")
	if err3 != nil {
	}

	fmt.Print(string(config))
	var dc DnsConfig
	json.Unmarshal([]byte(string(config)), &dc)
	fmt.Printf("PrimaryDNS: %s, SecondaryDNS: %s, nid: %d\n", dc.PrimaryDNS, dc.SecondaryDNS, dc.Nid)

	if dc.Nid != 0 {
		device.nid = dc.Nid
	}
	if dc.PrimaryDNS != "" {
		device.primaryDNS = dc.PrimaryDNS
	}
	if dc.SecondaryDNS != "" {
		device.secondaryDNS = dc.SecondaryDNS
	}
}

func ParseParams() {
	flag.StringVar(&device.primaryDNS, "primaryDNS", "34.80.254.200", "The primary DNS IP address. (ESPDNS)")
	flag.StringVar(&device.secondaryDNS, "secondaryDNS", "8.8.8.8", "The secondary DNS IP address. (GoogleDNS)")
	flag.IntVar(&device.nid, "nid", 0, "The network nid.")
	flag.Parse()
}

func main() {

	svcConfig := &service.Config{
		Name:        "ESPDNSProxy",
		DisplayName: "ESPDNSProxy",
		Description: "This is ESPDNSProxy for MDM usage",
	}

	// Create or open the log file
	file, err := os.OpenFile("dns.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Configure the logger to write to the file
	log.SetOutput(file)

	var mode string
	flag.StringVar(&mode, "mode", "", "install/uninstall/run")
	flag.Parse()

	fmt.Print(mode)

	prg := &program{}
	s, err := service.New(prg, svcConfig)

	if err != nil {
		log.Fatal(err)
	}

	if mode == "install" {
		err = s.Install()
		if err != nil {
			log.Fatal(err)
		}
	}

	if mode == "uninstall" {
		err = s.Uninstall()
		if err != nil {
			log.Fatal(err)
		}
	}

	if mode == "" || mode == "run" {
		err = s.Run()
		if err != nil {
			log.Fatal(err)
		}
	}
}

func runService(name string, isDebug bool) {

	startDNS_Server()
}

func startDNS_Server() {

	// load MDMServer

	// get device info (wifi_ip, device_id, wifimac)
	device = getDeviceInfo()
	loadMDMConfig()
	//ParseParams()
	loadDNSConfig()

	// start server
	dnsc = new(dns.Client)
	port := 53
	server = &dns.Server{
		Addr:      ":" + strconv.Itoa(port),
		Net:       "udp",
		ReusePort: true,
	}

	// Create or open the log file
	file, err := os.OpenFile("app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Configure the logger to write to the file
	log.SetOutput(file)

	log.Println("DNS Proxy parameters:")
	log.Println("  nid: " + strconv.Itoa(device.nid))
	log.Println("  primaryDNS: " + (device.primaryDNS))
	log.Println("  secondaryDNS: " + (device.secondaryDNS))
	log.Println("  Starting at port:" + strconv.Itoa(port))

	// attach request handler func
	dns.HandleFunc(".", handleDnsRequest)

	err2 := server.ListenAndServe()
	defer server.Shutdown()
	if err2 != nil {
		log.Fatalf("Failed to start server: %s\n ", err2.Error())
	}
}

// OpenDNS does an odd thing where they take a 16 byte GUID, encode it as
// 32 lowercase hex characters (NOT standard GUID format), and then hash
// that string with MD5. This function does that.
func OpenDNSHexHash(guid []byte) []byte {
	str := hex.EncodeToString(guid)
	hash := md5.Sum([]byte(str))
	return hash[:]
}

func option20292Data(
	orgID uint32,
	device_id_bytes []byte,
	clientIP net.IP,
) (b []byte) {

	b = []byte("ODNS")  // magic string
	b = append(b, 0x01) // version
	b = append(b, 0x00) // flags

	// Type
	b = append(b, 0x0)
	b = append(b, 0x8)
	// orgID
	b = binary.BigEndian.AppendUint32(b, orgID)

	// different options for IPv4 and IPv6
	if clientIP.To4() != nil {
		//Type
		b = append(b, 0x0)
		b = append(b, 0x10)
		//Remote IPV4
		b = append(b, clientIP.To4()...)
	} else if clientIP.To16() != nil {
		b = append(b, 0x0)
		b = append(b, 0x20)
		b = append(b, clientIP.To16()...)
	}

	//fmt.Println([]byte("ODNS"))
	// Device ID
	b = append(b, 0x0)
	b = append(b, 0x40)

	usingTestingDeviceId := false
	if usingTestingDeviceId {
		b = append(b, 0xf3)
		b = append(b, 0x38)
		b = append(b, 0xe9)
		b = append(b, 0xb8)
		b = append(b, 0xa8)
		b = append(b, 0x82)
		b = append(b, 0x98)
		b = append(b, 0xba)

		b = append(b, 0xf3)
		b = append(b, 0x38)
		b = append(b, 0xe9)
		b = append(b, 0xb8)
		b = append(b, 0xa8)
		b = append(b, 0x82)
		b = append(b, 0x98)
		b = append(b, 0xbf)
	} else {
		for i := 0; i < len(device_id_bytes); i++ {
			//fmt.Printf("Byte at index %d: 0x%x\n", i, device_id_bytes[i])
			b = append(b, device_id_bytes[i])
		}
	}

	return b
}
