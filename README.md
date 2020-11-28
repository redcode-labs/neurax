

<h1 align="center"> ColdFire</h1> <br>
<p align="center">
  <a>
    <img src="coldfire.png" width="450">
  </a>
</p>

<p align="center">
  Golang malware development framework
</p>

## Table of Contents
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Installation](#installation)
- [Types of functions included](#types-of-functions-included)
- [Documentation](#documentation)
  - [Logging functions](#logging-functions)
  - [Auxiliary functions](#auxiliary-functions)
  - [Reconnaissance functions](#reconnaissance-functions)
  - [Administration functions](#administration-functions)
  - [Evasion functions](#evasion-functions)
  - [Sandbox detection functions](#sandbox-detection-functions)
  - [Disruptive functions](#disruptive-functions)
- [Requirements](#requirements)
- [Disclaimer](#disclaimer)
- [License](#license)

## Introduction

ColdFire provides various methods useful for malware development in Golang.

Most functions are compatible with both Linux and Windows operating systems.

## Installation

`go get https://github.com/redcode-labs/ColdFire`

## Types of functions included

* Logging
* Auxiliary
* Reconnaissance
* Evasion
* Administration
* Sandbox detection
* Disruptive


## Documentation
### Logging functions

```
func f(s string, arg ...interface{}) string 
    Alias for fmt.Sprintf

func print_good(msg string)
    Print good status message

func print_info(msg string)
    Print info status message

func print_error(msg string)
    Print error status message
    
func print_warning(msg string)
    Print warning status message    
    
```
    
    
### Auxiliary functions

```
func file_to_slice(file string) []string
    Read from file and return slice with lines delimited with newline.

func contains(s interface{}, elem interface{}) bool 
    Check if interface type contains another interface type.

func str_to_int(string_integer string) int 
    Convert string to int.

func int_to_str(i int) string 
    Converts int to string.    

func interval_to_seconds(interval string) int 
    Converts given time interval to seconds.

func random_int(min int, max int) int
    Returns a random int from range.

func random_select_str(list []string) string 
    Returns a random selection from slice of strings.    

func random_select_int(list []int) int 
    Returns a random selection from slice of ints.    

func random_select_str_nested(list [][]string) []string  
    Returns a random selection from nested string slice.

func remove_newlines(s string) string 
    Removes "\n" and "\r" characters from string.

func full_remove(str string, to_remove string) string 
    Removes all occurrences of substring.

func remove_duplicates_str(slice []string) []string 
    Removes duplicates from string slice.

func remove_duplicates_int(slice []int) []int 
    Removes duplicates from int slice.

func contains_any(str string, elements []string) bool 
    Returns true if slice contains a string.

func random_string(n int) string
    Generates random string of length [n]

func exit_on_error(e error)
    Handle errors

func md5_hash(str string) string
    Returns MD5 checksum of a string

func make_zip(zip_file string, files []string) error 
    Creates a zip archive from a list of files

func read_file(filename string) (string, error) 
    Read contents of a file.

func write_file(filename string) error 
    Write contents to a file.

func b64d(str string) string 
    Returns a base64 decoded string

func b64e(str string) string 
    Returns a base64 encoded string

func file_exists(file string) bool
    Check if file exists. 

func parse_cidr(cidr string) ([]string, error) 
    Returns a slice containing all possible IP addresses in the given range.

 ```

### Reconnaissance functions
```

func ip_local() string
    Returns a local IP address of the machine.

func ip_global() string
    Returns a global IP address of the machine.
    
func is_root() bool
    Check if user has administrative privileges.
    
func processes() (map[int]string, error)
    Returns all processes' PIDs and their corresponding names.

func iface() string, string
    Returns name of currently used wireless interface and it's MAC address. 

func ifaces() []string
    Returns slice containing names of all local interfaces.
    
func disks() ([]string, error) 
    Lists local storage devices
    
func users() []string, err
    Returns list of known users.

func info() map[string]string 
    Returns basic system information. 
    Possible fields: username, hostname, go_os, os, 
    platform, cpu_num, kernel, core, local_ip, ap_ip, global_ip, mac.
    If the field cannot be resolved, it defaults to "N/A" value.
    
func dns_lookup(hostname string) ([]string, error) 
    Performs DNS lookup

func rdns_lookup(ip string) ([]string, error) 
    Performs reverse DNS lookup

func hosts_passive(interval string) []string, err
    Passively discovers active hosts on a network using ARP monitoring.
    Discovery time can be changed using <interval> argument.
    
func file_permissions(filename string) (bool,bool) 
    Checks if file has read and write permissions.
    
func portscan(target string, timeout, threads int) []int 
    Returns list of open ports on target.

func portscan_single(target string, port int) bool 
    Returns true if selected port is open.
    
func banner_grab(target string, port int) (string, error) 
    Grabs a service banner string from a given port.
    
func networks() ([]string, error) 
    Returns list of nearby wireless networks.
    
```

### Administration functions
```
func cmd_out(command string) string, error
    Execute a command and return it's output.

func cmd_out_platform(commands map[string]string) (string, error) 
    Executes commands in platform-aware mode.
    For example, passing {"windows":"dir", "linux":"ls"} will execute different command, 
    based on platform the implant was launched on.

func cmd_run(command string)
    Unlike cmd_out(), cmd_run does not return anything, and prints output and error to STDOUT.

func cmd_dir(dirs_cmd map[string]string) ([]string, error) 
    Executes commands in directory-aware mode.
    For example, passing {"/etc" : "ls"} will execute command "ls" under /etc directory.

func cmd_blind(command string)
    Run command without supervision, do not print any output.
    
func create_user(username, password string) error
    Creates a new user on the system.
    
func bind(port int)
    Run a bind shell on a given port.

func reverse(host string, port int)
    Run a reverse shell.

func send_data_tcp(host string, port int, data string) error 
    Sends string to a remote host using TCP protocol.

func send_data_udp(host string, port int, data string) error 
    Sends string to a remote host using UDP protocol.
    
func download(url string) error
    Downloads a file from url and save it under the same name.
```

### Evasion functions
```
func pkill_pid(pid int) error
    Kill process by PID.

func pkill_name(name string) error
    Kill all processes that contain [name].

func pkill_av() err
    Kill most common AV processes.
    
func wait(interval string)
    Does nothing for a given interval of time.

func remove()
    Removes binary from the host.
    
func set_ttl(interval string)
    Set time-to-live of the binary.
    Should be launched as goroutine.
    
func clear_logs() error
    Clears most system logs.
```

### Sandbox detection functions
```
func sandbox_filepath() bool 
    Detect sandbox by looking for common sandbox filepaths.
    Compatible only with windows.

func sandbox_proc() bool 
    Detect sandbox by looking for common sandbox processes.

func sandbox_sleep() bool
    Detect sandbox by looking for sleep-acceleration mechanism.

func sandbox_disk(size int) bool
    Detect sandbox by looking for abnormally small disk size.

func sandbox_cpu(cores int) bool
    Detect sandbox by looking for abnormally small number of cpu cores.

func sandbox_ram(ram_mb int) bool
    Detect sandbox by looking for abnormally small amount of RAM.

func sandbox_mac() bool
    Detect sandbox by looking for sandbox-specific MAC address of the localhost. 

func sandbox_utc() bool
    Detect sandbox by looking for properly set UTC time zone. 

func sandbox_all() bool
    Detect sandbox using all sandbox detection methods.
    Returns true if any sandbox-detection method returns true.    

func sandbox_all_n(num int) bool
    Detect sandbox using all sandbox detection methods.
    Returns true if at least <num> detection methods return true.
```

### Disruptive functions
```
func wifi_disconnect() error 
    Disconnects from wireless access point
    
func wipe() error
    Wipes out entire filesystem.
    
func erase_mbr(device string, partition_table bool) error 
    Erases MBR sector of a device.
    If <partition_table> is true, erases also partition table.
    
func forkbomb()
    Runs a forkbomb.
    
func shutdown() error
    Reboot the machine.

```



## Requirements
```
"github.com/google/gopacket"
"github.com/google/gopacket/layers"
"github.com/google/gopacket/pcap"
"github.com/robfig/cron"
"github.com/anvie/port-scanner"
"github.com/matishsiao/goInfo"
"github.com/fatih/color"
"github.com/minio/minio/pkg/disk"
"github.com/dustin/go-humanize"
"github.com/mitchellh/go-ps"
```

## Disclaimer
Developers are not responsible for any misuse regarding this tool.
Use it only against systems that you are permitted to attack.

## License
This software is under MIT license

